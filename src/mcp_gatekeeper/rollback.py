"""Session transaction, savepoints, undo log and compensation."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal

from psycopg import AsyncConnection, sql

from .audit import AuditLog
from .breaker import CircuitBreaker
from .config import Role


class SessionState(StrEnum):
    ACTIVE = "ACTIVE"
    ABORTED = "ABORTED"  # transaction was rolled back; call rollback_session to continue
    HALTED = "HALTED"  # breaker tripped; session refuses everything
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class UndoEntry:
    """How to reverse one row change made by this session."""

    kind: Literal["update", "delete", "insert"]
    table: str
    pk: str
    key: Any
    before: dict[str, Any] | None  # row image before the change (update/delete)
    version_after: int | None  # version the row had right after the change, if versioned


class Session:
    """One agent session = one database connection = one open transaction at a time."""

    def __init__(
        self,
        session_id: str,
        conn: AsyncConnection[Any],
        breaker: CircuitBreaker,
        audit: AuditLog,
        agent: str,
        role_name: str,
        role: Role,
    ) -> None:
        self.id = session_id
        self.conn: AsyncConnection[Any] | None = conn
        self.breaker = breaker
        self.audit = audit
        self.agent = agent
        self.role_name = role_name
        self.role = role
        self.state = SessionState.ACTIVE
        self.lock = asyncio.Lock()
        self.failed_writes: list[str] = []  # failed mutating steps in the current transaction
        self.pending_undo: list[UndoEntry] = []  # changes in the open transaction
        self.committed_undo: list[UndoEntry] = []  # changes this session already committed
        self.last_used = time.monotonic()
        self.ran_ddl = False
        self._sp = 0

    @property
    def db(self) -> AsyncConnection[Any]:
        if self.conn is None:
            raise RuntimeError(f"session {self.id} has no connection")
        return self.conn

    async def savepoint(self) -> str:
        self._sp += 1
        name = f"gk_sp_{self._sp}"
        await self.db.execute(sql.SQL("SAVEPOINT {}").format(sql.Identifier(name)))
        return name

    async def rollback_to(self, name: str) -> None:
        await self.db.execute(sql.SQL("ROLLBACK TO SAVEPOINT {}").format(sql.Identifier(name)))
        await self.db.execute(sql.SQL("RELEASE SAVEPOINT {}").format(sql.Identifier(name)))

    async def release(self, name: str) -> None:
        await self.db.execute(sql.SQL("RELEASE SAVEPOINT {}").format(sql.Identifier(name)))

    async def rollback_all(self) -> None:
        await self.db.rollback()
        self.failed_writes.clear()
        self.pending_undo.clear()

    async def commit(self) -> None:
        await self.db.commit()
        self.failed_writes.clear()
        self.committed_undo.extend(self.pending_undo)
        self.pending_undo.clear()

    async def state_hash(self, tables: frozenset[str]) -> str | None:
        """md5 over the full contents of the given tables, as seen inside this transaction."""
        if not tables:
            return None
        parts = []
        for table in sorted(tables):
            q = sql.SQL("SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY t::text), '')) FROM {} t").format(
                sql.Identifier(table)
            )
            row = await (await self.db.execute(q)).fetchone()
            parts.append(f"{table}:{row[0] if row else ''}")
        return ",".join(parts)


def _undo_statement(entry: UndoEntry, version_col: str) -> tuple[sql.Composed, list[Any]]:
    t, pk = sql.Identifier(entry.table), sql.Identifier(entry.pk)
    guard: sql.Composable = sql.SQL("")
    params: list[Any] = []
    if entry.kind == "insert":
        params = [entry.key]
        if entry.version_after is not None:
            guard = sql.SQL(" AND {} = %s").format(sql.Identifier(version_col))
            params.append(entry.version_after)
        return sql.SQL("DELETE FROM {} WHERE {} = %s{}").format(t, pk, guard), params
    assert entry.before is not None
    image = dict(entry.before)
    if version_col in image and entry.version_after is not None:
        image[version_col] = entry.version_after + 1  # move forward, never back: stale readers still conflict
    if entry.kind == "delete":
        stmt = sql.SQL("INSERT INTO {} SELECT * FROM jsonb_populate_record(NULL::{}, %s::jsonb) ON CONFLICT DO NOTHING")
        return stmt.format(t, t), [json.dumps(image, default=str)]
    cols = [c for c in image if c != entry.pk]
    targets = sql.SQL(", ").join(sql.Identifier(c) for c in cols)
    params = [json.dumps(image, default=str), entry.key]
    if entry.version_after is not None:
        guard = sql.SQL(" AND {} = %s").format(sql.Identifier(version_col))
        params.append(entry.version_after)
    stmt = sql.SQL("UPDATE {} SET ({}) = (SELECT {} FROM jsonb_populate_record(NULL::{}, %s::jsonb)) WHERE {} = %s{}")
    return stmt.format(t, targets, targets, t, pk, guard), params


async def compensate(conn: AsyncConnection[Any], entries: list[UndoEntry], version_col: str) -> tuple[bool, str]:
    """Reverse committed changes, newest first, in one transaction: all or nothing.

    Each undo is guarded (row still at the version this session left it), so a row someone
    else changed since is never clobbered; in that case nothing is compensated.
    """
    if not entries:
        return True, "nothing to compensate"
    try:
        for entry in reversed(entries):
            stmt, params = _undo_statement(entry, version_col)
            cur = await conn.execute(stmt, params)
            if cur.rowcount != 1:
                await conn.rollback()
                return False, f"row {entry.table}.{entry.pk}={entry.key} changed since this session wrote it; nothing compensated"
        await conn.commit()
    except Exception as e:  # noqa: BLE001 - compensation must never crash the tool call
        await conn.rollback()
        return False, f"compensation failed: {type(e).__name__}; nothing compensated"
    return True, f"reversed {len(entries)} committed row change(s)"
