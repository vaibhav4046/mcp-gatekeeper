"""The gatekeeper: policy -> breaker -> savepoint -> version check -> execute -> post-write checks.

Order of checks for every execute_sql call:

1. session must exist and be ACTIVE (HALTED and ABORTED sessions refuse work)
2. static policy for the session's role (sqlglot AST); a refusal counts toward the breaker
3. write cap (breaker) before any write runs
4. SAVEPOINT
5. UPDATE/DELETE: lock matched rows, capture before-images, check row cap and expected_version
6. execute; a DB error rolls back to the savepoint and taints the transaction
7. writes: row-cap recheck, change limits, declarative invariants (before RELEASE SAVEPOINT)
8. RELEASE SAVEPOINT, record undo entries, write the hash-chained trace, return
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool, PoolTimeout
from pydantic import BaseModel
from sqlglot import exp

from . import policy as pol
from .audit import AuditLog, Redactor
from .breaker import CircuitBreaker
from .config import Settings
from .rollback import Session, SessionState, UndoEntry, compensate
from .verifier import Check, VerifyResult, verify_write

log = logging.getLogger("mcp_gatekeeper")

PK_ALIAS, VER_ALIAS = "__gk_pk", "__gk_ver"


class Verdict(StrEnum):
    OK = "OK"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    CONCURRENT_MODIFICATION_CONFLICT = "CONCURRENT_MODIFICATION_CONFLICT"
    INVARIANT_VIOLATION = "INVARIANT_VIOLATION"
    DB_ERROR = "DB_ERROR"
    SESSION_HALTED = "SESSION_HALTED"
    TRANSACTION_ABORTED = "TRANSACTION_ABORTED"
    UNKNOWN_SESSION = "UNKNOWN_SESSION"
    UNKNOWN_AGENT = "UNKNOWN_AGENT"
    POOL_EXHAUSTED = "POOL_EXHAUSTED"
    COMMITTED = "COMMITTED"
    COMMIT_REFUSED = "COMMIT_REFUSED"
    ROLLED_BACK = "ROLLED_BACK"


class Result(BaseModel):
    verdict: Verdict
    session_id: str
    rule_id: str | None = None
    reason: str = ""
    rows: list[dict[str, Any]] | None = None
    rowcount: int | None = None
    session_state: str | None = None
    role: str | None = None
    latency_ms: float = 0.0
    db_ms: float = 0.0  # time spent executing the agent's own statement

    @property
    def ok(self) -> bool:
        return self.verdict in (Verdict.OK, Verdict.COMMITTED, Verdict.ROLLED_BACK)


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)


class _Abort(Exception):
    """Internal: stop processing a statement with this result."""

    def __init__(self, result: Result) -> None:
        self.result = result


class Gatekeeper:
    def __init__(self, pool: AsyncConnectionPool[Any], settings: Settings, redactor: Redactor | None = None) -> None:
        self.pool = pool
        self.s = settings
        self.p = settings.policy
        self.redactor = redactor or Redactor()
        self.sessions: dict[str, Session] = {}
        self._known_tables: frozenset[str] | None = None
        self._versioned: frozenset[str] = frozenset()
        self._pks: dict[str, str] = {}

    @classmethod
    async def create(cls, settings: Settings) -> Gatekeeper:
        lim = settings.policy.limits
        pool: AsyncConnectionPool[Any] = AsyncConnectionPool(
            settings.database_url,
            min_size=settings.pool_min,
            max_size=settings.pool_max,
            kwargs={"options": f"-c statement_timeout={lim.statement_timeout_ms} -c lock_timeout={lim.lock_timeout_ms}"},
            open=False,
        )
        await pool.open(wait=True)
        gk = cls(pool, settings, Redactor(await _secret_values(pool)))
        await gk.refresh_schema()
        return gk

    async def aclose(self) -> None:
        for sid in list(self.sessions):
            await self.close_session(sid)
        await self.pool.close()

    async def refresh_schema(self) -> None:
        """Snapshot tables, version columns and single-column primary keys of the current schema."""
        async with self.pool.connection() as conn:
            cur = await conn.execute(
                "SELECT table_name, bool_or(column_name = %s) FROM information_schema.columns "
                "WHERE table_schema = current_schema() GROUP BY table_name",
                (self.p.version_column,),
            )
            rows = await cur.fetchall()
            cur = await conn.execute(
                "SELECT tc.table_name, min(kcu.column_name) FROM information_schema.table_constraints tc "
                "JOIN information_schema.key_column_usage kcu ON kcu.constraint_name = tc.constraint_name "
                "AND kcu.table_schema = tc.table_schema WHERE tc.constraint_type = 'PRIMARY KEY' "
                "AND tc.table_schema = current_schema() GROUP BY tc.table_name HAVING count(*) = 1"
            )
            pks = await cur.fetchall()
            await conn.rollback()
        self._known_tables = frozenset(r[0] for r in rows)
        self._versioned = frozenset(r[0] for r in rows if r[1])
        self._pks = {r[0]: r[1] for r in pks}

    # ------------------------------------------------------------------ sessions
    async def begin_session(self, agent: str | None = None) -> Result:
        try:
            role_name, role = self.p.role_for(agent or self.s.agent)
        except KeyError as e:
            return Result(verdict=Verdict.UNKNOWN_AGENT, session_id="", reason=str(e))
        if self._known_tables is None:
            await self.refresh_schema()
        try:
            conn = await self.pool.getconn(timeout=self.s.session_acquire_timeout_s)
        except PoolTimeout:
            return Result(verdict=Verdict.POOL_EXHAUSTED, session_id="", reason="no free database connection; retry later")
        sid = uuid.uuid4().hex
        try:
            await conn.set_read_only(role.kind == "read_only")  # BEGIN ... READ ONLY on every transaction
            audit = AuditLog(Path(self.s.trace_dir) / f"{sid}.jsonl", self.redactor, self.s.audit_key)
        except Exception:
            await self.pool.putconn(conn)
            raise
        sess = Session(
            sid, conn, CircuitBreaker(self.p.limits), audit, agent or self.s.agent or self.p.default_agent, role_name, role
        )
        self.sessions[sid] = sess
        audit.write({"event": "begin_session", "verdict": "OK", "agent": sess.agent, "role": role_name})
        return Result(verdict=Verdict.OK, session_id=sid, session_state=sess.state, role=role_name)

    async def _halt(self, sess: Session, reason: str) -> str:
        """Breaker trip: roll back the open transaction, then undo this session's committed writes."""
        await sess.rollback_all()
        sess.state = SessionState.HALTED
        note = reason
        if self.p.limits.compensate_on_trip and sess.committed_undo:
            ok, detail = await compensate(sess.db, sess.committed_undo, self.p.version_column)
            sess.audit.write({"event": "compensation", "verdict": "OK" if ok else "FAILED", "reason": detail})
            if ok:
                sess.committed_undo.clear()
            note = f"{reason}; compensation: {detail}"
        log.warning("session %s halted: %s", sess.id, self.redactor.text(note))
        return note

    async def close_session(self, session_id: str) -> Result:
        """Roll back anything uncommitted and return the connection to the pool."""
        sess = self.sessions.pop(session_id, None)
        if sess is None:
            return Result(verdict=Verdict.UNKNOWN_SESSION, session_id=session_id)
        async with sess.lock:
            if sess.conn is not None:
                try:
                    await sess.conn.rollback()
                    await sess.conn.set_read_only(False)
                except psycopg.Error:
                    pass  # broken connection: the pool discards it
                finally:
                    await self.pool.putconn(sess.conn)
                    sess.conn = None
            prior = sess.state
            sess.state = SessionState.CLOSED
            sess.audit.write({"event": "close_session", "verdict": "ROLLED_BACK", "prior_state": prior})
            sess.audit.close()
        return Result(verdict=Verdict.ROLLED_BACK, session_id=session_id, session_state=SessionState.CLOSED)

    async def reap_idle(self, max_idle_s: float | None = None) -> list[str]:
        """Close sessions idle for longer than the limit (abandoned agents). Returns closed ids."""
        limit = self.p.limits.session_idle_timeout_s if max_idle_s is None else max_idle_s
        now = time.monotonic()
        stale = [sid for sid, s in self.sessions.items() if now - s.last_used >= limit and not s.lock.locked()]
        for sid in stale:
            await self.close_session(sid)
        return stale

    def _get(self, session_id: str) -> Session | None:
        sess = self.sessions.get(session_id)
        if sess is None or sess.conn is None:
            return None
        sess.last_used = time.monotonic()
        return sess

    async def commit_session(self, session_id: str) -> Result:
        t0 = time.perf_counter()
        sess = self._get(session_id)
        if sess is None:
            return Result(verdict=Verdict.UNKNOWN_SESSION, session_id=session_id)
        async with sess.lock:
            if sess.conn is None:
                return Result(verdict=Verdict.UNKNOWN_SESSION, session_id=session_id)
            if sess.state == SessionState.HALTED:
                res = Result(verdict=Verdict.SESSION_HALTED, session_id=session_id, reason=sess.breaker.tripped or "")
            elif sess.state == SessionState.ABORTED:
                res = Result(
                    verdict=Verdict.COMMIT_REFUSED,
                    session_id=session_id,
                    rule_id="TRANSACTION_ABORTED",
                    reason="transaction was already rolled back; call rollback_session and redo the work",
                )
            elif sess.failed_writes:
                failed = list(sess.failed_writes)
                await sess.rollback_all()
                res = Result(
                    verdict=Verdict.COMMIT_REFUSED,
                    session_id=session_id,
                    rule_id="PARTIAL_FAILURE",
                    reason=f"{len(failed)} mutating step(s) failed in this transaction; rolled back everything: {failed}",
                )
            else:
                try:
                    await sess.commit()
                    res = Result(verdict=Verdict.COMMITTED, session_id=session_id)
                except psycopg.Error as e:  # deferred constraint, serialization failure, lost connection
                    await sess.rollback_all()
                    res = Result(
                        verdict=Verdict.COMMIT_REFUSED,
                        session_id=session_id,
                        rule_id="COMMIT_FAILED",
                        reason=self.redactor.text(f"{e.sqlstate}: {e.diag.message_primary or type(e).__name__}"),
                    )
            res.session_state = sess.state
            res.latency_ms = _ms(t0)
            sess.audit.write({"event": "commit_session", **res.model_dump(exclude={"rows", "session_id"})})
        if res.verdict == Verdict.COMMITTED and sess.ran_ddl:
            await self.refresh_schema()
        return res

    async def rollback_session(self, session_id: str) -> Result:
        t0 = time.perf_counter()
        sess = self._get(session_id)
        if sess is None:
            return Result(verdict=Verdict.UNKNOWN_SESSION, session_id=session_id)
        async with sess.lock:
            if sess.conn is None:
                return Result(verdict=Verdict.UNKNOWN_SESSION, session_id=session_id)
            if sess.state == SessionState.HALTED:
                res = Result(verdict=Verdict.SESSION_HALTED, session_id=session_id, reason=sess.breaker.tripped or "")
            else:
                await sess.rollback_all()
                sess.state = SessionState.ACTIVE
                res = Result(verdict=Verdict.ROLLED_BACK, session_id=session_id)
            res.session_state = sess.state
            res.latency_ms = _ms(t0)
            sess.audit.write({"event": "rollback_session", **res.model_dump(exclude={"rows", "session_id"})})
            return res

    def trace_path(self, session_id: str) -> Path:
        return Path(self.s.trace_dir) / f"{session_id}.jsonl"

    def get_trace(self, session_id: str) -> list[dict[str, Any]] | None:
        if not all(c in "0123456789abcdef" for c in session_id) or not session_id:
            return None
        path = self.trace_path(session_id)
        if not path.exists():
            return None
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    # ------------------------------------------------------------------ execute
    async def execute_sql(self, session_id: str, sql_text: str, expected_version: int | None = None) -> Result:
        t0 = time.perf_counter()
        sess = self._get(session_id)
        if sess is None:
            return Result(verdict=Verdict.UNKNOWN_SESSION, session_id=session_id, reason="begin_session first")
        async with sess.lock:
            if sess.conn is None:
                return Result(verdict=Verdict.UNKNOWN_SESSION, session_id=session_id)
            res, pre, post = await self._execute_locked(sess, sql_text, expected_version)
            res = res.model_copy(
                update={"session_state": sess.state, "latency_ms": _ms(t0), "reason": self.redactor.text(res.reason)}
            )
            sess.audit.write(
                {
                    "event": "execute_sql",
                    "sql": sql_text,
                    "expected_version": expected_version,
                    "verdict": res.verdict,
                    "rule_id": res.rule_id,
                    "reason": res.reason,
                    "rowcount": res.rowcount,
                    "latency_ms": res.latency_ms,
                    "db_ms": res.db_ms,
                    "pre_state_hash": pre,
                    "post_state_hash": post,
                    "session_state": sess.state,
                }
            )
            return res

    async def _trip_or(self, sess: Session, trip: str | None, res: Result) -> Result:
        if trip:
            note = await self._halt(sess, trip)
            return res.model_copy(
                update={"verdict": Verdict.SESSION_HALTED, "rule_id": "CIRCUIT_BREAKER", "reason": f"{res.reason} | {note}"}
            )
        return res

    async def _violation(self, sess: Session, res: Result, is_write: bool) -> Result:
        if is_write:
            sess.failed_writes.append(f"{res.rule_id}")
        return await self._trip_or(sess, sess.breaker.record_violation(), res)

    async def _full_rollback(self, sess: Session, fp: str, res: Result) -> Result:
        await sess.rollback_all()
        sess.state = SessionState.ABORTED
        return await self._trip_or(sess, sess.breaker.record_failure(pol.fingerprint(fp)), res)

    async def _execute_locked(
        self, sess: Session, sql_text: str, expected_version: int | None
    ) -> tuple[Result, str | None, str | None]:
        sid = sess.id
        if sess.state == SessionState.HALTED:
            return (
                Result(
                    verdict=Verdict.SESSION_HALTED, session_id=sid, rule_id="CIRCUIT_BREAKER", reason=sess.breaker.tripped or ""
                ),
                None,
                None,
            )
        if sess.state != SessionState.ACTIVE:
            return (
                Result(
                    verdict=Verdict.TRANSACTION_ABORTED,
                    session_id=sid,
                    reason="transaction was rolled back after a conflict or invariant violation; call rollback_session",
                ),
                None,
                None,
            )

        pr = pol.check(sql_text, self.p, sess.role, self._known_tables)
        if not pr.allowed:
            res = Result(verdict=Verdict.POLICY_BLOCKED, session_id=sid, rule_id=pr.rule_id, reason=pr.reason)
            return await self._violation(sess, res, pr.is_write), None, None
        if pr.is_write:
            trip = sess.breaker.record_write()
            if trip:
                note = await self._halt(sess, trip)
                return Result(verdict=Verdict.SESSION_HALTED, session_id=sid, rule_id="CIRCUIT_BREAKER", reason=note), None, None

        fp = sql_text  # normalised lazily (pol.fingerprint) only when a failure is recorded
        hash_tables = pr.tables & (self._known_tables or frozenset())
        pre = post = None
        db_ms = 0.0
        sp: str | None = None
        try:
            sp = await sess.savepoint()
            if self.s.hash_state:
                pre = await sess.state_hash(hash_tables)
            ok, undo = await self._run_statement(sess, pr, sql_text, expected_version, sp, fp)
            db_ms = ok.db_ms
            await sess.release(sp)
            sess.pending_undo.extend(undo)
            if pr.is_ddl:
                sess.ran_ddl = True
            if self.s.hash_state:
                post = await sess.state_hash(hash_tables) if pr.is_write else pre
            return ok, pre, post
        except _Abort as a:
            return a.result, pre, None
        except psycopg.Error as e:
            # Anything that fails after the statement ran (checks, hashing, savepoint release)
            # leaves the transaction in an unknown state: roll all of it back.
            diag = e.diag.message_primary or str(e).splitlines()[0]
            res = Result(
                verdict=Verdict.DB_ERROR,
                session_id=sid,
                rule_id=e.sqlstate,
                reason=f"post-statement failure: {diag}",
                db_ms=db_ms,
            )
            return await self._full_rollback(sess, fp, res), pre, None

    async def _run_statement(
        self, sess: Session, pr: pol.PolicyResult, sql_text: str, expected_version: int | None, sp: str, fp: str
    ) -> tuple[Result, list[UndoEntry]]:
        """Run one statement after its savepoint. Refusals raise _Abort; success returns (result, undo)."""
        sid, conn, stmt = sess.id, sess.db, pr.statement
        final_sql = sql_text
        verified: VerifyResult | None = None
        table = ""
        undo: list[UndoEntry] = []
        key_mode = ""  # "": agent's statement as is; "hidden": we added RETURNING; "extra": appended to agent's RETURNING
        if isinstance(stmt, (exp.Update, exp.Delete)):
            table = pol.table_name(stmt.this)
            verified = await verify_write(
                conn,
                stmt,
                expected_version,
                versioned=table in self._versioned,
                version_col=self.p.version_column,
                max_rows=sess.role.max_rows_per_write,
            )
            if verified.check == Check.CONFLICT:
                res = Result(
                    verdict=Verdict.CONCURRENT_MODIFICATION_CONFLICT,
                    session_id=sid,
                    rule_id=verified.check,
                    reason=verified.reason,
                )
                raise _Abort(await self._full_rollback(sess, fp, res))
            if verified.check == Check.VERSION_MISSING:
                await sess.rollback_to(sp)
                res = Result(
                    verdict=Verdict.CONCURRENT_MODIFICATION_CONFLICT,
                    session_id=sid,
                    rule_id=verified.check,
                    reason=verified.reason,
                )
                raise _Abort(await self._violation(sess, res, True))
            if verified.check != Check.OK:
                await sess.rollback_to(sp)
                res = Result(verdict=Verdict.POLICY_BLOCKED, session_id=sid, rule_id=verified.check, reason=verified.reason)
                raise _Abort(await self._violation(sess, res, True))
            final_sql = verified.sql
        elif isinstance(stmt, exp.Insert) and self.p.limits.compensate_on_trip:
            table = pol.table_name(stmt.this) if isinstance(stmt.this, exp.Table) else ""
            if table in self._pks:
                final_sql, key_mode = self._insert_with_keys(stmt, table)

        t_db = time.perf_counter()
        rows: list[dict[str, Any]] | None
        try:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(final_sql)
                if key_mode:
                    rows = await cur.fetchall()  # every key is needed for undo
                else:
                    rows = await cur.fetchmany(self.s.max_result_rows) if cur.description else None
                rowcount = cur.rowcount
        except psycopg.Error as e:
            db_ms = _ms(t_db)
            await sess.rollback_to(sp)
            if pr.is_write:
                sess.failed_writes.append(f"DB_ERROR:{e.sqlstate}")
            diag = e.diag.message_primary or str(e).splitlines()[0]
            res = Result(verdict=Verdict.DB_ERROR, session_id=sid, rule_id=e.sqlstate, reason=diag, db_ms=db_ms)
            raise _Abort(await self._trip_or(sess, sess.breaker.record_failure(pol.fingerprint(fp)), res)) from None
        db_ms = _ms(t_db)

        if key_mode and rows is not None:
            pk = self._pks[table]
            for r in rows:
                ver = r.pop(VER_ALIAS, None)
                undo.append(UndoEntry("insert", table, pk, r.pop(PK_ALIAS), None, int(ver) if ver is not None else None))
            rows = None if key_mode == "hidden" else rows[: self.s.max_result_rows]
        if verified is not None and pr.is_write:
            if rowcount > sess.role.max_rows_per_write:  # WHERE matched differently than the probe (volatile functions)
                await sess.rollback_to(sp)
                res = Result(
                    verdict=Verdict.POLICY_BLOCKED,
                    session_id=sid,
                    rule_id=Check.BLAST_RADIUS,
                    reason="write touched more rows than the cap",
                )
                raise _Abort(await self._violation(sess, res, True))
            undo = self._undo_for(stmt, table, verified)
            breach = await self._change_limit_breach(sess, table, verified) if isinstance(stmt, exp.Update) else None
            if breach:
                await sess.rollback_to(sp)
                res = Result(verdict=Verdict.POLICY_BLOCKED, session_id=sid, rule_id="CHANGE_LIMIT_EXCEEDED", reason=breach)
                raise _Abort(await self._violation(sess, res, True))
        if pr.is_write:
            violated = await self._check_invariants(sess, pr.tables)
            if violated:
                res = Result(
                    verdict=Verdict.INVARIANT_VIOLATION,
                    session_id=sid,
                    rule_id=violated,
                    reason=f"invariant {violated} failed after write; whole transaction rolled back",
                    db_ms=db_ms,
                )
                raise _Abort(await self._full_rollback(sess, fp, res))
        return Result(verdict=Verdict.OK, session_id=sid, rows=rows, rowcount=rowcount, role=sess.role_name, db_ms=db_ms), undo

    def _insert_with_keys(self, stmt: exp.Insert, table: str) -> tuple[str, str]:
        """Add RETURNING pk (and version) so the insert can be undone; hide them from the agent."""
        new = stmt.copy()
        extra: list[exp.Expr] = [exp.alias_(exp.column(self._pks[table]), PK_ALIAS)]
        if table in self._versioned:
            extra.append(exp.alias_(exp.column(self.p.version_column), VER_ALIAS))
        returning = new.args.get("returning")
        if isinstance(returning, exp.Returning):
            returning.set("expressions", [*returning.expressions, *extra])
            return new.sql("postgres"), "extra"
        new.set("returning", exp.Returning(expressions=extra))
        return new.sql("postgres"), "hidden"

    def _undo_for(self, stmt: exp.Expr | None, table: str, verified: VerifyResult) -> list[UndoEntry]:
        pk = self._pks.get(table)
        if pk is None:
            return []
        kind = "update" if isinstance(stmt, exp.Update) else "delete"
        vc = self.p.version_column
        out = []
        for row in verified.before:
            after = (
                int(row[vc]) + 1
                if (kind == "update" and vc in row and table in self._versioned)
                else (int(row[vc]) if vc in row else None)
            )
            out.append(UndoEntry(kind, table, pk, row[pk], row, after))  # type: ignore[arg-type]
        return out

    async def _change_limit_breach(self, sess: Session, table: str, verified: VerifyResult) -> str | None:
        limits = [c for c in self.p.change_limits if c.table == table]
        for lim in limits:
            keys = [r[lim.primary_key] for r in verified.before if lim.primary_key in r]
            if not keys:
                continue
            q = psycopg.sql.SQL("SELECT {pk}, {col} FROM {t} WHERE {pk} = ANY(%s)").format(
                pk=psycopg.sql.Identifier(lim.primary_key),
                col=psycopg.sql.Identifier(lim.column),
                t=psycopg.sql.Identifier(table),
            )
            now = {k: v for k, v in await (await sess.db.execute(q, (keys,))).fetchall()}
            for r in verified.before:
                old, new = r.get(lim.column), now.get(r.get(lim.primary_key))
                if old is None or new is None:
                    continue
                delta = abs(Decimal(str(new)) - Decimal(str(old)))
                if delta > Decimal(str(lim.max_abs_delta)):
                    return f"{table}.{lim.column} changed by {delta} on one row; limit is {lim.max_abs_delta}"
        return None

    async def _check_invariants(self, sess: Session, tables: frozenset[str]) -> str | None:
        for inv in self.p.invariants:
            if inv.table in tables:
                row = await (await sess.db.execute(inv.sql())).fetchone()
                if row and row[0]:
                    return inv.name
        return None


async def _secret_values(pool: AsyncConnectionPool[Any]) -> list[str]:
    """Best effort: known secret values to redact. A least-privilege role cannot read them; fine."""
    try:
        async with pool.connection() as conn:
            cur = await conn.execute("SELECT value::text FROM system_secrets")
            return [r[0] for r in await cur.fetchall()]
    except psycopg.Error:
        return []
