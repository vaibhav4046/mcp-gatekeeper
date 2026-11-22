"""Optimistic concurrency + blast-radius check for UPDATE/DELETE.

Before a write runs, the verifier selects the rows the write's WHERE clause matches, locks
them (FOR UPDATE) and captures a full before-image of each (to_jsonb). It then compares the
version column with the version the agent says it read earlier. A missing or different
version means CONCURRENT_MODIFICATION_CONFLICT before anything is mutated. If it matches,
the write is rewritten to bump the version and to re-assert it in WHERE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from psycopg import AsyncConnection
from sqlglot import exp


class Check(StrEnum):
    OK = "OK"
    CONFLICT = "CONCURRENT_MODIFICATION_CONFLICT"
    VERSION_MISSING = "MISSING_EXPECTED_VERSION"
    BLAST_RADIUS = "BLAST_RADIUS"


@dataclass(frozen=True)
class VerifyResult:
    check: Check
    sql: str
    reason: str
    before: list[dict[str, Any]] = field(default_factory=list)  # full row images of matched rows


def _qualifier(table: exp.Table) -> exp.Identifier:
    alias = table.args.get("alias")
    if isinstance(alias, exp.TableAlias) and isinstance(alias.this, exp.Identifier):
        return alias.this.copy()
    ident = table.this
    return ident.copy() if isinstance(ident, exp.Identifier) else exp.to_identifier(table.name)


def _extra_sources(stmt: exp.Update | exp.Delete) -> list[exp.Expr]:
    """Tables from UPDATE ... FROM / DELETE ... USING (sqlglot: `from_` is a From, `using` a list)."""
    if isinstance(stmt, exp.Update):
        frm = stmt.args.get("from_") or stmt.args.get("from")
        if isinstance(frm, exp.From):
            return [s for s in (frm.this, *frm.expressions) if isinstance(s, exp.Expr)]
        return []
    using = stmt.args.get("using")
    if isinstance(using, list):
        return [s for s in using if isinstance(s, exp.Expr)]
    return [using] if isinstance(using, exp.Expr) else []


def _probe(stmt: exp.Update | exp.Delete, limit: int) -> str:
    table: exp.Table = stmt.this
    q = _qualifier(table)
    image = exp.Anonymous(this="to_jsonb", expressions=[exp.Column(this=q.copy())])
    query = exp.select(image).from_(table.copy())
    for src in _extra_sources(stmt):
        query = query.join(src.copy(), join_type="cross")
    query = query.where(stmt.args["where"].this.copy())
    query = query.lock(update=True)
    query.args["locks"][0].set("expressions", [exp.Table(this=q.copy())])
    with_ = stmt.args.get("with_") or stmt.args.get("with")
    if isinstance(with_, exp.With):
        query.set("with_" if "with_" in stmt.args else "with", with_.copy())
    return query.limit(limit).sql("postgres")


def rewrite_versioned(stmt: exp.Update | exp.Delete, version_col: str, expected: int) -> str:
    new = stmt.copy()
    q = _qualifier(new.this)
    version_ref = exp.Column(this=exp.to_identifier(version_col), table=q.copy())
    if isinstance(new, exp.Update):
        bump = exp.EQ(this=exp.column(version_col), expression=exp.Add(this=version_ref.copy(), expression=exp.Literal.number(1)))
        new.set("expressions", [*new.expressions, bump])
    guard = exp.EQ(this=version_ref.copy(), expression=exp.Literal.number(expected))
    new.set("where", exp.Where(this=exp.and_(exp.paren(new.args["where"].this.copy()), guard)))
    return new.sql("postgres")


async def verify_write(
    conn: AsyncConnection[Any],
    stmt: exp.Update | exp.Delete,
    expected_version: int | None,
    *,
    versioned: bool,
    version_col: str,
    max_rows: int,
) -> VerifyResult:
    original = stmt.sql("postgres")
    if versioned and expected_version is None:
        return VerifyResult(
            Check.VERSION_MISSING,
            original,
            f"writes to versioned table {stmt.this.name} must pass expected_version (SELECT its {version_col} first)",
        )
    cur = await conn.execute(_probe(stmt, max_rows + 1))
    rows = [r[0] for r in await cur.fetchall()]
    if len(rows) > max_rows:
        return VerifyResult(Check.BLAST_RADIUS, original, f"write matches more than {max_rows} rows")
    if not versioned:
        return VerifyResult(Check.OK, original, "unversioned table; row cap ok", rows)
    seen = sorted({int(r[version_col]) for r in rows})
    if any(v != expected_version for v in seen):
        return VerifyResult(
            Check.CONFLICT, original, f"expected version {expected_version}, found {seen}: row changed since it was read"
        )
    assert expected_version is not None
    return VerifyResult(Check.OK, rewrite_versioned(stmt, version_col, expected_version), "version ok", rows)
