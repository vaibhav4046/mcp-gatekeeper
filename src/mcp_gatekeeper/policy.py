"""Static SQL policy built on the sqlglot AST (postgres dialect). No regex.

Fail-closed rules:
- SQL that does not parse, or parses to more or fewer than one statement, is blocked.
- The root statement must be SELECT / set query / INSERT / UPDATE / DELETE (admins may also run
  CREATE and ALTER). Opaque `Command` nodes and statement nodes nested anywhere are blocked.
- Functions must be on an allowlist. Unknown functions are blocked, not guessed about.
- Tables must exist in the gatekeeper's schema snapshot and be allowlisted for the role.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.simplify import simplify

from .config import Policy, Role

logging.getLogger("sqlglot").setLevel(logging.ERROR)

ALWAYS_BLOCKED_DDL: tuple[type[exp.Expr], ...] = (exp.Drop, exp.TruncateTable, exp.Grant, exp.Revoke)
ADMIN_DDL: tuple[type[exp.Expr], ...] = (exp.Create, exp.Alter, exp.Comment)
WRITE_NODES: tuple[type[exp.Expr], ...] = (exp.Insert, exp.Update, exp.Delete, exp.Merge)
# Statement-like nodes that must never appear anywhere in an agent's query.
FOREIGN_STATEMENTS: tuple[type[exp.Expr], ...] = (
    exp.Command,
    exp.Set,
    exp.Copy,
    exp.Use,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Into,
    exp.Merge,
)

OPERATOR_NODES: tuple[type[exp.Expr], ...] = (exp.Binary, exp.Unary, exp.Connector, exp.Predicate)

# sqlglot sql_name() of typed functions, plus names of functions sqlglot leaves anonymous.
DEFAULT_ALLOWED_FUNCTIONS = frozenset(
    {
        "count", "sum", "avg", "min", "max", "coalesce", "nullif", "greatest", "least",
        "upper", "lower", "length", "substring", "trim", "round", "abs", "ceil", "floor",
        "current_timestamp", "current_date", "timestamp_trunc", "date_trunc", "extract",
        "concat", "group_concat", "array_agg", "cast", "try_cast", "case", "if", "exists",
        "time_to_str", "row_number", "rank", "dense_rank",
    }
)  # fmt: skip


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    rule_id: str | None
    reason: str
    statement: exp.Expr | None = None
    # True unless the statement is provably a read. Blocked statements that might have been
    # writes taint the transaction so a half-done unit of work cannot commit.
    is_write: bool = True
    is_ddl: bool = False
    tables: frozenset[str] = field(default_factory=frozenset)


def _block(rule_id: str, reason: str, *, is_write: bool = True, tables: frozenset[str] = frozenset()) -> PolicyResult:
    return PolicyResult(False, rule_id, reason, is_write=is_write, tables=tables)


def parse(sql: str) -> list[exp.Expr]:
    return [s for s in sqlglot.parse(sql, read="postgres") if s is not None]


def table_name(t: exp.Table) -> str:
    """Postgres folds unquoted identifiers to lower case and keeps quoted ones as written."""
    ident = t.this
    if isinstance(ident, exp.Identifier) and ident.quoted:
        return str(ident.this)
    return t.name.lower()


def is_tautology(cond: exp.Expr) -> bool:
    """True when a WHERE condition is trivially true for every row."""
    if isinstance(cond, exp.Paren):
        return is_tautology(cond.this)
    if isinstance(cond, exp.Or):
        return is_tautology(cond.left) or is_tautology(cond.right)
    if isinstance(cond, exp.And):
        return is_tautology(cond.left) and is_tautology(cond.right)
    if isinstance(cond, (exp.EQ, exp.GTE, exp.LTE, exp.NullSafeEQ)) and cond.left == cond.right:
        return True  # id = id, x >= x
    if isinstance(cond, exp.Like) and isinstance(cond.expression, exp.Literal) and cond.expression.this == "%":
        return True  # col LIKE '%'
    if cond.find(exp.Column) is None and cond.find(exp.Query) is None:
        folded = simplify(cond.copy())  # constant: 1=1, TRUE, 'a'='a', NOT FALSE, 2>1
        return isinstance(folded, exp.Boolean) and bool(folded.this)
    return False


def function_name(fn: exp.Func) -> str:
    if isinstance(fn, exp.Anonymous):
        return fn.name.lower()
    return fn.sql_name().lower()


def _cte_names(stmt: exp.Expr) -> set[str]:
    return {cte.alias_or_name.lower() for cte in stmt.find_all(exp.CTE)}


def _projection_aliases(stmt: exp.Expr) -> set[str]:
    return {a.alias.lower() for a in stmt.find_all(exp.Alias) if a.alias}


def _check_tables(stmt: exp.Expr, policy: Policy, role: Role, known: frozenset[str] | None) -> PolicyResult | None:
    ctes = _cte_names(stmt)
    for t in stmt.find_all(exp.Table):
        if not t.name:
            continue
        name, schema = table_name(t), (t.db or "").lower()
        if not schema and name.lower() in ctes:
            continue
        if name.lower() in policy.restricted_tables or schema in policy.restricted_schemas or name.lower().startswith("pg_"):
            return _block("RESTRICTED_TABLE", f"access to {schema + '.' if schema else ''}{name} is not allowed")
        if schema and schema != "public":
            return _block("TABLE_NOT_ALLOWED", f"schema-qualified table {schema}.{name} is outside the allowed schema")
        if known is not None and name not in known:
            return _block("UNKNOWN_TABLE", f"table {name} is not in the gatekeeper's schema snapshot")
        if role.tables is not None and name not in role.tables:
            return _block("TABLE_NOT_ALLOWED", f"role {role.kind} may not use table {name}")
    return None


def _real_tables(stmt: exp.Expr) -> dict[str, str]:
    """alias-or-name -> table name, for tables that are not CTE references."""
    ctes = _cte_names(stmt)
    out: dict[str, str] = {}
    for t in stmt.find_all(exp.Table):
        if t.name and not (not t.db and t.name.lower() in ctes):
            out[t.alias_or_name.lower()] = table_name(t)
    return out


def _check_columns(stmt: exp.Expr, role: Role) -> PolicyResult | None:
    if role.tables is None:
        return None
    tables = _real_tables(stmt)
    names = set(tables.values())
    aliases = _projection_aliases(stmt) | _cte_names(stmt)
    for star in stmt.find_all(exp.Star):
        parent = star.parent
        qualifier = parent.table.lower() if isinstance(parent, exp.Column) and parent.table else None
        targets = [tables[qualifier]] if qualifier in tables else ([] if qualifier else sorted(names))
        for tname in targets:
            if role.tables[tname].read != "*":
                return _block(
                    "COLUMN_NOT_ALLOWED", f"SELECT * on {tname} would expose columns outside the allowlist", is_write=False
                )
    for col in stmt.find_all(exp.Column):
        if isinstance(col.this, exp.Star):
            continue
        cname = col.name.lower()
        qualifier = col.table.lower() if col.table else None
        if qualifier and qualifier in tables:
            if not role.tables[tables[qualifier]].can_read(cname):
                return _block("COLUMN_NOT_ALLOWED", f"column {tables[qualifier]}.{cname} is not allowlisted", is_write=False)
        elif not qualifier:
            if cname in aliases:
                continue
            if names and not any(role.tables[t].can_read(cname) for t in names):
                return _block("COLUMN_NOT_ALLOWED", f"column {cname} is not allowlisted on {sorted(names)}", is_write=False)
    return None


def _check_write(node: exp.Expr, stmt: exp.Expr, policy: Policy, role: Role) -> PolicyResult | None:
    tables = frozenset(_real_tables(stmt).values())
    if node is not stmt:
        return _block("NESTED_WRITE", "data-modifying statements inside CTEs/subqueries are not allowed", tables=tables)
    if role.kind == "read_only":
        return _block("ROLE_READ_ONLY", "this agent's role is read_only", tables=tables)
    target = node.this if isinstance(node.this, exp.Table) else node.find(exp.Table)
    tname = table_name(target) if isinstance(target, exp.Table) else ""
    access = role.tables.get(tname) if role.tables is not None else None
    if isinstance(node, exp.Insert):
        conflict = node.args.get("conflict")
        if conflict is not None and conflict.args.get("expressions"):
            return _block("UPSERT_UPDATE", "INSERT ... ON CONFLICT DO UPDATE bypasses version checks", tables=tables)
        if role.tables is not None and (access is None or not access.insert):
            return _block("WRITE_NOT_ALLOWED", f"role {role.kind} may not INSERT into {tname}", tables=tables)
        return None
    verb = type(node).__name__.upper()
    if isinstance(node, exp.Delete) and role.tables is not None and (access is None or not access.delete):
        return _block("WRITE_NOT_ALLOWED", f"role {role.kind} may not DELETE from {tname}", tables=tables)
    where = node.args.get("where")
    if where is None:
        return _block("NO_WHERE", f"{verb} without WHERE touches every row", tables=tables)
    if is_tautology(where.this):
        return _block("TAUTOLOGICAL_WHERE", f"{verb} WHERE clause is always true: {where.this.sql('postgres')}", tables=tables)
    if isinstance(node, exp.Update):
        for assignment in node.expressions:
            col = assignment.this
            cname = col.name.lower() if isinstance(col, exp.Column) else ""
            if cname == policy.version_column:
                return _block("VERSION_TAMPER", f"the {policy.version_column} column is managed by the gatekeeper", tables=tables)
            if role.tables is not None and (access is None or not access.can_update(cname)):
                return _block("WRITE_NOT_ALLOWED", f"role {role.kind} may not UPDATE {tname}.{cname or '?'}", tables=tables)
    return None


def check(
    sql: str,
    policy: Policy,
    role: Role,
    known_tables: Iterable[str] | None = None,
    allowed_functions: frozenset[str] = DEFAULT_ALLOWED_FUNCTIONS,
) -> PolicyResult:
    known = frozenset(known_tables) if known_tables is not None else None
    try:
        statements = parse(sql)
    except SqlglotError as e:
        return _block("PARSE_ERROR", f"SQL could not be parsed; refusing to guess: {str(e).splitlines()[0]}")
    if not statements:
        return _block("EMPTY", "no SQL statement found", is_write=False)
    if len(statements) > 1:
        return _block("MULTI_STATEMENT", f"{len(statements)} statements in one call; send exactly one")

    stmt = statements[0]
    tables = frozenset(_real_tables(stmt).values())
    writes = [n for n in stmt.walk() if isinstance(n, WRITE_NODES)]
    is_read = isinstance(stmt, exp.Query) and not writes

    bad_ddl = next((n for n in stmt.walk() if isinstance(n, ALWAYS_BLOCKED_DDL)), None)
    if bad_ddl is not None:
        return _block("DDL_BLOCKED", f"{type(bad_ddl).__name__.upper()} is never allowed", tables=tables)
    is_ddl = isinstance(stmt, ADMIN_DDL)
    if is_ddl and role.kind != "admin":
        return _block("DDL_BLOCKED", f"{type(stmt).__name__.upper()} needs the admin role", tables=tables)
    if not is_ddl and not isinstance(stmt, (exp.Query, exp.Insert, exp.Update, exp.Delete)):
        return _block("STATEMENT_NOT_ALLOWED", f"{type(stmt).__name__} statements are not allowed", tables=tables)
    foreign = next((n for n in stmt.walk() if isinstance(n, FOREIGN_STATEMENTS)), None)
    if foreign is not None:
        return _block("STATEMENT_NOT_ALLOWED", f"{type(foreign).__name__} is not allowed inside a statement", tables=tables)

    blocked = _check_tables(stmt, policy, role, None if is_ddl else known)
    if blocked:
        return PolicyResult(False, blocked.rule_id, blocked.reason, is_write=not is_read, tables=tables)

    allowed_fns = allowed_functions | role.allow_functions
    for fn in stmt.find_all(exp.Func):
        if isinstance(fn, OPERATOR_NODES):
            continue  # sqlglot models AND/OR/NOT/+/= as Func subclasses; they are operators, not calls
        fname = function_name(fn)
        if fname in role.allow_functions:
            continue
        if fname not in allowed_fns or fname in policy.denied_functions:
            return _block(
                "FUNCTION_NOT_ALLOWED", f"function {fname}() is not on the allowlist", is_write=not is_read, tables=tables
            )

    if not is_ddl:
        blocked = _check_columns(stmt, role)
        if blocked:
            return PolicyResult(False, blocked.rule_id, blocked.reason, is_write=not is_read, tables=tables)
    for node in writes:
        blocked = _check_write(node, stmt, policy, role)
        if blocked:
            return blocked

    return PolicyResult(True, None, "allowed", statement=stmt, is_write=not is_read, is_ddl=is_ddl, tables=tables)


def fingerprint(sql: str) -> str:
    """Normalise a query so retries that differ only in literals compare equal."""
    try:
        statements = parse(sql)
    except SqlglotError:
        return " ".join(sql.lower().split())
    normalised = [
        s.transform(lambda n: exp.Placeholder() if isinstance(n, exp.Literal) else n).sql("postgres") for s in statements
    ]
    return "; ".join(normalised).lower()
