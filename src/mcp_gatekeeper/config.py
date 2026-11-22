"""Policy (policies.yaml, validated by pydantic v2) and runtime settings.

Everything here is deterministic configuration. No model calls anywhere.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import sqlglot
import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlglot import exp

DEFAULT_DATABASE_URL = "postgresql://gatekeeper:gatekeeper@localhost:5432/gatekeeper"

# Functions that read the server filesystem, change settings, open connections, or stall a
# backend. Every function whose name starts with "pg_" is denied as well, unless a role lists
# it in allow_functions.
DEFAULT_DENIED_FUNCTIONS = frozenset(
    {
        "current_setting",
        "set_config",
        "dblink",
        "dblink_exec",
        "dblink_connect",
        "lo_import",
        "lo_export",
        "lo_get",
        "lo_put",
        "query_to_xml",
        "query_to_json",
        "table_to_xml",
        "database_to_xml",
        "inet_server_addr",
        "inet_server_port",
    }
)

Columns = Literal["*"] | list[str]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TableAccess(_Strict):
    """What a role may do with one table. Column lists are lower-case names or "*"."""

    read: Columns = "*"
    update: Columns = []
    insert: bool = False
    delete: bool = False

    def can_read(self, column: str) -> bool:
        return self.read == "*" or column in self.read

    def can_update(self, column: str) -> bool:
        return self.update == "*" or column in self.update


class Role(_Strict):
    kind: Literal["read_only", "scoped_write", "admin"]
    # None = every table that is not restricted (only allowed for admin).
    tables: dict[str, TableAccess] | None = None
    max_rows_per_write: int = Field(default=10, ge=1)
    allow_functions: frozenset[str] = frozenset()

    @model_validator(mode="after")
    def _check(self) -> Role:
        if self.tables is None and self.kind != "admin":
            raise ValueError(f"{self.kind} roles need an explicit table allowlist")
        if self.kind == "read_only" and self.tables:
            for name, access in self.tables.items():
                if access.update or access.insert or access.delete:
                    raise ValueError(f"read_only role grants writes on {name}")
        return self


class Invariant(_Strict):
    """Declarative post-write rule, e.g. table=accounts, check="balance >= 0".

    Compiled to `SELECT count(*) FROM <table> WHERE NOT (<check>)`; any row returned is a
    violation and rolls back the whole session transaction.
    """

    name: str
    table: str
    check: str

    @field_validator("check")
    @classmethod
    def _parse(cls, v: str) -> str:
        try:
            cond = sqlglot.parse_one(v, read="postgres")
        except sqlglot.errors.SqlglotError as e:
            raise ValueError(f"invariant check does not parse: {e}") from e
        if cond.find(exp.Query) is not None or isinstance(cond, exp.Query):
            raise ValueError("invariant checks may not contain subqueries")
        return v

    def sql(self) -> str:
        cond = sqlglot.parse_one(self.check, read="postgres")
        query = exp.select("count(*)").from_(exp.to_table(self.table)).where(exp.Not(this=exp.paren(cond)))
        return query.sql("postgres")


class ChangeLimit(_Strict):
    """Largest allowed change of a numeric column per UPDATE row (checked after the write)."""

    table: str
    column: str
    max_abs_delta: float = Field(gt=0)
    primary_key: str = "id"


class Limits(_Strict):
    max_identical_failures: int = 3  # trip when the same normalised query fails more often in the window
    failure_window_s: float = 30.0
    max_policy_violations: int = 3  # trip at this many violations
    max_writes: int = 20  # trip on the write after this many
    statement_timeout_ms: int = 5000
    lock_timeout_ms: int = 2000
    session_idle_timeout_s: float = 300.0
    compensate_on_trip: bool = True  # undo this session's committed writes when the breaker trips


class Policy(_Strict):
    version: Literal[1] = 1
    default_agent: str = "default"
    agents: dict[str, str] = {"default": "scoped_write"}
    roles: dict[str, Role]
    restricted_tables: frozenset[str] = frozenset({"audit_logs", "system_secrets"})
    restricted_schemas: frozenset[str] = frozenset({"pg_catalog", "information_schema", "pg_toast"})
    denied_functions: frozenset[str] = DEFAULT_DENIED_FUNCTIONS
    version_column: str = "version"
    invariants: tuple[Invariant, ...] = ()
    change_limits: tuple[ChangeLimit, ...] = ()
    limits: Limits = Limits()

    @model_validator(mode="after")
    def _check(self) -> Policy:
        for agent, role in self.agents.items():
            if role not in self.roles:
                raise ValueError(f"agent {agent!r} uses unknown role {role!r}")
        if self.default_agent not in self.agents:
            raise ValueError(f"default_agent {self.default_agent!r} is not in agents")
        for role_name, role_def in self.roles.items():
            for table in role_def.tables or {}:
                if table in self.restricted_tables:
                    raise ValueError(f"role {role_name!r} allowlists restricted table {table!r}")
        return self

    def role_for(self, agent: str | None) -> tuple[str, Role]:
        name = agent or self.default_agent
        if name not in self.agents:
            raise KeyError(f"unknown agent {name!r}")
        role_name = self.agents[name]
        return role_name, self.roles[role_name]

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(data)


DEFAULT_POLICY_YAML = """\
# mcp-gatekeeper policy. Validated at startup; an invalid file stops the server.
version: 1

# Which role each agent identity gets. The identity is fixed by the operator when the server
# starts (`mcp-gatekeeper serve --agent NAME`), never chosen by the model.
default_agent: default
agents:
  default: scoped_write
  analyst: read_only
  dba: admin

roles:
  read_only:
    kind: read_only
    tables:
      accounts: {read: "*"}
      orders: {read: "*"}
  scoped_write:
    kind: scoped_write
    max_rows_per_write: 10
    tables:
      accounts: {read: "*", update: [balance, owner], insert: true, delete: false}
      orders: {read: "*", update: [status, amount], insert: true, delete: true}
  admin:
    kind: admin            # all non-restricted tables; DDL allowed except DROP/TRUNCATE/GRANT/REVOKE
    max_rows_per_write: 1000
    allow_functions: [pg_sleep]

restricted_tables: [audit_logs, system_secrets]

invariants:
  - {name: non_negative_balance, table: accounts, check: "balance >= 0"}

change_limits:
  - {table: accounts, column: balance, max_abs_delta: 10000}

limits:
  max_identical_failures: 3
  failure_window_s: 30
  max_policy_violations: 3
  max_writes: 20
  statement_timeout_ms: 5000
  lock_timeout_ms: 2000
  session_idle_timeout_s: 300
  compensate_on_trip: true
"""

DEFAULT_POLICY = Policy.model_validate(yaml.safe_load(DEFAULT_POLICY_YAML))


class Settings(BaseModel):
    model_config = ConfigDict(frozen=True)

    database_url: str = DEFAULT_DATABASE_URL
    policy: Policy = DEFAULT_POLICY
    agent: str | None = None  # identity used when begin_session is not given one
    audit_key: str | None = None  # HMAC-SHA256 key for traces (GATEKEEPER_AUDIT_KEY)
    max_result_rows: int = 200
    hash_state: bool = True
    trace_dir: str = "traces"
    pool_min: int = 2
    pool_max: int = 50
    session_acquire_timeout_s: float = 10.0

    @classmethod
    def from_env(cls, **overrides: object) -> Settings:
        values: dict[str, object] = {}
        if url := os.environ.get("DATABASE_URL"):
            values["database_url"] = url
        if trace_dir := os.environ.get("GATEKEEPER_TRACE_DIR"):
            values["trace_dir"] = trace_dir
        if key := os.environ.get("GATEKEEPER_AUDIT_KEY"):
            values["audit_key"] = key
        if agent := os.environ.get("GATEKEEPER_AGENT"):
            values["agent"] = agent
        if policy_path := os.environ.get("GATEKEEPER_POLICY"):
            values["policy"] = Policy.load(policy_path)
        values.update(overrides)
        return cls.model_validate(values)
