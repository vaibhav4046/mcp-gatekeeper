"""The C++ backend must agree with the Python reference on the project's own policy cases.
Skipped when the binary is not built (cmake -S cpp -B cpp/build && cmake --build cpp/build)."""

from __future__ import annotations

import pytest

from mcp_gatekeeper.config import DEFAULT_POLICY
from mcp_gatekeeper.native import DEFAULT_BINARY, NativePolicy
from mcp_gatekeeper.policy import check

KNOWN = {"accounts", "orders", "audit_logs", "system_secrets"}
SQLS = [
    "SELECT id, balance, version FROM accounts WHERE id = 3",
    "UPDATE accounts SET balance = balance - 10 WHERE id = 3",
    "DELETE FROM orders",
    "DELETE FROM orders WHERE 1=1",
    "SELECT * FROM system_secrets",
    "SELECT pg_sleep(10)",
    "DROP TABLE accounts",
    "SELECT 1; SELECT 2",
    "WITH d AS (DELETE FROM orders WHERE id = 1 RETURNING *) SELECT * FROM d",
    "INSERT INTO accounts (id, owner, balance) VALUES (1, 'a', 1) ON CONFLICT (id) DO UPDATE SET balance = 0",
    "SELEC * FROM accounts",
]


@pytest.mark.skipif(not DEFAULT_BINARY.exists(), reason="gatekeeper-cpp not built")
@pytest.mark.parametrize("role", ["scoped_write", "read_only", "admin"])
def test_native_matches_reference(role: str) -> None:
    with NativePolicy(DEFAULT_POLICY) as native:
        for sql in SQLS:
            want = check(sql, DEFAULT_POLICY, DEFAULT_POLICY.roles[role], KNOWN)
            got = native.check(sql, role, KNOWN)
            assert (got.allowed, got.rule_id, got.is_write, got.is_ddl, got.tables) == (
                want.allowed,
                want.rule_id,
                want.is_write,
                want.is_ddl,
                want.tables,
            ), sql
