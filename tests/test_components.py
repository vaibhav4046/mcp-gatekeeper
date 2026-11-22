from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import psycopg
import pytest
from conftest import begin, read
from pydantic import ValidationError

from mcp_gatekeeper import Gatekeeper, Policy, Verdict
from mcp_gatekeeper.audit import AuditLog, Redactor, verify_trace
from mcp_gatekeeper.breaker import CircuitBreaker
from mcp_gatekeeper.config import DEFAULT_POLICY, Invariant, Limits
from mcp_gatekeeper.policy import check, fingerprint, is_tautology, parse

P = DEFAULT_POLICY
WRITER = P.roles["scoped_write"]
READER = P.roles["read_only"]
ADMIN = P.roles["admin"]
KNOWN = {"accounts", "orders", "audit_logs", "system_secrets"}


# ---------------------------------------------------------------- policy (no DB)
@pytest.mark.parametrize(
    ("sql", "rule"),
    [
        ("DROP TABLE accounts", "DDL_BLOCKED"),
        ("/* maintenance */ DROP TABLE accounts", "DDL_BLOCKED"),
        ("TRUNCATE orders", "DDL_BLOCKED"),
        ("ALTER TABLE accounts DROP COLUMN balance", "DDL_BLOCKED"),
        ("CREATE TABLE x (id int)", "DDL_BLOCKED"),
        ("GRANT ALL ON system_secrets TO PUBLIC", "DDL_BLOCKED"),
        ("REVOKE ALL ON accounts FROM PUBLIC", "DDL_BLOCKED"),
        ("SELECT * INTO copy_of_accounts FROM accounts", "STATEMENT_NOT_ALLOWED"),
        ("SELECT 1; DROP TABLE accounts", "MULTI_STATEMENT"),
        ("SELECT 1; /* harmless */ DROP TABLE accounts", "MULTI_STATEMENT"),
        ("DELETE FROM orders", "NO_WHERE"),
        ("UPDATE accounts SET balance = 0", "NO_WHERE"),
        ("DELETE FROM orders WHERE 1=1", "TAUTOLOGICAL_WHERE"),
        ("DELETE FROM orders WHERE TRUE", "TAUTOLOGICAL_WHERE"),
        ("DELETE FROM orders WHERE id = id", "TAUTOLOGICAL_WHERE"),
        ("UPDATE accounts SET balance = 0 WHERE (owner = 'x' OR 'a' = 'a')", "TAUTOLOGICAL_WHERE"),
        ("DELETE FROM orders WHERE status LIKE '%'", "TAUTOLOGICAL_WHERE"),
        ("SELECT * FROM system_secrets", "RESTRICTED_TABLE"),
        ("SELECT owner FROM accounts UNION SELECT value FROM system_secrets", "RESTRICTED_TABLE"),
        ("WITH s AS (SELECT value FROM system_secrets) SELECT * FROM s", "RESTRICTED_TABLE"),
        ("SELECT (SELECT value FROM SYSTEM_SECRETS LIMIT 1) FROM accounts", "RESTRICTED_TABLE"),
        ("DELETE FROM audit_logs WHERE id < 10", "RESTRICTED_TABLE"),
        ("SELECT rolname, rolpassword FROM pg_authid", "RESTRICTED_TABLE"),
        ("SELECT * FROM information_schema.tables", "RESTRICTED_TABLE"),
        ("SELECT * FROM other.accounts", "TABLE_NOT_ALLOWED"),
        ('UPDATE "Accounts" SET balance = 1 WHERE id = 1', "UNKNOWN_TABLE"),
        ("SELECT pg_read_file('PG_VERSION')", "FUNCTION_NOT_ALLOWED"),
        ("SELECT \"pg_read_file\"('PG_VERSION')", "FUNCTION_NOT_ALLOWED"),
        ("SELECT query_to_xml_and_xmlschema('select 1', true, true, '')", "FUNCTION_NOT_ALLOWED"),
        ("SELECT * FROM ts_stat('select 1')", "FUNCTION_NOT_ALLOWED"),
        ("SELECT nextval('orders_id_seq')", "FUNCTION_NOT_ALLOWED"),
        ("SELECT pg_sleep(10)", "FUNCTION_NOT_ALLOWED"),
        ("SELECT set_config('statement_timeout', '0', false)", "FUNCTION_NOT_ALLOWED"),
        ("COPY accounts TO STDOUT", "STATEMENT_NOT_ALLOWED"),
        ("SET statement_timeout = 0", "STATEMENT_NOT_ALLOWED"),
        ("VACUUM", "STATEMENT_NOT_ALLOWED"),
        ("WITH d AS (DELETE FROM orders WHERE id = 1 RETURNING *) SELECT * FROM d", "NESTED_WRITE"),
        ("UPDATE accounts SET version = 1 WHERE id = 1", "VERSION_TAMPER"),
        (
            "INSERT INTO accounts (id, owner, balance) VALUES (1, 'a', 1) ON CONFLICT (id) DO UPDATE SET balance = 0",
            "UPSERT_UPDATE",
        ),
        ("DELETE FROM accounts WHERE id = 3", "WRITE_NOT_ALLOWED"),
        ("SELEC * FROM accounts", "PARSE_ERROR"),
        ("", "EMPTY"),
    ],
)
def test_policy_blocks_for_scoped_write(sql: str, rule: str) -> None:
    res = check(sql, P, WRITER, KNOWN)
    assert not res.allowed, sql
    assert res.rule_id == rule, (sql, res)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id, balance, version FROM accounts WHERE id = 3",
        "SELECT count(*) FROM orders WHERE status = 'pending'",
        "SELECT count(*) AS n FROM orders GROUP BY status ORDER BY n",
        "UPDATE accounts SET balance = balance - 10 WHERE id = 3",
        "DELETE FROM orders WHERE id = 17",
        "INSERT INTO orders (account_id, amount) VALUES (1, 20)",
        "INSERT INTO orders (account_id, amount) VALUES (1, 20) ON CONFLICT DO NOTHING",
        "SELECT a.owner, o.amount FROM accounts a JOIN orders o ON o.account_id = a.id WHERE a.id = 2",
        "SELECT * FROM accounts WHERE id = 1 FOR UPDATE",
        "SELECT upper(owner), coalesce(balance, 0), now() FROM accounts WHERE id = 1",
        "WITH big AS (SELECT id FROM orders WHERE amount > 20) SELECT count(*) FROM big",
    ],
)
def test_policy_allows_for_scoped_write(sql: str) -> None:
    res = check(sql, P, WRITER, KNOWN)
    assert res.allowed, (sql, res)


def test_read_only_role_blocks_every_write() -> None:
    for sql in (
        "UPDATE accounts SET balance = 1 WHERE id = 1",
        "INSERT INTO orders (account_id, amount) VALUES (1, 2)",
        "DELETE FROM orders WHERE id = 1",
    ):
        res = check(sql, P, READER, KNOWN)
        assert not res.allowed and res.rule_id == "ROLE_READ_ONLY", sql
    assert check("SELECT owner FROM accounts WHERE id = 1", P, READER, KNOWN).allowed


def test_column_allowlist() -> None:
    narrow = Policy.model_validate(
        {
            "agents": {"default": "r"},
            "roles": {"r": {"kind": "scoped_write", "tables": {"accounts": {"read": ["id", "owner"], "update": ["owner"]}}}},
        }
    )
    role = narrow.roles["r"]
    assert check("SELECT id, owner FROM accounts WHERE id = 1", narrow, role, KNOWN).allowed
    assert check("SELECT balance FROM accounts", narrow, role, KNOWN).rule_id == "COLUMN_NOT_ALLOWED"
    assert check("SELECT * FROM accounts", narrow, role, KNOWN).rule_id == "COLUMN_NOT_ALLOWED"
    assert check("UPDATE accounts SET owner = 'x' WHERE id = 1", narrow, role, KNOWN).allowed
    assert check("UPDATE accounts SET balance = 0 WHERE id = 1", narrow, role, KNOWN).rule_id in {
        "COLUMN_NOT_ALLOWED",
        "WRITE_NOT_ALLOWED",
    }


def test_admin_role_still_blocks_destructive_ddl_and_restricted_tables() -> None:
    assert check("CREATE INDEX idx ON orders (status)", P, ADMIN, KNOWN).allowed
    for sql, rule in [
        ("DROP TABLE orders", "DDL_BLOCKED"),
        ("TRUNCATE orders", "DDL_BLOCKED"),
        ("GRANT SELECT ON accounts TO PUBLIC", "DDL_BLOCKED"),
        ("SELECT * FROM system_secrets", "RESTRICTED_TABLE"),
        ("DELETE FROM audit_logs WHERE id = 1", "RESTRICTED_TABLE"),
        ("SELECT 1; SELECT 2", "MULTI_STATEMENT"),
    ]:
        assert check(sql, P, ADMIN, KNOWN).rule_id == rule, sql
    assert check("SELECT pg_sleep(0.01)", P, ADMIN, KNOWN).allowed  # opted in via allow_functions


def test_blocked_unparseable_statement_counts_as_possible_write() -> None:
    assert check("UPDATE accounts SET balance = 1 WHER id = 2", P, WRITER, KNOWN).is_write
    assert not check("SELECT * FROM system_secrets", P, WRITER, KNOWN).is_write


def test_policy_file_validation() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate({"agents": {"default": "missing"}, "roles": {}})
    with pytest.raises(ValidationError):
        Policy.model_validate({"agents": {"default": "r"}, "roles": {"r": {"kind": "scoped_write"}}})  # no allowlist
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {"agents": {"default": "r"}, "roles": {"r": {"kind": "read_only", "tables": {"accounts": {"insert": True}}}}}
        )
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {"agents": {"default": "r"}, "roles": {"r": {"kind": "scoped_write", "tables": {"system_secrets": {}}}}}
        )
    with pytest.raises(ValidationError):
        Invariant(name="x", table="accounts", check="balance >= (SELECT 1)")
    assert (
        Invariant(name="x", table="accounts", check="balance >= 0").sql()
        == "SELECT COUNT(*) FROM accounts WHERE NOT (balance >= 0)"
    )


def test_tautology_does_not_flag_real_filters() -> None:
    cond = parse("SELECT 1 WHERE id > 0 AND status = 'x'")[0].args["where"].this
    assert not is_tautology(cond)


def test_fingerprint_normalises_literals() -> None:
    assert fingerprint("SELECT * FROM acounts WHERE id = 1") == fingerprint("select *  from acounts where id = 99")
    assert fingerprint("SELECT * FROM a WHERE id = 1") != fingerprint("SELECT * FROM b WHERE id = 1")


# ---------------------------------------------------------------- breaker (no DB)
class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_breaker_repeated_failures_within_window() -> None:
    b = CircuitBreaker(Limits(), FakeClock())
    for _ in range(3):
        assert b.record_failure("q") is None
    trip = b.record_failure("q")
    assert trip is not None and trip.startswith("REPEATED_FAILURE")


def test_breaker_failures_outside_window_do_not_trip() -> None:
    clock = FakeClock()
    b = CircuitBreaker(Limits(), clock)
    for _ in range(10):
        assert b.record_failure("q") is None
        clock.t += 11  # at most 3 failures per 30 s window
    assert b.tripped is None


def test_breaker_violations_and_write_cap() -> None:
    b = CircuitBreaker(Limits())
    assert b.record_violation() is None and b.record_violation() is None
    trip = b.record_violation()
    assert trip is not None and trip.startswith("POLICY_VIOLATIONS")
    w = CircuitBreaker(Limits())
    assert all(w.record_write() is None for _ in range(20))
    trip = w.record_write()
    assert trip is not None and trip.startswith("WRITE_LIMIT")


# ---------------------------------------------------------------- audit (no DB)
def _write_trace(path: Path, key: str | None = None) -> None:
    log = AuditLog(path, Redactor(["CANARY_root_9b21"]), key)
    log.write({"event": "begin_session", "verdict": "OK"})
    log.write({"event": "execute_sql", "sql": "SELECT 1", "verdict": "OK", "latency_ms": 1.5})
    log.write(
        {
            "event": "execute_sql",
            "sql": "UPDATE accounts SET owner = 'ops@example.com' WHERE id = 1",
            "reason": "password=hunter2 CANARY_root_9b21",
        }
    )
    log.close()


def test_trace_chain_verifies_and_detects_one_character_edit(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    _write_trace(path)
    assert verify_trace(path).ok
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"latency_ms":1.5', '"latency_ms":1.6')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = verify_trace(path)
    assert not report.ok and report.bad_line == 2


def test_trace_detects_deleted_lines(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    _write_trace(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert verify_trace(path).bad_line == 2


def test_trace_hmac(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    _write_trace(path, key="k1")
    assert verify_trace(path, key="k1").ok
    assert not verify_trace(path, key="other").ok


def test_trace_redacts_secrets_and_emails(tmp_path: Path) -> None:
    path = tmp_path / "t.jsonl"
    _write_trace(path)
    text = path.read_text(encoding="utf-8")
    for leaked in ("ops@example.com", "hunter2", "CANARY_root_9b21"):
        assert leaked not in text


def test_redactor_patterns() -> None:
    s = Redactor().text(
        "conn postgresql://app:s3cr3t@db/x key sk_live_ABCDEF123456 gh ghp_"
        + "a" * 36
        + " mail a.b@corp.io Bearer abcdefghijklmnop"
    )
    for leaked in ("s3cr3t", "sk_live_ABCDEF123456", "ghp_", "a.b@corp.io", "abcdefghijklmnop"):
        assert leaked not in s, s


# ---------------------------------------------------------------- integration (Postgres)
async def test_versioned_update_bumps_version(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    _, ver = await read(gk, sid, 1)
    res = await gk.execute_sql(sid, "UPDATE accounts SET balance = balance - 10 WHERE id = 1", expected_version=ver)
    assert res.verdict == Verdict.OK and res.rowcount == 1
    assert (await gk.commit_session(sid)).verdict == Verdict.COMMITTED
    assert admin.execute("SELECT balance, version FROM accounts WHERE id = 1").fetchone() == (990, ver + 1)


async def test_update_without_version_is_a_conflict(gk: Gatekeeper) -> None:
    sid = await begin(gk)
    res = await gk.execute_sql(sid, "UPDATE accounts SET balance = 0 WHERE id = 1")
    assert res.verdict == Verdict.CONCURRENT_MODIFICATION_CONFLICT and res.rule_id == "MISSING_EXPECTED_VERSION"


async def test_blast_radius_blocks_mass_update(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    res = await gk.execute_sql(sid, "UPDATE accounts SET balance = 0 WHERE id > 0", expected_version=1)
    assert res.verdict == Verdict.POLICY_BLOCKED and res.rule_id == "BLAST_RADIUS"
    assert admin.execute("SELECT count(*) FROM accounts WHERE balance = 0").fetchone() == (0,)


async def test_concurrent_writers_conflict_instead_of_losing_update(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    a, b = await begin(gk), await begin(gk)
    bal_a, ver_a = await read(gk, a, 2)
    bal_b, ver_b = await read(gk, b, 2)
    assert (await gk.execute_sql(a, f"UPDATE accounts SET balance = {bal_a - 100} WHERE id = 2", ver_a)).verdict == Verdict.OK
    task = asyncio.create_task(gk.execute_sql(b, f"UPDATE accounts SET balance = {bal_b - 50} WHERE id = 2", ver_b))
    await asyncio.sleep(0.2)  # b is now waiting on a's row lock
    assert (await gk.commit_session(a)).verdict == Verdict.COMMITTED
    assert (await task).verdict == Verdict.CONCURRENT_MODIFICATION_CONFLICT
    assert (await gk.commit_session(b)).verdict == Verdict.COMMIT_REFUSED
    assert admin.execute("SELECT balance FROM accounts WHERE id = 2").fetchone() == (900,)


async def test_invariant_violation_rolls_back_whole_transaction(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    assert (await gk.execute_sql(sid, "INSERT INTO orders (account_id, amount) VALUES (3, 1500)")).verdict == Verdict.OK
    _, ver = await read(gk, sid, 3)
    res = await gk.execute_sql(sid, "UPDATE accounts SET balance = balance - 1500 WHERE id = 3", ver)
    assert res.verdict == Verdict.INVARIANT_VIOLATION
    assert (await gk.execute_sql(sid, "SELECT 1")).verdict == Verdict.TRANSACTION_ABORTED
    assert (await gk.commit_session(sid)).verdict == Verdict.COMMIT_REFUSED
    assert admin.execute("SELECT count(*) FROM orders WHERE amount = 1500").fetchone() == (0,)
    assert admin.execute("SELECT balance FROM accounts WHERE id = 3").fetchone() == (1000,)
    assert (await gk.rollback_session(sid)).verdict == Verdict.ROLLED_BACK
    assert (await gk.execute_sql(sid, "SELECT 1")).verdict == Verdict.OK


async def test_change_limit_blocks_outsized_update(gk: Gatekeeper) -> None:
    sid = await begin(gk)
    _, ver = await read(gk, sid, 5)
    res = await gk.execute_sql(sid, "UPDATE accounts SET balance = balance + 1000000 WHERE id = 5", ver)
    assert res.verdict == Verdict.POLICY_BLOCKED and res.rule_id == "CHANGE_LIMIT_EXCEEDED"
    assert (await gk.execute_sql(sid, "UPDATE accounts SET balance = balance + 500 WHERE id = 5", ver)).verdict == Verdict.OK


async def test_failed_step_rolls_back_to_savepoint_and_blocks_commit(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    _, ver = await read(gk, sid, 4)
    assert (await gk.execute_sql(sid, "UPDATE accounts SET balance = balance - 100 WHERE id = 4", ver)).verdict == Verdict.OK
    bad = await gk.execute_sql(sid, "UPDATE accounts SET owner = NULL WHERE id = 5", 1)  # NOT NULL violation
    assert bad.verdict == Verdict.DB_ERROR
    assert (await read(gk, sid, 4))[0] == 900  # transaction still usable and sees the first step
    res = await gk.commit_session(sid)
    assert res.verdict == Verdict.COMMIT_REFUSED and res.rule_id == "PARTIAL_FAILURE"
    assert admin.execute("SELECT balance FROM accounts WHERE id = 4").fetchone() == (1000,)


async def test_unparseable_write_taints_commit(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    _, ver = await read(gk, sid, 6)
    assert (await gk.execute_sql(sid, "UPDATE accounts SET balance = 1 WHERE id = 6", ver)).verdict == Verdict.OK
    assert (await gk.execute_sql(sid, "UPDATE accounts SET balance = 2 WHER id = 7")).verdict == Verdict.POLICY_BLOCKED
    assert (await gk.commit_session(sid)).verdict == Verdict.COMMIT_REFUSED
    assert admin.execute("SELECT balance FROM accounts WHERE id = 6").fetchone() == (1000,)


async def test_breaker_halts_runaway_write_loop_and_rolls_back(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    verdicts = [(await gk.execute_sql(sid, "INSERT INTO orders (account_id, amount) VALUES (6, 5)")).verdict for _ in range(25)]
    assert verdicts[:20] == [Verdict.OK] * 20
    assert verdicts[20] == Verdict.SESSION_HALTED
    assert (await gk.commit_session(sid)).verdict == Verdict.SESSION_HALTED
    assert admin.execute("SELECT count(*) FROM orders WHERE account_id = 6 AND amount = 5").fetchone() == (0,)


async def test_breaker_compensates_committed_writes(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    before = admin.execute("SELECT count(*), sum(amount) FROM orders").fetchone()
    sid = await begin(gk)
    res = None
    for k in range(1, 25):  # a loop that commits every iteration
        rows = (await gk.execute_sql(sid, f"SELECT version FROM orders WHERE id = {k}")).rows
        res = await gk.execute_sql(sid, f"DELETE FROM orders WHERE id = {k}", rows[0]["version"] if rows else None)
        if res.verdict != Verdict.OK:
            break
        await gk.commit_session(sid)
    assert res is not None and res.verdict == Verdict.SESSION_HALTED and "compensation: reversed 20" in res.reason
    assert admin.execute("SELECT count(*), sum(amount) FROM orders").fetchone() == before


async def test_compensation_refuses_to_clobber_newer_changes(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    _, ver = await read(gk, sid, 8)
    await gk.execute_sql(sid, "UPDATE accounts SET balance = balance - 1 WHERE id = 8", ver)
    await gk.commit_session(sid)
    admin.execute("UPDATE accounts SET balance = 555, version = version + 1 WHERE id = 8")  # someone else, later
    res = None
    for _ in range(3):
        res = await gk.execute_sql(sid, "DELETE FROM orders")
    assert res is not None and res.verdict == Verdict.SESSION_HALTED and "nothing compensated" in res.reason
    assert admin.execute("SELECT balance FROM accounts WHERE id = 8").fetchone() == (555,)


async def test_breaker_halts_after_three_policy_violations(gk: Gatekeeper) -> None:
    sid = await begin(gk)
    v = [(await gk.execute_sql(sid, "DELETE FROM orders")).verdict for _ in range(4)]
    assert v == [Verdict.POLICY_BLOCKED, Verdict.POLICY_BLOCKED, Verdict.SESSION_HALTED, Verdict.SESSION_HALTED]


async def test_breaker_halts_repeated_identical_failures(gk: Gatekeeper) -> None:
    sid = await begin(gk)
    v = [(await gk.execute_sql(sid, f"SELECT balanse FROM accounts WHERE id = {i}")).verdict for i in range(5)]
    assert v == [Verdict.DB_ERROR] * 3 + [Verdict.SESSION_HALTED] * 2


async def test_read_only_session_is_read_only_in_postgres_too(gk: Gatekeeper) -> None:
    sid = await begin(gk, "analyst")
    assert (await gk.execute_sql(sid, "SELECT count(*) FROM accounts")).verdict == Verdict.OK
    row = await (await gk.sessions[sid].db.execute("SHOW transaction_read_only")).fetchone()
    assert row == ("on",)


async def test_update_from_and_delete_using_are_verified(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    res = await gk.execute_sql(
        sid, "UPDATE accounts a SET balance = a.balance + 1 FROM orders o WHERE o.account_id = a.id AND o.id = 5", 1
    )
    assert res.verdict == Verdict.OK and res.rowcount == 1, res
    acct = admin.execute("SELECT account_id FROM orders WHERE id = 5").fetchone()
    res = await gk.execute_sql(sid, "DELETE FROM orders o USING accounts a WHERE o.account_id = a.id AND o.id = 6", 1)
    assert res.verdict == Verdict.OK and res.rowcount == 1, res
    assert (await gk.commit_session(sid)).verdict == Verdict.COMMITTED
    assert acct is not None
    assert admin.execute("SELECT balance, version FROM accounts WHERE id = %s", (acct[0],)).fetchone() == (1001, 2)


async def test_versioned_delete_checks_version(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    rows = (await gk.execute_sql(sid, "SELECT version FROM orders WHERE id = 9")).rows
    assert rows
    ver = rows[0]["version"]
    assert (
        await gk.execute_sql(sid, "DELETE FROM orders WHERE id = 9", ver + 1)
    ).verdict == Verdict.CONCURRENT_MODIFICATION_CONFLICT
    await gk.rollback_session(sid)
    ok = await gk.execute_sql(sid, "DELETE FROM orders WHERE id = 9", ver)
    assert ok.verdict == Verdict.OK and ok.rowcount == 1
    assert (await gk.commit_session(sid)).verdict == Verdict.COMMITTED
    assert admin.execute("SELECT count(*) FROM orders WHERE id = 9").fetchone() == (0,)


async def test_insert_returning_hides_internal_keys(gk: Gatekeeper) -> None:
    sid = await begin(gk)
    plain = await gk.execute_sql(sid, "INSERT INTO orders (account_id, amount) VALUES (1, 3)")
    assert plain.verdict == Verdict.OK and plain.rows is None and plain.rowcount == 1
    ret = await gk.execute_sql(sid, "INSERT INTO orders (account_id, amount) VALUES (1, 4) RETURNING amount")
    assert ret.rows is not None and list(ret.rows[0]) == ["amount"]


async def test_trace_records_chain_hashes_and_verdicts(gk: Gatekeeper) -> None:
    sid = await begin(gk)
    _, ver = await read(gk, sid, 7)
    await gk.execute_sql(sid, "UPDATE accounts SET balance = balance + 1 WHERE id = 7", ver)
    await gk.execute_sql(sid, "DROP TABLE accounts")
    await gk.commit_session(sid)
    events = gk.get_trace(sid)
    assert events is not None
    assert [e["event"] for e in events] == ["begin_session", "execute_sql", "execute_sql", "execute_sql", "commit_session"]
    upd = events[2]
    assert upd["verdict"] == "OK" and upd["pre_state_hash"] != upd["post_state_hash"]
    assert events[3]["verdict"] == "POLICY_BLOCKED" and events[3]["rule_id"] == "DDL_BLOCKED"
    assert events[4]["verdict"] == "COMMIT_REFUSED"  # the blocked DROP counts as a failed mutating step
    assert all(e["prev_hash"] == events[i - 1]["entry_hash"] for i, e in enumerate(events) if i)
    assert verify_trace(gk.trace_path(sid)).ok
    assert json.dumps(events)
