"""Persona end-to-end tests against a live PostgreSQL."""

from __future__ import annotations

import asyncio
import statistics
import time
from pathlib import Path
from typing import Any

import psycopg
import pytest
from conftest import begin, mcp_client, read
from mcp import Client
from typer.testing import CliRunner

from mcp_gatekeeper import Gatekeeper, Settings, Verdict
from mcp_gatekeeper.cli import app


# ------------------------------------------------------------------ 1. developer
async def tool(client: Client, name: str, **args: Any) -> dict[str, Any]:
    res = await client.call_tool(name, args)
    assert not res.is_error and isinstance(res.structured_content, dict), res
    return res.structured_content


async def test_developer_occ_update_over_mcp(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, admin: psycopg.Connection[Any]
) -> None:
    async with mcp_client(settings, monkeypatch) as client:
        sid = (await tool(client, "begin_session"))["session_id"]
        row = (await tool(client, "execute_sql", session_id=sid, sql="SELECT balance, version FROM accounts WHERE id = 10"))[
            "rows"
        ][0]
        upd = await tool(
            client,
            "execute_sql",
            session_id=sid,
            sql="UPDATE accounts SET balance = balance - 25 WHERE id = 10",
            expected_version=row["version"],
        )
        assert upd["verdict"] == "OK" and upd["rowcount"] == 1
        assert (await tool(client, "commit_session", session_id=sid))["verdict"] == "COMMITTED"
        assert admin.execute("SELECT balance, version FROM accounts WHERE id = 10").fetchone() == (975, 2)
        missing = await tool(client, "execute_sql", session_id=sid, sql="UPDATE accounts SET balance = 0 WHERE id = 10")
        assert missing["verdict"] == "CONCURRENT_MODIFICATION_CONFLICT" and missing["rule_id"] == "MISSING_EXPECTED_VERSION"
        bad = await tool(client, "execute_sql", session_id=sid, sql="UPDATE accounts SET balance = WHERE id = 10")
        assert bad["verdict"] == "POLICY_BLOCKED" and bad["rule_id"] == "PARSE_ERROR" and bad["reason"]


# ------------------------------------------------------------------ 2. auditor
async def test_auditor_verify_trace_and_tamper_detection(gk: Gatekeeper, tmp_path: Path) -> None:
    sid = await begin(gk)
    _, ver = await read(gk, sid, 11)
    await gk.execute_sql(sid, "UPDATE accounts SET balance = balance + 5 WHERE id = 11", ver)
    await gk.commit_session(sid)
    await gk.close_session(sid)
    path = gk.trace_path(sid)
    runner = CliRunner()
    ok = runner.invoke(app, ["verify-trace", str(path)])
    assert ok.exit_code == 0, ok.output
    lines = path.read_text(encoding="utf-8").splitlines()
    target = 2  # 1-based line to tamper with
    i = lines[target - 1].index('"rowcount":1')
    lines[target - 1] = lines[target - 1][: i + len('"rowcount":')] + "2" + lines[target - 1][i + len('"rowcount":1') :]
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = runner.invoke(app, ["verify-trace", str(tampered)])
    assert bad.exit_code == 1
    assert f"line {target}" in bad.output


async def test_auditor_secrets_keys_and_emails_are_redacted(gk: Gatekeeper, caplog: pytest.LogCaptureFixture) -> None:
    sid = await begin(gk)
    probes = ["ceo@corp.example", "sk_live_ABCDEF123456", "CANARY_root_9b21"]
    for value in probes:
        res = await gk.execute_sql(sid, f"SELECT CAST('{value}' AS int)")
        assert res.verdict == Verdict.DB_ERROR
        assert value not in res.reason, res.reason  # the raw Postgres message would echo the value
    for _ in range(2):
        await gk.execute_sql(sid, "SELECT CAST('ceo@corp.example' AS int)")  # trips the breaker: logs a warning
    trace = gk.trace_path(sid).read_text(encoding="utf-8")
    for value in probes:
        assert value not in trace
        assert value not in caplog.text


# ------------------------------------------------------------------ 3. SRE
async def test_sre_p99_overhead_over_100_sequential_queries(gk: Gatekeeper) -> None:
    sid = await begin(gk)
    overhead = []
    for i in range(100):
        res = await gk.execute_sql(sid, f"SELECT balance, version FROM accounts WHERE id = {1 + i % 50}")
        assert res.verdict == Verdict.OK
        overhead.append(res.latency_ms - res.db_ms)
    p99 = statistics.quantiles(overhead, n=100)[98]
    print(f"\nproxy overhead over 100 reads: p50={statistics.median(overhead):.3f} ms p99={p99:.3f} ms")
    assert p99 < 15.0


async def test_sre_statement_timeout_kills_pg_sleep_without_hanging_pool(gk: Gatekeeper) -> None:
    sid = await begin(gk, "dba")  # only the admin role opts in to pg_sleep
    t0 = time.perf_counter()
    res = await gk.execute_sql(sid, "SELECT pg_sleep(10)")
    elapsed = time.perf_counter() - t0
    assert res.verdict == Verdict.DB_ERROR and res.rule_id == "57014", res  # query_canceled
    assert elapsed < 8
    assert (await gk.execute_sql(sid, "SELECT 1 AS one")).verdict == Verdict.OK  # same session recovered
    other = await begin(gk)
    assert (await gk.execute_sql(other, "SELECT 1 AS one")).verdict == Verdict.OK


async def test_sre_abandoned_session_rolls_back_and_connection_recovers(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sid = await begin(gk)
    _, ver = await read(gk, sid, 12)
    assert (await gk.execute_sql(sid, "UPDATE accounts SET balance = 1 WHERE id = 12", ver)).verdict == Verdict.OK
    # the agent disappears holding a row lock and an open transaction
    assert sid in await gk.reap_idle(0)
    assert admin.execute("SELECT balance FROM accounts WHERE id = 12").fetchone() == (1000,)
    nxt = await begin(gk)
    _, ver = await read(gk, nxt, 12)
    res = await asyncio.wait_for(gk.execute_sql(nxt, "UPDATE accounts SET balance = 2 WHERE id = 12", ver), timeout=3)
    assert res.verdict == Verdict.OK  # no leftover lock
    assert (await gk.commit_session(nxt)).verdict == Verdict.COMMITTED


# ------------------------------------------------------------------ 4. fleet
async def test_fleet_five_agents_one_winner_per_version(gk: Gatekeeper, admin: psycopg.Connection[Any]) -> None:
    sids = [await begin(gk) for _ in range(5)]
    reads = [await read(gk, s, 13) for s in sids]
    assert len({v for _, v in reads}) == 1

    async def agent(i: int, sid: str) -> tuple[int, str]:
        res = await gk.execute_sql(sid, f"UPDATE accounts SET balance = {100 + i} WHERE id = 13", reads[i][1])
        if res.verdict != Verdict.OK:
            return i, str(res.verdict)
        return i, str((await gk.commit_session(sid)).verdict)

    outcomes = await asyncio.gather(*(agent(i, s) for i, s in enumerate(sids)))
    winners = [i for i, v in outcomes if v == "COMMITTED"]
    losers = [v for i, v in outcomes if v != "COMMITTED"]
    assert len(winners) == 1, outcomes
    assert losers == ["CONCURRENT_MODIFICATION_CONFLICT"] * 4, outcomes
    assert admin.execute("SELECT balance, version FROM accounts WHERE id = 13").fetchone() == (100 + winners[0], 2)


# ------------------------------------------------------------------ 5. adversary
async def test_adversary_attacks_blocked_breaker_halts_prior_writes_rolled_back(
    gk: Gatekeeper, admin: psycopg.Connection[Any]
) -> None:
    before = admin.execute("SELECT count(*), sum(balance) FROM accounts").fetchone()
    sid = await begin(gk)
    _, ver = await read(gk, sid, 14)
    assert (await gk.execute_sql(sid, "UPDATE accounts SET balance = 0 WHERE id = 14", ver)).verdict == Verdict.OK
    attacks = [
        "SELECT id FROM accounts WHERE id = 1; DROP TABLE accounts",
        "/* routine cleanup */ DROP TABLE accounts",
        "DELETE FROM orders WHERE 1=1",
    ]
    verdicts = [(await gk.execute_sql(sid, sql)).verdict for sql in attacks]
    assert verdicts == [Verdict.POLICY_BLOCKED, Verdict.POLICY_BLOCKED, Verdict.SESSION_HALTED]
    assert (await gk.execute_sql(sid, "SELECT * FROM system_secrets")).verdict == Verdict.SESSION_HALTED
    assert admin.execute("SELECT count(*), sum(balance) FROM accounts").fetchone() == before  # prior write rolled back
    assert admin.execute("SELECT count(*) FROM orders").fetchone() == (200,)


async def test_adversary_exfiltration_and_read_only_escalation(gk: Gatekeeper) -> None:
    sid = await begin(gk, "analyst")
    for sql in (
        "SELECT value FROM system_secrets",
        "SELECT owner FROM accounts UNION SELECT value FROM system_secrets",
    ):
        res = await gk.execute_sql(sid, sql)
        assert res.verdict == Verdict.POLICY_BLOCKED and res.rule_id == "RESTRICTED_TABLE" and not res.rows
    other = await begin(gk, "analyst")
    for sql, rule in (
        ("UPDATE accounts SET balance = 1 WHERE id = 1", "ROLE_READ_ONLY"),
        ("SET TRANSACTION READ WRITE", "STATEMENT_NOT_ALLOWED"),
    ):
        res = await gk.execute_sql(other, sql, 1)
        assert res.verdict == Verdict.POLICY_BLOCKED and res.rule_id == rule, (sql, res)


async def test_adversary_retry_loop_dos_is_halted(gk: Gatekeeper) -> None:
    sid = await begin(gk)
    verdicts = [(await gk.execute_sql(sid, f"SELECT balanse FROM accounts WHERE id = {i}")).verdict for i in range(50)]
    assert verdicts.index(Verdict.SESSION_HALTED) == 3
    assert set(verdicts[3:]) == {Verdict.SESSION_HALTED}
