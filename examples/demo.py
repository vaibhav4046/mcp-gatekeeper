"""Terminal demo: an "agent" talks to the gatekeeper over MCP (in-memory transport).

uv run python examples/demo.py            # prints the demo
uv run python examples/demo.py --svg docs/demo.svg   # also saves a terminal screenshot
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Any

import psycopg
from mcp.client import Client
from rich.console import Console

from mcp_gatekeeper import Settings, server

ROOT = Path(__file__).resolve().parents[1]
console = Console(record=True, width=100)
COLORS = {"OK": "green", "COMMITTED": "green", "ROLLED_BACK": "yellow"}


async def main(svg: str | None) -> None:
    settings = Settings.from_env()
    with psycopg.connect(settings.database_url, autocommit=True) as db:
        db.execute((ROOT / "benchmarks" / "schema.sql").read_text(encoding="utf-8"))

    async with Client(server.mcp) as c:

        async def call(tool: str, **args: Any) -> dict[str, Any]:
            res = (await c.call_tool(tool, args)).structured_content or {}
            verdict = res.get("verdict", "")
            shown = args.get("sql", tool)
            ev = f"  [dim](expected_version={args['expected_version']})[/]" if args.get("expected_version") else ""
            console.print(f"[bold cyan]agent>[/] {shown}{ev}")
            rule = res.get("rule_id", "") if res.get("rule_id") != verdict else ""
            detail = f" [dim]{rule} {res.get('reason', '')}[/]" if verdict not in ("OK", "COMMITTED") else ""
            console.print(f"   [{COLORS.get(verdict, 'red')}]{verdict}[/]{detail}")
            return res

        console.rule("[bold]1. destructive and injected SQL is blocked before it runs")
        s = (await call("begin_session"))["session_id"]
        await call("execute_sql", session_id=s, sql="DELETE FROM orders WHERE status = 'pending' OR 1 = 1")
        await call("execute_sql", session_id=s, sql="SELECT owner FROM accounts UNION SELECT value FROM system_secrets")
        await call("rollback_session", session_id=s)

        console.rule("[bold]2. a stale write gets a conflict instead of a lost update")
        a = (await call("begin_session"))["session_id"]
        b = (await call("begin_session"))["session_id"]
        row = (await call("execute_sql", session_id=a, sql="SELECT balance, version FROM accounts WHERE id = 1"))["rows"][0]
        await call("execute_sql", session_id=b, sql="SELECT balance, version FROM accounts WHERE id = 1")
        await call(
            "execute_sql", session_id=a, sql="UPDATE accounts SET balance = 900 WHERE id = 1", expected_version=row["version"]
        )
        await call("commit_session", session_id=a)
        await call(
            "execute_sql", session_id=b, sql="UPDATE accounts SET balance = 950 WHERE id = 1", expected_version=row["version"]
        )

        console.rule("[bold]3. a failed step means the whole unit rolls back")
        p = (await call("begin_session"))["session_id"]
        r = (await call("execute_sql", session_id=p, sql="SELECT version FROM accounts WHERE id = 2"))["rows"][0]
        await call(
            "execute_sql",
            session_id=p,
            sql="UPDATE accounts SET balance = balance - 100 WHERE id = 2",
            expected_version=r["version"],
        )
        await call(
            "execute_sql", session_id=p, sql="UPDATE accounts SET balanse = balanse + 100 WHERE id = 3", expected_version=1
        )
        await call("commit_session", session_id=p)

        console.rule("[bold]4. a runaway loop trips the circuit breaker")
        q = (await c.call_tool("begin_session", {})).structured_content["session_id"]
        for i in range(21):
            res = (
                await c.call_tool(
                    "execute_sql", {"session_id": q, "sql": "INSERT INTO orders (account_id, amount) VALUES (4, 5)"}
                )
            ).structured_content
            if res["verdict"] != "OK":
                console.print(
                    f"[bold cyan]agent>[/] INSERT INTO orders (account_id, amount) VALUES (4, 5)   [dim]# attempt {i + 1}[/]"
                )
                console.print(f"   [red]{res['verdict']}[/] [dim]{res['reason']}[/]")
        trace = (await c.call_tool("get_session_trace", {"session_id": q})).structured_content["events"]
        last = trace[-1]
        console.print(
            f"[dim]trace: {len(trace)} events; last = {{verdict: {last['verdict']}, latency_ms: {last['latency_ms']}}}[/]"
        )

    with psycopg.connect(settings.database_url) as db:
        bal = db.execute("SELECT balance FROM accounts WHERE id IN (1, 2) ORDER BY id").fetchall()
        n = (db.execute("SELECT count(*) FROM orders WHERE account_id = 4 AND amount = 5").fetchone() or [0])[0]
    console.rule("[bold]database afterwards")
    console.print(
        f"account 1 = {bal[0][0]} (one committed write), account 2 = {bal[1][0]} (unchanged), runaway inserts kept = {n}"
    )
    if svg:
        console.save_svg(svg, title="mcp-gatekeeper demo")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--svg")
    asyncio.run(main(ap.parse_args().svg))
