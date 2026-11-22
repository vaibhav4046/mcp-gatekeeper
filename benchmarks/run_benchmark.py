"""Run all 50 scenarios unprotected vs protected, then measure proxy overhead.

    uv run python benchmarks/run_benchmark.py

Writes benchmarks/results.json and benchmarks/results.md. Every number in the README comes
from these files.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import random
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg_pool import AsyncConnectionPool
from rich.console import Console
from rich.table import Table

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scenarios import CATEGORIES, OK_VERDICTS, SCENARIOS, Ctx, Executor, Protected, Recorder, Unprotected, read_state, scalar

from mcp_gatekeeper import Gatekeeper, Settings

HERE = Path(__file__).resolve().parent
# --check fails CI if any scenario crashes or any protected scenario not listed here corrupts data.
KNOWN_PROTECTED_MISSES: set[str] = set()  # none: any protected corruption fails CI
SCHEMA_SQL = (HERE / "schema.sql").read_text(encoding="utf-8")
console = Console(stderr=True)


def pct(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    k = (len(ordered) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo), 3)


def summary(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "p50": pct(values, 50),
        "p95": pct(values, 95),
        "p99": pct(values, 99),
        "mean": round(statistics.fmean(values), 3),
    }


async def reset(db: psycopg.AsyncConnection) -> None:
    await db.execute(SCHEMA_SQL)


async def run_scenarios(executor: Executor, db: psycopg.AsyncConnection, seed: int) -> list[dict[str, Any]]:
    out = []
    for sc in SCENARIOS:
        await reset(db)
        ctx = Ctx(db=db, before=await read_state(db), rng=random.Random(f"{seed}:{sc.id}"))
        rec = Recorder(executor)
        t0 = time.perf_counter()
        error = None
        try:
            reasons = await asyncio.wait_for(sc.fn(rec, ctx), timeout=120)
        except Exception as e:  # a crashed scenario is reported, never silently dropped
            reasons, error = [f"scenario crashed: {type(e).__name__}: {e}"], repr(e)
        await rec.close_all()
        leaked = rec.leaked or (sc.leak_if_rows and rec.rows_returned)
        if leaked:
            reasons = [*reasons, "restricted data returned to the agent"]
        refused = sorted({v for v in rec.verdicts if v not in OK_VERDICTS})
        expected_hit = not refused if "NO_FALSE_POSITIVE" in sc.expect else bool(sc.expect & set(rec.verdicts))
        out.append(
            {
                "id": sc.id,
                "category": sc.category,
                "title": sc.title,
                "corrupted": bool(reasons),
                "reasons": reasons,
                "leaked": leaked,
                "verdicts": rec.verdicts,
                "rules": sorted(set(rec.rules)),
                "refusals": refused,
                "expected": sorted(sc.expect),
                "expected_hit": expected_hit,
                "notes": ctx.notes,
                "seconds": round(time.perf_counter() - t0, 3),
                "error": error,
            }
        )
        mark = "[red]CORRUPTED[/]" if reasons else "[green]clean[/]"
        console.print(f"  {executor.name:11} {sc.id} {mark} {sc.title}")
    return out


async def measure_overhead(settings: Settings, db: psycopg.AsyncConnection, iterations: int) -> dict[str, Any]:
    """Benign workload (read, versioned update, insert, commit) through the gatekeeper vs direct."""
    await reset(db)
    raw_lat: list[float] = []
    async with await psycopg.AsyncConnection.connect(settings.database_url) as conn:
        for i in range(iterations):
            acct = 1 + i % 50
            for sql in (
                f"SELECT balance, version FROM accounts WHERE id = {acct}",
                f"UPDATE accounts SET balance = balance + 1, version = version + 1 WHERE id = {acct}",
                f"INSERT INTO orders (account_id, amount) VALUES ({acct}, 5)",
            ):
                t = time.perf_counter()
                await conn.execute(sql)
                raw_lat.append((time.perf_counter() - t) * 1000)
            await conn.commit()

    results: dict[str, Any] = {"direct": summary(raw_lat)}
    for label, hash_state in (("gatekeeper", True), ("gatekeeper_no_state_hash", False)):
        await reset(db)
        gk = await Gatekeeper.create(settings.model_copy(update={"hash_state": hash_state}))
        total: list[float] = []
        overhead: list[float] = []
        refused = 0
        sid = (await gk.begin_session()).session_id
        for i in range(iterations):
            acct = 1 + i % 50
            r1 = await gk.execute_sql(sid, f"SELECT balance, version FROM accounts WHERE id = {acct}")
            ver = r1.rows[0]["version"] if r1.rows else None
            r2 = await gk.execute_sql(sid, f"UPDATE accounts SET balance = balance + 1 WHERE id = {acct}", ver)
            r3 = await gk.execute_sql(sid, f"INSERT INTO orders (account_id, amount) VALUES ({acct}, 5)")
            for r in (r1, r2, r3):
                refused += r.verdict != "OK"
                total.append(r.latency_ms)
                overhead.append(r.latency_ms - r.db_ms)
            await gk.commit_session(sid)
            if (i + 1) % 10 == 0:  # 2 writes/iteration: stay under the 20-write session cap
                await gk.close_session(sid)
                sid = (await gk.begin_session()).session_id
        await gk.aclose()
        results[label] = {"total": summary(total), "overhead": summary(overhead), "benign_calls_refused": refused}
    return results


async def measure_mcp_roundtrip(settings: Settings, db: psycopg.AsyncConnection, calls: int) -> dict[str, Any]:
    from mcp.client import Client

    from mcp_gatekeeper import server

    await reset(db)
    os.environ["DATABASE_URL"] = settings.database_url
    os.environ["GATEKEEPER_TRACE_DIR"] = settings.trace_dir
    lat: list[float] = []
    async with Client(server.mcp) as client:
        sid = (await client.call_tool("begin_session", {})).structured_content["session_id"]
        for i in range(calls):
            t = time.perf_counter()
            res = await client.call_tool(
                "execute_sql", {"session_id": sid, "sql": f"SELECT balance FROM accounts WHERE id = {1 + i % 50}"}
            )
            lat.append((time.perf_counter() - t) * 1000)
            assert res.structured_content["verdict"] == "OK"
    return summary(lat)


def aggregate(unprot: list[dict[str, Any]], prot: list[dict[str, Any]]) -> dict[str, Any]:
    cats = {}
    for key, label in CATEGORIES.items():
        u = [r for r in unprot if r["category"] == key]
        p = [r for r in prot if r["category"] == key]
        cats[key] = {
            "label": label,
            "n": len(p),
            "corrupted_unprotected": sum(r["corrupted"] for r in u),
            "corrupted_protected": sum(r["corrupted"] for r in p),
            "expected_verdict_hits": sum(r["expected_hit"] for r in p),
        }
    total = {
        "n": len(prot),
        "corrupted_unprotected": sum(r["corrupted"] for r in unprot),
        "corrupted_protected": sum(r["corrupted"] for r in prot),
        "expected_verdict_hits": sum(r["expected_hit"] for r in prot),
    }
    return {"categories": cats, "total": total}


def rate(a: int, n: int) -> str:
    return f"{a}/{n} ({100 * a / n:.0f}%)"


def markdown(agg: dict[str, Any], overhead: dict[str, Any], mcp_rt: dict[str, Any], prot: list[dict[str, Any]]) -> str:
    lines = [
        "| Category | Corrupted, unprotected | Corrupted, protected | Expected block/rollback verdict |",
        "|---|---|---|---|",
    ]
    for c in agg["categories"].values():
        lines.append(
            f"| {c['label']} | {rate(c['corrupted_unprotected'], c['n'])} | {rate(c['corrupted_protected'], c['n'])} | {rate(c['expected_verdict_hits'], c['n'])} |"
        )
    t = agg["total"]
    lines.append(
        f"| **All 50** | **{rate(t['corrupted_unprotected'], t['n'])}** | **{rate(t['corrupted_protected'], t['n'])}** | **{rate(t['expected_verdict_hits'], t['n'])}** |"
    )
    g, gn, d = overhead["gatekeeper"], overhead["gatekeeper_no_state_hash"], overhead["direct"]
    lines += [
        "",
        f"Latency per call, ms ({g['total']['n']} calls of a benign read / versioned update / insert workload):",
        "",
        "| Path | p50 | p95 | p99 |",
        "|---|---|---|---|",
        f"| Direct psycopg (no proxy) | {d['p50']} | {d['p95']} | {d['p99']} |",
        f"| Gatekeeper, total | {g['total']['p50']} | {g['total']['p95']} | {g['total']['p99']} |",
        f"| Gatekeeper overhead (total minus the agent's own statement) | {g['overhead']['p50']} | {g['overhead']['p95']} | {g['overhead']['p99']} |",
        f"| Gatekeeper overhead, state hashing off | {gn['overhead']['p50']} | {gn['overhead']['p95']} | {gn['overhead']['p99']} |",
        f"| MCP tool call round trip, in-memory transport ({mcp_rt['n']} SELECTs) | {mcp_rt['p50']} | {mcp_rt['p95']} | {mcp_rt['p99']} |",
        "",
        f"Benign workload calls refused by the gatekeeper: {g['benign_calls_refused']} of {g['total']['n']}.",
    ]
    corrupted = [r for r in prot if r["corrupted"]]
    missed = [r for r in prot if not r["expected_hit"]]
    if corrupted or missed:
        lines += ["", "Protected-mode misses:", ""]
        for r in prot:
            if r["corrupted"] or not r["expected_hit"]:
                lines.append(
                    f"- {r['id']} {r['title']}: verdicts {r['refusals'] or ['OK only']}; {'; '.join(r['reasons']) or 'state clean'}; notes {r['notes']}"
                )
    return "\n".join(lines) + "\n"


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=20261122)
    ap.add_argument("--overhead-iterations", type=int, default=500)
    ap.add_argument("--mcp-calls", type=int, default=300)
    ap.add_argument("--check", action="store_true", help="exit 1 on crashes or unexpected protected corruption")
    args = ap.parse_args()

    settings = Settings.from_env(trace_dir=str(HERE.parent / "traces" / "benchmark"))
    db = await psycopg.AsyncConnection.connect(settings.database_url, autocommit=True)
    server_version = await scalar(db, "SHOW server_version")

    console.rule("unprotected")
    raw_pool = AsyncConnectionPool(
        settings.database_url,
        min_size=2,
        max_size=30,
        kwargs={"autocommit": True, "options": "-c statement_timeout=5000"},
        open=False,
    )
    await raw_pool.open(wait=True)
    unprot = await run_scenarios(Unprotected(raw_pool), db, args.seed)
    await raw_pool.close()

    console.rule("protected")
    await reset(db)
    gk = await Gatekeeper.create(settings)
    prot = await run_scenarios(Protected(gk), db, args.seed)
    await gk.aclose()

    console.rule("overhead")
    overhead = await measure_overhead(settings, db, args.overhead_iterations)
    mcp_rt = await measure_mcp_roundtrip(settings, db, args.mcp_calls)
    await reset(db)
    await db.close()

    agg = aggregate(unprot, prot)
    md = markdown(agg, overhead, mcp_rt, prot)
    env = {
        "timestamp_utc": datetime.now(UTC).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "postgres": server_version,
        "seed": args.seed,
        "ci": bool(os.environ.get("CI")),
    }
    payload = {
        "environment": env,
        "summary": agg,
        "overhead_ms": overhead,
        "mcp_roundtrip_ms": mcp_rt,
        "unprotected": unprot,
        "protected": prot,
    }
    (HERE / "results.json").write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    (HERE / "results.md").write_text(
        f"<!-- generated by benchmarks/run_benchmark.py at {env['timestamp_utc']} -->\n" + md, encoding="utf-8"
    )

    table = Table(title="mcp-gatekeeper benchmark (50 scenarios)")
    for col in ("Category", "Unprotected corrupted", "Protected corrupted", "Expected verdict"):
        table.add_column(col)
    for c in agg["categories"].values():
        table.add_row(
            c["label"],
            rate(c["corrupted_unprotected"], c["n"]),
            rate(c["corrupted_protected"], c["n"]),
            rate(c["expected_verdict_hits"], c["n"]),
        )
    t = agg["total"]
    table.add_row(
        "All",
        rate(t["corrupted_unprotected"], t["n"]),
        rate(t["corrupted_protected"], t["n"]),
        rate(t["expected_verdict_hits"], t["n"]),
        style="bold",
    )
    Console().print(table)
    print(md)
    if args.check:
        crashed = [r["id"] for r in unprot + prot if r["error"]]
        unexpected = [r["id"] for r in prot if r["corrupted"] and r["id"] not in KNOWN_PROTECTED_MISSES]
        if crashed or unexpected:
            console.print(f"[red]check failed: crashed={crashed} unexpected_protected_corruption={unexpected}[/]")
            sys.exit(1)
        console.print("[green]check passed[/]")


if __name__ == "__main__":
    asyncio.run(main())
