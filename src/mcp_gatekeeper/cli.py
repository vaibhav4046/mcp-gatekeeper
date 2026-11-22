"""Command line: init, serve, verify-trace, benchmark, doctor."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import psycopg
import typer
from pydantic import ValidationError
from rich.console import Console

from .audit import verify_trace
from .config import DEFAULT_DATABASE_URL, DEFAULT_POLICY_YAML, Settings

app = typer.Typer(help="Deterministic MCP safety proxy for PostgreSQL.", no_args_is_help=True, add_completion=False)
err = Console(stderr=True)

ENV_EXAMPLE = f"""\
# Copy to .env (or export) before `mcp-gatekeeper serve`.
DATABASE_URL={DEFAULT_DATABASE_URL}
GATEKEEPER_POLICY=policies.yaml
# Identity this server acts as; its role comes from policies.yaml.
GATEKEEPER_AGENT=default
GATEKEEPER_TRACE_DIR=traces
# Optional: HMAC-SHA256 key for traces. Keep it out of version control.
GATEKEEPER_AUDIT_KEY=
"""


class Transport(StrEnum):
    stdio = "stdio"
    http = "streamable-http"


@app.command()
def init(
    directory: Annotated[Path, typer.Argument(help="Where to write the files.")] = Path("."),
    force: Annotated[bool, typer.Option(help="Overwrite existing files.")] = False,
) -> None:
    """Write policies.yaml and .env.example."""
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in (("policies.yaml", DEFAULT_POLICY_YAML), (".env.example", ENV_EXAMPLE)):
        path = directory / name
        if path.exists() and not force:
            err.print(f"[yellow]skip[/] {path} exists (use --force to overwrite)")
            continue
        path.write_text(content, encoding="utf-8")
        err.print(f"[green]wrote[/] {path}")


@app.command()
def serve(
    transport: Annotated[Transport, typer.Option(help="MCP transport.")] = Transport.stdio,
    host: str = "127.0.0.1",
    port: int = 8000,
    policy: Annotated[Path | None, typer.Option(help="policies.yaml (or GATEKEEPER_POLICY).")] = None,
    agent: Annotated[str | None, typer.Option(help="Agent identity for this server (or GATEKEEPER_AGENT).")] = None,
) -> None:
    """Run the MCP server. Logs go to stderr; stdout is reserved for the protocol."""
    if policy is not None:
        os.environ["GATEKEEPER_POLICY"] = str(policy)
    if agent is not None:
        os.environ["GATEKEEPER_AGENT"] = agent
    try:
        Settings.from_env()  # fail fast on a bad policy file before the transport starts
    except (ValidationError, OSError, ValueError) as e:
        err.print(f"[red]invalid configuration:[/] {e}")
        raise typer.Exit(2) from e
    from .server import serve as run_server

    run_server(transport.value, host, port)


@app.command("verify-trace")
def verify_trace_cmd(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="A traces/<session>.jsonl file.")],
    key_env: Annotated[str, typer.Option(help="Env var holding the HMAC key, if traces are signed.")] = "GATEKEEPER_AUDIT_KEY",
) -> None:
    """Check a trace's hash chain (and HMAC). Exits 1 and names the first bad line on tampering."""
    key = os.environ.get(key_env) or None
    report = verify_trace(file, key)
    if report.ok:
        err.print(f"[green]OK[/] {file}: {report.entries} entries, chain intact{', HMAC verified' if key else ''}")
        return
    err.print(f"[red]TAMPERED[/] {file}: {report.reason}")
    raise typer.Exit(1)


@app.command()
def benchmark(args: Annotated[list[str] | None, typer.Argument(help="Extra args for run_benchmark.py")] = None) -> None:
    """Run benchmarks/run_benchmark.py from a source checkout."""
    script = Path("benchmarks/run_benchmark.py")
    if not script.exists():
        err.print("[red]benchmarks/run_benchmark.py not found; run this from a clone of the repository[/]")
        raise typer.Exit(2)
    raise typer.Exit(subprocess.call([sys.executable, str(script), *(args or [])]))  # noqa: S603 (fixed script, own interpreter)


async def _doctor(settings: Settings) -> list[tuple[str, bool, str]]:
    checks: list[tuple[str, bool, str]] = []
    try:
        conn = await psycopg.AsyncConnection.connect(settings.database_url, connect_timeout=5)
    except psycopg.Error as e:
        return [("database connection", False, str(e).splitlines()[0])]
    async with conn:
        row = await (
            await conn.execute("SELECT current_user, version(), rolsuper FROM pg_roles WHERE rolname = current_user")
        ).fetchone()
        assert row is not None
        user, version, is_super = row
        checks.append(("database connection", True, f"{user} @ {version.split(',')[0]}"))
        checks.append(("role is not superuser", not is_super, "superuser can bypass every grant" if is_super else "ok"))
        for table in sorted(settings.policy.restricted_tables):
            exists = (await (await conn.execute("SELECT to_regclass(%s) IS NOT NULL", (table,))).fetchone() or [False])[0]
            if not exists:
                checks.append((f"no direct access to {table}", True, "table absent"))
                continue
            can = (
                await (await conn.execute("SELECT has_table_privilege(current_user, %s, 'SELECT')", (table,))).fetchone()
                or [True]
            )[0]
            checks.append(
                (f"no direct access to {table}", not can, "role can SELECT it (defence in depth lost)" if can else "ok")
            )
        allowlisted = sorted({t for role in settings.policy.roles.values() for t in (role.tables or {})})
        for table in allowlisted:
            exists = (await (await conn.execute("SELECT to_regclass(%s) IS NOT NULL", (table,))).fetchone() or [False])[0]
            checks.append((f"allowlisted table {table} exists", bool(exists), "ok" if exists else "missing"))
    return checks


@app.command()
def doctor(policy: Annotated[Path | None, typer.Option(help="policies.yaml to validate.")] = None) -> None:
    """Check DB connectivity, policy validity and database role permissions."""
    if policy is not None:
        os.environ["GATEKEEPER_POLICY"] = str(policy)
    try:
        settings = Settings.from_env()
        err.print(f"[green]PASS[/] policy valid ({len(settings.policy.roles)} roles, {len(settings.policy.agents)} agents)")
    except (ValidationError, OSError, ValueError) as e:
        err.print(f"[red]FAIL[/] policy invalid: {e}")
        raise typer.Exit(1) from e
    results = asyncio.run(_doctor(settings))
    failed = False
    for name, ok, detail in results:
        hard = name == "database connection" or name.startswith("allowlisted")
        label = "[green]PASS[/]" if ok else ("[red]FAIL[/]" if hard else "[yellow]WARN[/]")
        failed |= hard and not ok
        err.print(f"{label} {name}: {detail}")
    raise typer.Exit(1 if failed else 0)


def main() -> Any:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined,unused-ignore]
    return app()
