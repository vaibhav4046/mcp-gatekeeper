from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import psycopg
import pytest

from mcp_gatekeeper import Gatekeeper, Settings, Verdict

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SQL = (ROOT / "benchmarks" / "schema.sql").read_text(encoding="utf-8")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://gatekeeper:gatekeeper@localhost:5432/gatekeeper")


def reset_schema() -> None:
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        conn.execute(SCHEMA_SQL)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(database_url=DATABASE_URL, trace_dir=str(tmp_path / "traces"), pool_max=20)


@pytest.fixture
async def gk(settings: Settings) -> AsyncIterator[Gatekeeper]:
    reset_schema()
    gatekeeper = await Gatekeeper.create(settings)
    try:
        yield gatekeeper
    finally:
        await gatekeeper.aclose()


@pytest.fixture
def admin() -> Iterator[psycopg.Connection[Any]]:
    """Plain autocommit connection for setup and assertions, outside the gatekeeper."""
    with psycopg.connect(DATABASE_URL, autocommit=True) as conn:
        yield conn


async def begin(gk: Gatekeeper, agent: str | None = None) -> str:
    res = await gk.begin_session(agent)
    assert res.verdict == Verdict.OK, res
    return res.session_id


async def read(gk: Gatekeeper, sid: str, account_id: int) -> tuple[Any, int]:
    res = await gk.execute_sql(sid, f"SELECT balance, version FROM accounts WHERE id = {account_id}")
    assert res.verdict == Verdict.OK and res.rows, res
    row = res.rows[0]
    return row["balance"], int(row["version"])


@asynccontextmanager
async def mcp_client(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Any]:
    """In-memory MCP client for the real server. Used inside the test body: anyio cancel scopes
    must be entered and exited in the same task, which a pytest fixture does not guarantee."""
    from mcp import Client

    from mcp_gatekeeper import server

    reset_schema()
    monkeypatch.setenv("DATABASE_URL", settings.database_url)
    monkeypatch.setenv("GATEKEEPER_TRACE_DIR", settings.trace_dir)
    monkeypatch.delenv("GATEKEEPER_AGENT", raising=False)
    async with Client(server.mcp) as c:
        yield c
