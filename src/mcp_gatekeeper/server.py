"""MCP server exposing the gatekeeper. Logs go to stderr only (stdout carries the protocol)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp.server import MCPServer

from .config import Settings
from .proxy import Gatekeeper, Result

log = logging.getLogger("mcp_gatekeeper.server")

_gatekeeper: Gatekeeper | None = None

INSTRUCTIONS = """\
Safety proxy in front of PostgreSQL. Workflow: begin_session -> execute_sql (one statement per
call) -> commit_session or rollback_session. To UPDATE/DELETE a versioned row, first SELECT its
`version` column and pass it as expected_version. If you get CONCURRENT_MODIFICATION_CONFLICT,
call rollback_session, re-read, and retry. A session whose mutating step failed cannot commit.
"""


def configure_logging() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


async def _reaper(gk: Gatekeeper) -> None:
    while True:
        await asyncio.sleep(30)
        closed = await gk.reap_idle()
        if closed:
            log.info("closed %d idle session(s)", len(closed))


@asynccontextmanager
async def lifespan(_server: MCPServer[Any]) -> AsyncIterator[dict[str, Any]]:
    global _gatekeeper
    _gatekeeper = await Gatekeeper.create(Settings.from_env())
    reaper = asyncio.create_task(_reaper(_gatekeeper))
    log.info("gatekeeper ready (agent=%s)", _gatekeeper.s.agent or _gatekeeper.p.default_agent)
    try:
        yield {}
    finally:
        reaper.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await reaper
        await _gatekeeper.aclose()
        _gatekeeper = None


mcp: MCPServer[Any] = MCPServer("mcp-gatekeeper", instructions=INSTRUCTIONS, lifespan=lifespan)


def _gk() -> Gatekeeper:
    if _gatekeeper is None:
        raise RuntimeError("gatekeeper not initialised")
    return _gatekeeper


def _out(res: Result) -> dict[str, Any]:
    # default=str turns Decimal/datetime into strings so the result is plain JSON.
    data: dict[str, Any] = json.loads(json.dumps(res.model_dump(exclude_none=True), default=str))
    return data


@mcp.tool()
async def begin_session() -> dict[str, Any]:
    """Open a gatekeeper session (one database transaction at a time). Returns session_id and role.

    The agent identity and role are fixed by whoever started this server, not by the caller."""
    return _out(await _gk().begin_session())


@mcp.tool()
async def execute_sql(session_id: str, sql: str, expected_version: int | None = None) -> dict[str, Any]:
    """Run one SQL statement inside the session. UPDATE/DELETE on versioned tables need expected_version."""
    return _out(await _gk().execute_sql(session_id, sql, expected_version))


@mcp.tool()
async def commit_session(session_id: str) -> dict[str, Any]:
    """Commit the session transaction. Refused if any mutating step failed."""
    return _out(await _gk().commit_session(session_id))


@mcp.tool()
async def rollback_session(session_id: str) -> dict[str, Any]:
    """Roll back the session transaction and clear an ABORTED state."""
    return _out(await _gk().rollback_session(session_id))


@mcp.tool()
async def get_session_trace(session_id: str) -> dict[str, Any]:
    """Return the hash-chained JSONL replay trace of a session as a list of events."""
    events = _gk().get_trace(session_id)
    if events is None:
        return {"verdict": "UNKNOWN_SESSION", "session_id": session_id}
    return {"session_id": session_id, "events": events}


def serve(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8000) -> None:
    configure_logging()
    if sys.platform == "win32":
        # psycopg's async driver needs a selector event loop on Windows.
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # type: ignore[attr-defined,unused-ignore]
    if transport == "stdio":
        mcp.run("stdio")
    else:
        mcp.run("streamable-http", host=host, port=port)
