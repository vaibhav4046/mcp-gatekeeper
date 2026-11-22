"""MCP protocol tests: the real server object over the SDK's in-memory transport."""

from __future__ import annotations

import json
from typing import Any

import pytest
from conftest import mcp_client
from mcp import Client

from mcp_gatekeeper import Settings
from mcp_gatekeeper.audit import verify_trace

TOOLS = {"begin_session", "execute_sql", "commit_session", "rollback_session", "get_session_trace"}


async def call(client: Client, name: str, **args: Any) -> dict[str, Any]:
    res = await client.call_tool(name, args)
    assert not res.is_error, res
    data = res.structured_content
    if data is None:
        block = res.content[0]
        data = json.loads(getattr(block, "text", "{}"))
    assert isinstance(data, dict)
    return data


async def test_tool_list_and_schemas(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    async with mcp_client(settings, monkeypatch) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert set(tools) == TOOLS
        schema = tools["execute_sql"].input_schema
        assert set(schema["required"]) == {"session_id", "sql"}
        assert "expected_version" in schema["properties"]
        assert tools["begin_session"].input_schema.get("properties", {}) == {}  # identity is not caller-controlled


async def test_structured_errors(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    async with mcp_client(settings, monkeypatch) as client:
        sid = (await call(client, "begin_session"))["session_id"]
        missing = await call(client, "execute_sql", session_id=sid, sql="UPDATE accounts SET balance = 1 WHERE id = 1")
        assert missing["verdict"] == "CONCURRENT_MODIFICATION_CONFLICT"
        assert missing["rule_id"] == "MISSING_EXPECTED_VERSION" and "expected_version" in missing["reason"]
        invalid = await call(client, "execute_sql", session_id=sid, sql="SELEC balance FROM accounts")
        assert invalid["verdict"] == "POLICY_BLOCKED" and invalid["rule_id"] == "PARSE_ERROR"
        unknown = await call(client, "execute_sql", session_id="nope", sql="SELECT 1")
        assert unknown["verdict"] == "UNKNOWN_SESSION"
        assert (await call(client, "get_session_trace", session_id="../../etc/passwd"))["verdict"] == "UNKNOWN_SESSION"


async def test_trace_tool_returns_a_verifiable_chain(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    async with mcp_client(settings, monkeypatch) as client:
        sid = (await call(client, "begin_session"))["session_id"]
        await call(client, "execute_sql", session_id=sid, sql="SELECT count(*) AS n FROM orders")
        await call(client, "commit_session", session_id=sid)
        events = (await call(client, "get_session_trace", session_id=sid))["events"]
        assert [e["event"] for e in events] == ["begin_session", "execute_sql", "commit_session"]
        assert verify_trace(f"{settings.trace_dir}/{sid}.jsonl").ok
