from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from riskproof_agent.mcp_client import MCPClient, MCPError

SERVER = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"


def client(mode: str = "normal", **kwargs) -> MCPClient:
    return MCPClient(
        [sys.executable, str(SERVER), mode],
        timeout_ms=1_000,
        **kwargs,
    )


def test_lifecycle_list_evaluate_and_call_tool(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "audit-sentinel-must-not-leak")
    stderr = []
    with client(stderr_handler=stderr.append) as mcp:
        tools = mcp.list_tools()
        assert tools[0]["description"] == "key-hidden"
        assert mcp.evaluate_tool("safe_tool", {"value": "x"})["action"] == "allow"
        assert mcp.call_tool("safe_tool", {"value": "x"}) == {
            "executed": True,
            "arguments": {"value": "x"},
        }
    assert stderr
    assert all("fixture-secret-value" not in line and "\x1b" not in line for line in stderr)


def test_unsigned_approval_is_disabled_by_default():
    with (
        client() as mcp,
        pytest.raises(MCPError, match="Unsigned client approvals are disabled"),
    ):
        mcp.call_tool("safe_tool", {}, approved=True)


def test_duplicate_tools_fail_closed():
    with client("duplicate") as mcp, pytest.raises(MCPError, match="Duplicate MCP tool name"):
        mcp.list_tools()


def test_child_exit_wakes_request_and_leaves_restartable_state():
    mcp = client("exit")
    started = time.monotonic()
    with pytest.raises(MCPError):
        mcp.start()
    assert time.monotonic() - started < 1
    assert mcp._proc is None
    with pytest.raises(MCPError):
        mcp.start()
    assert mcp._proc is None


def test_concurrent_requests_do_not_interleave_json_lines():
    with client() as mcp:
        results = []
        errors = []

        def invoke(index: int) -> None:
            try:
                results.append(mcp.call_tool("safe_tool", {"value": str(index)}))
            except Exception as error:  # pragma: no cover - asserted below
                errors.append(error)

        threads = [threading.Thread(target=invoke, args=(index,)) for index in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
        assert errors == []
        assert len(results) == 20


def test_explicit_environment_is_the_only_way_to_pass_a_secret(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "parent-secret")
    with client(env={"OPENAI_API_KEY": "explicit-secret"}) as mcp:
        assert mcp.list_tools()[0]["description"] == "key-visible"
