from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from langchain_core.tools import tool

from riskproof_agent.callback import (
    LangChainRiskProofHandler,
    RiskProofApprovalRequiredError,
    RiskProofBlockedError,
    RiskProofCallback,
    RiskProofConnectionError,
    RiskProofProtocolError,
    RiskProofRejectedError,
    validate_engine_response,
)


class StubCallback(RiskProofCallback):
    def __init__(self, response, **kwargs):
        super().__init__(**kwargs)
        self.response = response

    def evaluate(self, tool_name, tool_args):
        return validate_engine_response(self.response)


def result(action: str = "allow", risk: str = "low") -> dict:
    return {
        "action": action,
        "decision": "allow" if action == "allow" else "deny",
        "riskLevel": risk,
        "matchedPolicies": [] if action == "allow" else [{"id": "fixture_rule"}],
        "arguments": {},
        "proof": {"proofId": "fixture"},
    }


def test_callback_is_a_real_fail_closed_langchain_handler():
    callback = StubCallback(result("block", "critical"))
    executed = []

    @tool
    def destructive(value: str) -> str:
        """A fake destructive tool used only to count execution."""
        executed.append(value)
        return "EXECUTED"

    with pytest.raises(RiskProofBlockedError):
        destructive.invoke({"value": "sentinel"}, config={"callbacks": [callback]})
    assert executed == []
    assert callback.raise_error is True


@pytest.mark.parametrize("payload", [{}, {"action": "new_action"}, None, []])
def test_missing_or_unknown_action_fails_closed(payload):
    callback = StubCallback(payload)
    with pytest.raises(RiskProofProtocolError):
        callback.handle_tool_call("shell_exec", {"command": "echo safe"})


def test_noninteractive_approval_raises_and_does_not_allow():
    callback = StubCallback(result("ask_approval", "high"), interactive=False)
    with pytest.raises(RiskProofApprovalRequiredError):
        callback.handle_tool_call("shell_exec", {"command": "echo safe"})


@pytest.mark.parametrize(
    ("approved", "exception"),
    [(True, None), (False, RiskProofRejectedError)],
)
def test_explicit_approval_callback_controls_interactive_path(approved, exception):
    callback = StubCallback(
        result("ask_approval", "high"),
        interactive=True,
        approval_callback=lambda *_args: approved,
    )
    if exception:
        with pytest.raises(exception):
            callback.handle_tool_call("shell_exec", {"command": "echo safe"})
    else:
        assert callback.handle_tool_call("shell_exec", {"command": "echo safe"}) is None


def test_tool_mapping_is_required_for_business_names():
    callback = RiskProofCallback()
    with pytest.raises(RiskProofProtocolError):
        callback.handle_tool_call("deploy_config", {"command": "echo safe"})


def test_legacy_wrapper_also_propagates_errors():
    callback = StubCallback(result("block", "critical"))
    wrapper = LangChainRiskProofHandler(callback)
    assert wrapper.raise_error is True
    with pytest.raises(RiskProofBlockedError):
        wrapper.on_tool_start({"name": "shell_exec"}, json.dumps({"command": "rm -rf /"}))


def test_http_mode_sends_only_tool_and_arguments():
    captured = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            captured.append(json.loads(self.rfile.read(length)))
            payload = json.dumps(result()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        callback = RiskProofCallback(
            base_url=f"http://127.0.0.1:{server.server_port}",
            tool_mapping={"business_tool": "shell_exec"},
        )
        assert callback.handle_tool_call("business_tool", {"command": "echo safe"}) is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    assert captured == [{"tool": "shell_exec", "args": {"command": "echo safe"}}]


def test_cli_mode_uses_explicit_command_without_npx(tmp_path):
    cli = tmp_path / "fake_cli.py"
    cli.write_text(
        f"import json, sys\nprint(json.dumps({result()!r}))\nraise SystemExit(0)\n",
        encoding="utf-8",
    )
    callback = RiskProofCallback(mode="cli", cli_command=[sys.executable, str(cli)])
    assert callback.handle_tool_call("shell_exec", {"command": "echo safe"}) is None


def test_cli_start_failure_is_fail_closed():
    callback = RiskProofCallback(mode="cli", cli_command=["/definitely/missing/riskproof"])
    with pytest.raises(RiskProofConnectionError):
        callback.handle_tool_call("shell_exec", {"command": "echo safe"})
