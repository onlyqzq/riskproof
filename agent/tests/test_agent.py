from __future__ import annotations

from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import StateGraph
from langgraph.types import Command

from riskproof_agent.agent import (
    AgentState,
    RiskProofAgent,
    _normalise_approval_decisions,
    resolve_llm_settings,
)


class FakeMCP:
    def __init__(self, actions):
        self.actions = actions
        self.evaluations = []
        self.executions = []

    def evaluate_tool(self, name, args):
        self.evaluations.append((name, args))
        action = self.actions[name]
        return {
            "action": action,
            "decision": "allow" if action == "allow" else "require_approval",
            "riskLevel": "low" if action == "allow" else "high",
            "matchedPolicies": [] if action == "allow" else [{"id": "fixture"}],
            "arguments": {},
            "proof": {"proofId": f"proof-{name}", "reason": "fixture reason"},
        }

    def call_tool(self, name, args, approved=False):
        self.executions.append((name, approved))
        return {"name": name, "executed": True}


def make_graph(fake_mcp):
    agent = object.__new__(RiskProofAgent)
    agent.mcp = fake_mcp
    workflow = StateGraph(AgentState)
    workflow.add_node("tools", agent._tools_node)
    workflow.set_entry_point("tools")
    workflow.set_finish_point("tools")
    return workflow.compile(checkpointer=MemorySaver())


def tool_message(*calls):
    return AIMessage(
        content="",
        tool_calls=[
            {"name": name, "args": {}, "id": call_id, "type": "tool_call"}
            for name, call_id in calls
        ],
    )


def test_interrupt_resume_does_not_replay_an_allowed_side_effect():
    fake = FakeMCP({"already_allowed": "allow", "needs_approval": "ask_approval"})
    graph = make_graph(fake)
    config = {"configurable": {"thread_id": "allow-approve"}}
    first = graph.invoke(
        {"messages": [tool_message(("already_allowed", "call-1"), ("needs_approval", "call-2"))]},
        config,
    )
    assert first["__interrupt__"]
    assert fake.executions == []

    graph.invoke(Command(resume={"decisions": {"call-2": "approve"}}), config)
    assert fake.executions == [
        ("already_allowed", False),
        ("needs_approval", True),
    ]


def test_reject_still_executes_each_independent_allowed_call_once():
    fake = FakeMCP({"already_allowed": "allow", "needs_approval": "ask_approval"})
    graph = make_graph(fake)
    config = {"configurable": {"thread_id": "allow-reject"}}
    graph.invoke(
        {"messages": [tool_message(("already_allowed", "call-1"), ("needs_approval", "call-2"))]},
        config,
    )
    graph.invoke(Command(resume={"decisions": {"call-2": "reject"}}), config)
    assert fake.executions == [("already_allowed", False)]


def test_invalid_or_missing_batch_decisions_default_to_reject():
    requests = [{"tool_call_id": "a"}, {"tool_call_id": "b"}]
    assert _normalise_approval_decisions({}, requests) == {"a": "reject", "b": "reject"}
    assert _normalise_approval_decisions(
        {"decisions": {"a": "approve", "b": "invalid"}}, requests
    ) == {"a": "approve", "b": "reject"}


def test_deepseek_settings_never_default_to_openai_endpoint(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "deepseek-sentinel")
    monkeypatch.delenv("DEEPSEEK_BASE_URL", raising=False)
    key, base_url, model = resolve_llm_settings()
    assert key == "deepseek-sentinel"
    assert base_url == "https://api.deepseek.com"
    assert model == "deepseek-chat"


def test_explicit_settings_do_not_mutate_process_environment(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert resolve_llm_settings("explicit", "https://provider.example", "model") == (
        "explicit",
        "https://provider.example",
        "model",
    )
    assert "OPENAI_API_KEY" not in __import__("os").environ


def test_missing_key_raises_value_error_before_subprocess_or_llm_use(monkeypatch):
    for name in ("OPENAI_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY or DEEPSEEK_API_KEY"):
        RiskProofAgent(["definitely-not-executed"])


def test_session_stream_resume_response_and_close_helpers():
    class FakeGraph:
        def stream(self, state, config, **kwargs):
            yield {"state": state, "config": config, "kwargs": kwargs}

        def invoke(self, command, config):
            return {"command": command, "config": config}

        def get_state(self, _config):
            return SimpleNamespace(values={"messages": [AIMessage(content="final answer")]})

    class Closable:
        closed = False

        def close(self):
            self.closed = True

    agent = object.__new__(RiskProofAgent)
    agent._thread_id = None
    agent.graph = FakeGraph()
    agent.mcp = Closable()
    thread_id = agent.start_session()
    config = agent.get_config(thread_id)
    assert list(agent.send_message("hello", config))[0]["kwargs"] == {"stream_mode": "updates"}
    assert agent.resume_after_interrupt({"action": "reject"}, config)["config"] == config
    assert agent.get_response(config) == "final answer"
    assert list(agent.stream("hello", thread_id))[0]["state"]["messages"][0].content == "hello"
    agent.close()
    assert agent.mcp.closed is True


def test_run_detects_returned_interrupt_and_auto_rejects():
    class InterruptingGraph:
        def __init__(self):
            self.calls = []

        def invoke(self, value, config):
            self.calls.append((value, config))
            if len(self.calls) == 1:
                return {"__interrupt__": [object()], "messages": [HumanMessage(content="query")]}
            return {"messages": [AIMessage(content="rejected safely")]}

    agent = object.__new__(RiskProofAgent)
    agent._thread_id = None
    agent.graph = InterruptingGraph()
    assert agent.run("query") == "rejected safely"
    assert isinstance(agent.graph.calls[1][0], Command)


def test_tool_loading_and_routing_helpers():
    class ToolsMCP:
        def list_tools(self):
            return [
                {
                    "name": "safe_tool",
                    "description": "safe",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]

    agent = object.__new__(RiskProofAgent)
    agent.mcp = ToolsMCP()
    agent.tools = []
    agent._tool_name_to_def = {}
    assert len(agent._load_mcp_tools()) == 1
    assert agent._should_continue({"messages": [AIMessage(content="done")]}) == "end"
    assert (
        agent._should_continue({"messages": [tool_message(("safe_tool", "call-1"))]}) == "continue"
    )
