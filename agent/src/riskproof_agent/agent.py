"""
RiskProof + LangGraph Agent

A ReAct-pattern LangGraph agent that connects to the RiskProof MCP proxy
for risk-aware tool-call interception. Every tool call flows through
RiskProof's policy engine. When a call is blocked, the agent shows the
full RiskProof approval card (provenance, taint, matched policies,
consequences, recommendation).

Architecture:
    User query → LLM (with bound MCP tools)
                    ↓
              Tool call? ──Yes──→ MCPClient.call_tool()
                    ↓                  ↓
                   No            RiskProof proxy
                    ↓                  ↓
                Response     allow / block / ask_approval
                                   ↓
                            ToolMessage (result or block card)
                                   ↓
                            LLM (explains to user)
                                   ↓
                              Final response
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Mapping
from typing import Annotated, Literal, TypedDict

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import Command, interrupt

from riskproof_agent.mcp_client import (
    MCPApprovalRequiredError,
    MCPBlockedError,
    MCPClient,
    MCPError,
    mcp_tool_to_langchain,
)

logger = logging.getLogger(__name__)


def resolve_llm_settings(
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
) -> tuple[str | None, str | None, str]:
    """Resolve a consistent provider key/base/model tuple.

    Explicit arguments take precedence. Selecting a DeepSeek key without an
    explicit base URL uses the DeepSeek endpoint and model, never OpenAI's.
    """
    deepseek_api_key = os.getenv("DEEPSEEK_API_KEY")
    if api_key is not None:
        return (
            api_key,
            base_url,
            model or os.getenv("LLM_MODEL") or "gpt-4o",
        )
    if deepseek_api_key:
        return (
            deepseek_api_key,
            base_url or os.getenv("DEEPSEEK_BASE_URL") or "https://api.deepseek.com",
            model or os.getenv("DEEPSEEK_MODEL") or os.getenv("LLM_MODEL") or "deepseek-chat",
        )
    return (
        os.getenv("OPENAI_API_KEY"),
        base_url or os.getenv("OPENAI_BASE_URL") or None,
        model or os.getenv("LLM_MODEL") or "gpt-4o",
    )


# ── Agent State ─────────────────────────────────────────────────────────────


class AgentState(TypedDict):
    """LangGraph agent state — a simple accumulator of chat messages."""

    messages: Annotated[list[BaseMessage], add_messages]


def _normalise_approval_decisions(
    resumed: object,
    requests: list[dict],
) -> dict[str, str]:
    """Return an explicit approve/reject decision for every pending tool call."""
    request_ids = [request["tool_call_id"] for request in requests]
    if not isinstance(resumed, dict):
        return {request_id: "reject" for request_id in request_ids}

    # Backward compatibility for the original single-request demo payload.
    if len(request_ids) == 1 and resumed.get("action") in {"approve", "reject"}:
        return {request_ids[0]: resumed["action"]}

    supplied = resumed.get("decisions")
    if not isinstance(supplied, dict):
        return {request_id: "reject" for request_id in request_ids}
    return {
        request_id: supplied.get(request_id)
        if supplied.get(request_id) in {"approve", "reject"}
        else "reject"
        for request_id in request_ids
    }


# ── RiskProof Agent ─────────────────────────────────────────────────────────


class RiskProofAgent:
    """
    A ReAct agent that uses the RiskProof MCP proxy for tool execution.

    Every tool call goes through RiskProof's policy engine. The agent
    understands RiskProof's block and approval-required responses and
    communicates them clearly to the user.

    Usage:
        agent = RiskProofAgent(["npx", "tsx", "proxy.ts", "--upstream", "..."])
        response = agent.run("Send an email to customer@example.com")
    """

    def __init__(
        self,
        mcp_command: list[str],
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        *,
        mcp_env: Mapping[str, str] | None = None,
        allow_unsigned_client_decisions: bool = False,
    ):
        """
        Args:
            mcp_command: The subprocess command to start the RiskProof proxy.
            model: LLM model name (default from LLM_MODEL env or 'gpt-4o').
            api_key: OpenAI-compatible API key (default from provider environment).
            base_url: OpenAI-compatible base URL (default from provider environment).
        """
        # ── MCP Client ─────────────────────────────────────────────────
        self.mcp = MCPClient(
            mcp_command,
            env=mcp_env,
            allow_unsigned_client_decisions=allow_unsigned_client_decisions,
        )
        self._thread_id: str | None = None

        # ── LLM ────────────────────────────────────────────────────────
        api_key_val, base_url_val, model_val = resolve_llm_settings(api_key, base_url, model)

        if not api_key_val:
            raise ValueError(
                "OPENAI_API_KEY or DEEPSEEK_API_KEY is not set. "
                "Set it via .env file or environment variable.\n"
                "  echo 'OPENAI_API_KEY=sk-your-key' > agent/.env\n"
                "  # or\n"
                "  echo 'DEEPSEEK_API_KEY=sk-your-key' > agent/.env"
            )

        logger.info("LLM configured: model=%s", model_val)

        self.llm = ChatOpenAI(
            model=model_val,
            openai_api_key=api_key_val,
            base_url=base_url_val,
            temperature=0,
            max_retries=2,
            timeout=30,
        )

        # ── System prompt ──────────────────────────────────────────────
        self.system_prompt = SystemMessage(
            content="""You are an enterprise AI assistant with access to business tools.
All your tool calls are monitored by RiskProof, a security layer that evaluates
each action for risk before execution.

When you call a tool and RiskProof BLOCKS it:
- Read the approval card carefully — it explains WHAT was blocked, WHY it
  was blocked (provenance, taint, matched policies), and WHAT the
  consequences would be.
- Explain the block to the user in clear, non-technical language: what you
  tried to do, what RiskProof detected, and why it's dangerous.
- Proactively suggest a safer alternative approach to accomplish the user's
  goal. For example: instead of running a remote script directly, suggest
  downloading and reviewing it first; instead of sending raw customer data,
  suggest anonymizing it.
- Do NOT attempt to call the same blocked tool again with the same arguments.

When RiskProof REQUIRES APPROVAL:
- The action has been paused for user review. Summarize what the tool would
  do and why RiskProof flagged it, then ask the user whether to proceed.
- The user will be shown a security card and given the choice to approve or
  reject. Their decision will be communicated back to you.
- If the user APPROVES, you will receive the tool result and should continue
  the task normally.
- If the user REJECTS, treat it as blocked: explain the rejection and
  suggest an alternative approach.
- Do NOT attempt to bypass the approval requirement.

When a tool call is ALLOWED:
- Report the result normally and continue the task.

Be helpful, transparent, and always respect RiskProof's security decisions.
When tools are blocked or rejected, be constructive — help the user find a
safer way to achieve their goal."""
        )

        # ── Load tools & build graph ───────────────────────────────────
        self.tools: list[dict] = []
        self._tool_name_to_def: dict[str, dict] = {}
        self.graph = self._build()

    # ── Tool loading ────────────────────────────────────────────────────

    def _load_mcp_tools(self) -> list[dict]:
        """Fetch tool definitions from the MCP server via tools/list."""
        logger.info("Connecting to RiskProof MCP proxy")
        raw = self.mcp.list_tools()
        logger.info("Loaded %d MCP tools", len(raw))
        self.tools = []
        self._tool_name_to_def = {}
        for t in raw:
            self._tool_name_to_def[t["name"]] = t
            self.tools.append(mcp_tool_to_langchain(t))
        return self.tools

    # ── Graph construction ──────────────────────────────────────────────

    def _build(self):
        """Build the ReAct StateGraph.

        Nodes:
            agent:  LLM decides what to do (call tools or respond).
            tools:  Execute tool calls through RiskProof proxy.

        Edges:
            agent → tools (when tool calls are needed)
            agent → END   (when response is ready)
            tools → agent (loop back with results)
        """
        self._load_mcp_tools()

        workflow = StateGraph(AgentState)

        # Add nodes
        workflow.add_node("agent", self._agent_node)
        workflow.add_node("tools", self._tools_node)

        # Entry point
        workflow.set_entry_point("agent")

        # Conditional routing after agent node
        workflow.add_conditional_edges(
            "agent",
            self._should_continue,
            {
                "continue": "tools",
                "end": END,
            },
        )

        # After tools, always go back to agent
        workflow.add_edge("tools", "agent")

        # ── Compile with checkpointer for multi-turn + interrupt support ──
        self.memory = MemorySaver()
        return workflow.compile(checkpointer=self.memory)

    # ── Agent node ───────────────────────────────────────────────────────

    def _agent_node(self, state: AgentState) -> dict:
        """Call the LLM with the current message history and available tools.

        The LLM may respond with a final text answer, or with one or more
        tool_calls that need to be routed to the tools node.
        """
        messages = state["messages"]

        # Prepend system prompt if not already present
        full_messages = [self.system_prompt] + list(messages)

        # Bind the current MCP tools to the LLM
        llm_with_tools = self.llm.bind_tools(self.tools)

        logger.debug("Calling LLM with %d tools", len(self.tools))
        response = llm_with_tools.invoke(full_messages)

        if hasattr(response, "tool_calls") and response.tool_calls:
            logger.debug("LLM requested %d tool calls", len(response.tool_calls))
        else:
            logger.debug("LLM returned a direct response")

        return {"messages": [response]}

    # ── Tools node ───────────────────────────────────────────────────────

    def _tools_node(self, state: AgentState) -> dict:
        """Preflight all calls, collect approvals, then execute at most once.

        No external tool is executed before the single batch ``interrupt``.
        LangGraph may replay this node while resuming, but replay only repeats
        side-effect-free policy evaluation; execution begins after every human
        decision is known. This prevents an earlier allowed tool from running a
        second time when a later tool pauses for approval.
        """
        last_message = state["messages"][-1]
        if not isinstance(last_message, AIMessage) or not last_message.tool_calls:
            return {"messages": []}

        outcomes: list[dict] = []
        approval_requests: list[dict] = []

        for tool_call in last_message.tool_calls:
            tool_name = tool_call.get("name")
            tool_args = tool_call.get("args")
            tool_call_id = tool_call.get("id")
            if (
                not isinstance(tool_name, str)
                or not isinstance(tool_args, dict)
                or not isinstance(tool_call_id, str)
            ):
                outcomes.append(
                    {
                        "tool_name": tool_name if isinstance(tool_name, str) else "unknown",
                        "tool_args": {},
                        "tool_call_id": tool_call_id
                        if isinstance(tool_call_id, str)
                        else "invalid",
                        "action": "error",
                        "message": "RiskProof rejected a malformed LLM tool call before execution.",
                    }
                )
                continue
            try:
                decision = self.mcp.evaluate_tool(tool_name, tool_args)
                action = decision["action"]
                outcome = {
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "tool_call_id": tool_call_id,
                    "action": action,
                    "decision": decision,
                }
                outcomes.append(outcome)
                if action == "ask_approval":
                    proof = decision.get("proof", {})
                    approval_requests.append(
                        {
                            "tool_name": tool_name,
                            "tool_call_id": tool_call_id,
                            "risk_level": decision.get("riskLevel", "unknown"),
                            "matched_policy_ids": [
                                policy.get("id", "?")
                                for policy in decision.get("matchedPolicies", [])
                                if isinstance(policy, dict)
                            ],
                            "arguments": decision.get("arguments", {}),
                            "proof_id": proof.get("proofId") if isinstance(proof, dict) else None,
                            "reason": proof.get("reason") if isinstance(proof, dict) else None,
                        }
                    )
            except MCPError as error:
                logger.warning("RiskProof preflight failed closed: code=%s", error.code)
                outcomes.append(
                    {
                        "tool_name": tool_name,
                        "tool_args": tool_args,
                        "tool_call_id": tool_call_id,
                        "action": "error",
                        "message": "RiskProof policy evaluation failed; the tool was not executed.",
                    }
                )

        decisions: dict[str, str] = {}
        if approval_requests:
            resumed = interrupt(
                {
                    "type": "approval_required",
                    "requests": approval_requests,
                }
            )
            decisions = _normalise_approval_decisions(resumed, approval_requests)

        tool_messages: list[ToolMessage] = []
        for outcome in outcomes:
            tool_name = outcome["tool_name"]
            tool_args = outcome["tool_args"]
            tool_call_id = outcome["tool_call_id"]
            action = outcome["action"]

            if action == "block":
                decision = outcome["decision"]
                proof = decision.get("proof", {})
                reason = proof.get("reason", "RiskProof policy denied the call")
                content = (
                    "RISKPROOF BLOCKED THIS ACTION.\n\n"
                    f"Reason: {reason}\n\n"
                    "The action was not executed. Explain the risk and suggest a safer alternative."
                )
            elif action == "error":
                content = outcome["message"]
            elif action == "ask_approval" and decisions.get(tool_call_id) != "approve":
                content = (
                    "RISKPROOF APPROVAL WAS REJECTED.\n\n"
                    f"The user chose not to execute '{tool_name}'. "
                    "The action was not performed."
                )
            else:
                try:
                    result = self.mcp.call_tool(
                        tool_name,
                        tool_args,
                        approved=action == "ask_approval",
                    )
                    content = json.dumps(result, ensure_ascii=False, indent=2)
                except (MCPBlockedError, MCPApprovalRequiredError, MCPError) as error:
                    logger.warning("MCP execution failed closed: code=%s", error.code)
                    content = (
                        "RiskProof did not execute the tool because the final proxy "
                        "authorization or upstream call failed."
                    )
                except Exception:
                    logger.exception("Unexpected MCP execution failure")
                    content = "The tool was not confirmed as executed due to an internal error."

            tool_messages.append(
                ToolMessage(
                    content=content,
                    tool_call_id=tool_call_id,
                    name=tool_name,
                )
            )
        return {"messages": tool_messages}

    # ── Routing ──────────────────────────────────────────────────────────

    def _should_continue(self, state: AgentState) -> Literal["continue", "end"]:
        """Decide whether to continue to the tools node or end."""
        last_message = state["messages"][-1]

        if isinstance(last_message, AIMessage) and last_message.tool_calls:
            return "continue"

        return "end"

    # ── Public API ───────────────────────────────────────────────────────

    def start_session(self) -> str:
        """Start a new conversation session. Returns the thread_id.

        Call this once per conversation. The returned thread_id is used
        across all turns to maintain conversation state.
        """
        self._thread_id = str(uuid.uuid4())
        return self._thread_id

    def get_config(self, thread_id: str | None = None) -> dict:
        """Get the LangGraph config for a session.

        Args:
            thread_id: Optional thread_id. Uses the one from start_session() if omitted.
        """
        tid = thread_id or getattr(self, "_thread_id", None) or self.start_session()
        return {"configurable": {"thread_id": tid}}

    def send_message(self, content: str, config: dict | None = None):
        """Send a user message and yield stream events.

        Yields dicts where keys may include node names with message updates,
        or a special '__interrupt__' key when approval is required.

        Args:
            content: The user's message text.
            config: LangGraph config with thread_id. Created automatically if omitted.
        """
        cfg = config or self.get_config()
        initial_state: AgentState = {"messages": [HumanMessage(content=content)]}

        yield from self.graph.stream(
            initial_state,
            cfg,
            stream_mode="updates",
        )

    def resume_after_interrupt(self, decision: dict, config: dict | None = None):
        """Resume graph execution after an interrupt with the user's decision.

        Args:
            decision: {"action": "approve"} or {"action": "reject"}
            config: LangGraph config with thread_id.

        Returns:
            The final graph state after resumption.
        """
        cfg = config or self.get_config()
        return self.graph.invoke(Command(resume=decision), cfg)

    def get_response(self, config: dict | None = None) -> str | None:
        """Extract the last AI message from the current session state."""
        cfg = config or self.get_config()
        state = self.graph.get_state(cfg)
        if state.values and "messages" in state.values:
            for msg in reversed(state.values["messages"]):
                if isinstance(msg, AIMessage) and msg.content:
                    return msg.content
        return None

    def run(self, query: str, thread_id: str | None = None) -> str:
        """Run the agent with a user query and return the final response.

        In non-interactive mode, approval requests are auto-rejected.
        For interactive approval, use send_message() + resume_after_interrupt().

        Args:
            query: The user's natural-language request.
            thread_id: Optional thread_id for multi-turn conversations.
                If omitted, a new session is created.

        Returns:
            The agent's final text response.
        """
        logger.debug("Invoking agent graph")

        cfg = self.get_config(thread_id)

        try:
            result = self.graph.invoke(
                {"messages": [HumanMessage(content=query)]},
                cfg,
            )
            # LangGraph returns interrupts as state in current releases rather
            # than raising GraphInterrupt. Non-interactive run() rejects them.
            if isinstance(result, dict) and result.get("__interrupt__"):
                result = self.graph.invoke(Command(resume={"action": "reject"}), cfg)
        except Exception:
            logger.exception("LangGraph invocation failed")
            raise

        # Extract the final AI message
        final_message = result["messages"][-1]
        if isinstance(final_message, AIMessage) and final_message.content:
            return final_message.content

        return str(final_message)

    def stream(self, query: str, thread_id: str | None = None):
        """Stream the agent's execution, yielding state updates.

        Yields dicts with the current state after each graph step.
        For interactive approval, use send_message() instead.

        Args:
            query: The user's natural-language request.
            thread_id: Optional thread_id for multi-turn conversations.
        """
        cfg = self.get_config(thread_id)
        initial_state: AgentState = {"messages": [HumanMessage(content=query)]}
        yield from self.graph.stream(initial_state, cfg)

    def close(self):
        """Shut down the MCP subprocess."""
        self.mcp.close()
        logger.info("MCP client closed")
