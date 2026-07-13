"""
RiskProof Agent SDK — Risk-aware approval middleware for AI Agent tool calls.

Provides:
- RiskProofAgent: A LangGraph ReAct agent with human-in-the-loop approval
- MCPClient: JSON-RPC stdio client for the RiskProof proxy
- RiskProofCallback: LangChain callback handler for tool-call interception
- LangChainRiskProofHandler: Native LangChain BaseCallbackHandler
- resolve_llm_settings: Helper to resolve LLM credentials from env vars

Quick Start:
    from riskproof_agent import RiskProofAgent

    agent = RiskProofAgent(
        mcp_command=["npx", "riskproof", "proxy", "--upstream", "your-mcp-server"],
    )
    response = agent.run("Send the report to customer@example.com")

Callback Mode:
    from riskproof_agent import RiskProofCallback

    handler = RiskProofCallback(base_url="http://localhost:9090")
    agent.invoke({"messages": [...]}, config={"callbacks": [handler]})
"""

from riskproof_agent.agent import RiskProofAgent, resolve_llm_settings
from riskproof_agent.callback import (
    LangChainRiskProofHandler,
    RiskProofApprovalRequiredError,
    RiskProofBlockedError,
    RiskProofCallback,
    RiskProofConnectionError,
    RiskProofError,
    RiskProofProtocolError,
    RiskProofRejectedError,
)
from riskproof_agent.mcp_client import (
    MCPApprovalRequiredError,
    MCPBlockedError,
    MCPClient,
    MCPError,
    MCPTimeoutError,
    format_blocked_message,
    mcp_tool_to_langchain,
)

__all__ = [
    # Agent
    "RiskProofAgent",
    "resolve_llm_settings",
    # MCP Client
    "MCPClient",
    "MCPBlockedError",
    "MCPApprovalRequiredError",
    "MCPError",
    "MCPTimeoutError",
    "mcp_tool_to_langchain",
    "format_blocked_message",
    # Callback
    "RiskProofCallback",
    "RiskProofError",
    "RiskProofConnectionError",
    "RiskProofBlockedError",
    "RiskProofRejectedError",
    "RiskProofApprovalRequiredError",
    "RiskProofProtocolError",
    "LangChainRiskProofHandler",
]

__version__ = "0.1.0"
