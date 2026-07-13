"""Fail-closed LangChain callback for RiskProof tool-call evaluation."""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal

from langchain_core.callbacks import BaseCallbackHandler

RISK_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
VALID_ACTIONS = {"allow", "block", "ask_approval"}
SUPPORTED_TOOLS = {"send_email", "http_request", "shell_exec"}


class RiskProofError(Exception):
    """Base exception for RiskProof integration errors."""


class RiskProofConnectionError(RiskProofError):
    """The RiskProof service or CLI could not be reached."""


class RiskProofProtocolError(RiskProofError):
    """RiskProof returned malformed or unsupported data; execution must stop."""


class RiskProofBlockedError(RiskProofError):
    """The policy engine denied the tool call."""

    def __init__(self, result: dict[str, Any]):
        self.result = result
        policies = [
            policy.get("id", "?")
            for policy in result.get("matchedPolicies", [])
            if isinstance(policy, dict)
        ]
        super().__init__(
            f"Blocked by RiskProof: {', '.join(policies) or 'policy deny'} "
            f"(risk: {result.get('riskLevel', 'unknown')})"
        )


class RiskProofApprovalRequiredError(RiskProofError):
    """The call requires a trusted human approval before execution."""

    def __init__(self, result: dict[str, Any]):
        self.result = result
        super().__init__(f"Approval required (risk: {result.get('riskLevel', 'unknown')})")


class RiskProofRejectedError(RiskProofError):
    """The user explicitly rejected the tool call."""

    def __init__(self, result: dict[str, Any]):
        self.result = result
        super().__init__("User rejected the tool call")


ApprovalCallback = Callable[[str, dict[str, Any], dict[str, Any]], bool]


class RiskProofCallback(BaseCallbackHandler):
    """Evaluate LangChain tool calls before execution and fail closed on errors.

    ``tool_mapping`` is required when LangChain tool names differ from the three
    RiskProof engine tool types. Security context (capabilities, invariants and
    internal domains) is intentionally not accepted from LLM-controlled tool
    input; configure it on the trusted RiskProof service instead.
    """

    raise_error = True

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:9090",
        mode: Literal["http", "cli"] = "http",
        interactive: bool = False,
        auto_deny_shell: bool = True,
        min_risk_for_prompt: str = "medium",
        *,
        tool_mapping: Mapping[str, str] | None = None,
        approval_callback: ApprovalCallback | None = None,
        cli_command: Sequence[str] = ("riskproof",),
        timeout_seconds: float = 10.0,
    ):
        super().__init__()
        if mode not in {"http", "cli"}:
            raise ValueError("mode must be 'http' or 'cli'")
        if min_risk_for_prompt not in RISK_ORDER:
            raise ValueError(f"min_risk_for_prompt must be one of: {', '.join(RISK_ORDER)}")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        self.base_url = base_url.rstrip("/")
        self.mode = mode
        self.interactive = interactive
        # Kept as a public compatibility attribute. All explicit block
        # decisions now fail closed regardless of risk level.
        self.auto_deny_shell = auto_deny_shell
        self.min_risk = min_risk_for_prompt
        self._min_risk_order = RISK_ORDER[min_risk_for_prompt]
        self.tool_mapping = dict(tool_mapping or {})
        self.approval_callback = approval_callback
        self.cli_command = tuple(cli_command)
        self.timeout_seconds = timeout_seconds

    def evaluate(self, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        mapped_tool = self.tool_mapping.get(tool_name, tool_name)
        if mapped_tool not in SUPPORTED_TOOLS:
            raise RiskProofProtocolError(
                f"Unsupported tool '{tool_name}'. Configure tool_mapping to one of: "
                f"{', '.join(sorted(SUPPORTED_TOOLS))}"
            )

        if self.mode == "http":
            result = self._evaluate_http(mapped_tool, tool_args)
        else:
            result = self._evaluate_cli(mapped_tool, tool_args)
        return validate_engine_response(result)

    def _evaluate_http(self, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps({"tool": tool_name, "args": tool_args}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/evaluate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
                if len(payload) > 2 * 1024 * 1024:
                    raise RiskProofProtocolError("RiskProof response exceeds 2 MB")
                decoded = json.loads(payload.decode("utf-8"))
                if not isinstance(decoded, dict):
                    raise RiskProofProtocolError("RiskProof response must be a JSON object")
                return decoded
        except RiskProofProtocolError:
            raise
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise RiskProofProtocolError("RiskProof returned invalid JSON") from error
        except urllib.error.HTTPError as error:
            raise RiskProofConnectionError(
                f"RiskProof rejected the evaluation request with HTTP {error.code}"
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise RiskProofConnectionError(
                f"Cannot reach RiskProof server at {self.base_url}"
            ) from error

    def _evaluate_cli(self, tool_name: str, tool_args: dict[str, Any]) -> dict[str, Any]:
        if not self.cli_command:
            raise RiskProofConnectionError("cli_command must not be empty")
        event = {"tool": tool_name, "args": tool_args}
        path = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as file:
                json.dump(event, file)
                path = file.name
            result = subprocess.run(
                [*self.cli_command, "check", path, "--pretty"],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=minimal_subprocess_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RiskProofConnectionError("Failed to execute the RiskProof CLI") from error
        finally:
            if path:
                with contextlib.suppress(OSError):
                    os.unlink(path)

        if result.returncode not in (0, 2, 3):
            raise RiskProofConnectionError(
                f"RiskProof CLI failed with exit code {result.returncode}"
            )
        try:
            decoded = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise RiskProofProtocolError("RiskProof CLI returned invalid JSON") from error
        if not isinstance(decoded, dict):
            raise RiskProofProtocolError("RiskProof CLI response must be an object")
        return decoded

    def handle_tool_call(self, tool_name: str, tool_args: dict[str, Any]) -> None:
        result = self.evaluate(tool_name, tool_args)
        action = result["action"]
        if action == "allow":
            return
        if action == "block":
            raise RiskProofBlockedError(result)

        risk_level = result["riskLevel"]
        should_prompt = self.interactive and RISK_ORDER[risk_level] >= self._min_risk_order
        if should_prompt:
            approved = (
                self.approval_callback(tool_name, tool_args, result)
                if self.approval_callback
                else self._prompt_user(tool_name, result)
            )
            if approved:
                return
            raise RiskProofRejectedError(result)
        raise RiskProofApprovalRequiredError(result)

    def _prompt_user(self, tool_name: str, result: dict[str, Any]) -> bool:
        policy_ids = [
            policy.get("id", "?")
            for policy in result.get("matchedPolicies", [])
            if isinstance(policy, dict)
        ]
        print("\nRiskProof approval required")
        print(f"  Tool: {tool_name}")
        print(f"  Risk: {result['riskLevel'].upper()}")
        print(f"  Policies: {', '.join(policy_ids)}")
        while True:
            choice = input("  Approve? [y/N]: ").strip().lower()
            if choice in ("y", "yes"):
                return True
            if choice in ("n", "no", ""):
                return False
            print("  Invalid choice. Enter 'y' or 'n'.")

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name")
        if not isinstance(tool_name, str) or not tool_name:
            raise RiskProofProtocolError("LangChain tool name is missing or invalid")
        structured_inputs = kwargs.get("inputs")
        if isinstance(structured_inputs, dict):
            tool_args = structured_inputs
        else:
            if not isinstance(input_str, str):
                raise RiskProofProtocolError("LangChain tool input must be JSON text")
            try:
                tool_args = json.loads(input_str)
            except json.JSONDecodeError as error:
                raise RiskProofProtocolError("LangChain tool input is not valid JSON") from error
        if not isinstance(tool_args, dict):
            raise RiskProofProtocolError("LangChain tool input must decode to an object")
        self.handle_tool_call(tool_name, tool_args)


class LangChainRiskProofHandler(BaseCallbackHandler):
    """Backward-compatible wrapper around :class:`RiskProofCallback`."""

    raise_error = True

    def __init__(self, riskproof: RiskProofCallback):
        super().__init__()
        self.riskproof = riskproof

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        self.riskproof.on_tool_start(serialized, input_str, **kwargs)


def validate_engine_response(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise RiskProofProtocolError("RiskProof response must be an object")
    action = result.get("action")
    if action not in VALID_ACTIONS:
        raise RiskProofProtocolError(
            f"RiskProof response has missing or unsupported action: {action!r}"
        )
    risk_level = result.get("riskLevel")
    if risk_level not in RISK_ORDER:
        raise RiskProofProtocolError(
            f"RiskProof response has missing or unsupported riskLevel: {risk_level!r}"
        )
    policies = result.get("matchedPolicies")
    if not isinstance(policies, list) or not all(
        isinstance(policy, dict) and isinstance(policy.get("id"), str) for policy in policies
    ):
        raise RiskProofProtocolError("RiskProof matchedPolicies must be a list of policy objects")
    return result


def minimal_subprocess_env() -> dict[str, str]:
    allowed = ("PATH", "HOME", "TMPDIR", "TEMP", "TMP", "SYSTEMROOT", "WINDIR")
    return {name: os.environ[name] for name in allowed if name in os.environ}
