"""Thread-safe, fail-closed JSON-RPC stdio client for an MCP subprocess."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import subprocess
import threading
from collections.abc import Callable, Mapping
from typing import Any

ERR_BLOCKED = -32000
ERR_REQUIRES_APPROVAL = -32001
MAX_RESPONSE_LINE = 4 * 1024 * 1024
_SAFE_ENV_NAMES = (
    "PATH",
    "HOME",
    "USERPROFILE",
    "TMPDIR",
    "TEMP",
    "TMP",
    "SYSTEMROOT",
    "WINDIR",
    "LANG",
    "LC_ALL",
    "TERM",
)

logger = logging.getLogger(__name__)


class MCPError(Exception):
    """Base exception for MCP protocol and RiskProof errors."""

    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(message)


class MCPBlockedError(MCPError):
    """Tool call was blocked by RiskProof policy."""


class MCPApprovalRequiredError(MCPError):
    """Tool call requires trusted user approval."""


class MCPTimeoutError(MCPError):
    """Request timed out."""


class MCPClient:
    """JSON-RPC 2.0 client over stdio.

    Parent credentials are not inherited by default. Pass only the exact
    variables required by the proxy in ``env``. Unsigned approval metadata is
    disabled unless both this client and the TypeScript proxy explicitly opt in.
    """

    def __init__(
        self,
        command: list[str],
        timeout_ms: int = 60_000,
        *,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        stderr_handler: Callable[[str], None] | None = None,
        allow_unsigned_client_decisions: bool = False,
    ):
        if not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError("command must contain at least one non-empty string")
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        self._command = list(command)
        self._timeout = timeout_ms / 1000.0
        self._env = _minimal_env(env)
        self._cwd = cwd
        self._stderr_handler = stderr_handler
        self._allow_unsigned_client_decisions = allow_unsigned_client_decisions
        self._proc: subprocess.Popen[str] | None = None
        self._pending: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()
        self._reader_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._initialized = False
        self._next_id = 0

    def __enter__(self) -> MCPClient:
        self.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def start(self) -> None:
        """Start and initialize the MCP subprocess."""
        with self._lock:
            if self._proc is not None and self._proc.poll() is None and self._initialized:
                return
            if self._proc is not None:
                self._cleanup_process()
            try:
                self._proc = subprocess.Popen(
                    self._command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    env=self._env,
                    cwd=self._cwd,
                )
            except OSError as error:
                self._proc = None
                raise MCPError(-1, "Failed to start MCP subprocess") from error

            self._reader_thread = threading.Thread(
                target=self._read_loop, name="riskproof-mcp-stdout", daemon=True
            )
            self._stderr_thread = threading.Thread(
                target=self._drain_stderr, name="riskproof-mcp-stderr", daemon=True
            )
            self._reader_thread.start()
            self._stderr_thread.start()

        try:
            result = self._send_request(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "clientInfo": {"name": "riskproof-agent", "version": "0.1.0"},
                },
            )
            if not isinstance(result.get("serverInfo", {}), dict):
                raise MCPError(-1, "Invalid initialize response: serverInfo must be an object")
            self._send_notification("notifications/initialized", {})
            self._initialized = True
            logger.info(
                "MCP initialized: server=%s",
                result.get("serverInfo", {}).get("name", "unknown"),
            )
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        """Terminate the subprocess and wake all pending requests."""
        self._initialized = False
        self._fail_pending("MCP client closed")
        self._cleanup_process()
        current = threading.current_thread()
        for thread in (self._reader_thread, self._stderr_thread):
            if thread and thread is not current and thread.is_alive():
                thread.join(timeout=1)
        self._reader_thread = None
        self._stderr_thread = None

    def list_tools(self) -> list[dict[str, Any]]:
        self._ensure_started()
        response = self._send_request("tools/list", {})
        tools = response.get("tools")
        if not isinstance(tools, list):
            raise MCPError(-1, "Invalid tools/list response: tools must be an array")
        validated: list[dict[str, Any]] = []
        names: set[str] = set()
        for index, tool in enumerate(tools):
            if not isinstance(tool, dict):
                raise MCPError(-1, f"Invalid tool at index {index}: expected object")
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                raise MCPError(-1, f"Invalid tool at index {index}: missing name")
            if name in names:
                raise MCPError(-1, f"Duplicate MCP tool name: {name}")
            names.add(name)
            validated.append(tool)
        return validated

    def evaluate_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Evaluate a tool call without forwarding it to the upstream tool."""
        _validate_tool_call(name, arguments)
        self._ensure_started()
        result = self._send_request("riskproof/evaluate", {"name": name, "arguments": arguments})
        if result.get("action") not in {"allow", "ask_approval", "block"}:
            raise MCPError(-1, "Invalid riskproof/evaluate response action")
        return result

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        approved: bool = False,
    ) -> dict[str, Any]:
        """Execute a tool through the proxy.

        ``approved=True`` uses the MVP unsigned client-decision extension and is
        rejected unless ``allow_unsigned_client_decisions`` was explicitly set.
        It must only be used with a trusted local proxy launched with
        ``--allow-client-decisions``.
        """
        _validate_tool_call(name, arguments)
        if approved and not self._allow_unsigned_client_decisions:
            raise MCPError(
                -1,
                "Unsigned client approvals are disabled; use a trusted approval integration",
            )
        self._ensure_started()
        params: dict[str, Any] = {"name": name, "arguments": arguments}
        if approved:
            params["_meta"] = {"riskproof_user_decision": "approve"}
        response = self._send_request("tools/call", params)
        if response.get("isError") is True:
            raise MCPError(-1, "Upstream MCP tool returned isError=true")
        return _parse_tool_content(response)

    def _ensure_started(self) -> None:
        if not self._initialized or self._proc is None or self._proc.poll() is not None:
            self.start()

    def _next_request_id(self) -> str:
        with self._lock:
            self._next_id += 1
            return str(self._next_id)

    def _send_request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self._next_request_id()
        event = threading.Event()
        with self._lock:
            self._pending[request_id] = {"event": event, "response": None}
        try:
            self._write_json(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            )
        except Exception:
            with self._lock:
                self._pending.pop(request_id, None)
            raise

        if not event.wait(timeout=self._timeout):
            with self._lock:
                self._pending.pop(request_id, None)
            raise MCPTimeoutError(
                -1,
                f"Request timed out after {self._timeout:g}s: {method} id={request_id}",
            )

        with self._lock:
            entry = self._pending.pop(request_id, None)
        if entry is None or not isinstance(entry.get("response"), dict):
            raise MCPError(-1, f"Missing response for id={request_id}")
        response = entry["response"]
        error = response.get("error")
        if error is not None:
            if not isinstance(error, dict):
                raise MCPError(-1, "Malformed JSON-RPC error response")
            code = error.get("code", -1)
            message = error.get("message", "Unknown MCP error")
            if not isinstance(code, int) or not isinstance(message, str):
                raise MCPError(-1, "Malformed JSON-RPC error response")
            exception = {
                ERR_BLOCKED: MCPBlockedError,
                ERR_REQUIRES_APPROVAL: MCPApprovalRequiredError,
            }.get(code, MCPError)
            raise exception(code, message, error.get("data"))
        result = response.get("result")
        if not isinstance(result, dict):
            raise MCPError(-1, "Malformed JSON-RPC response: result must be an object")
        return result

    def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        self._write_json({"jsonrpc": "2.0", "method": method, "params": params})

    def _write_json(self, value: dict[str, Any]) -> None:
        process = self._proc
        if process is None or process.stdin is None or process.poll() is not None:
            raise MCPError(-1, "MCP subprocess is not running")
        line = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        try:
            with self._write_lock:
                process.stdin.write(line + "\n")
                process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            raise MCPError(-1, "Failed to write to MCP subprocess") from error

    def _read_loop(self) -> None:
        process = self._proc
        if process is None or process.stdout is None:
            return
        try:
            for raw_line in process.stdout:
                if len(raw_line) > MAX_RESPONSE_LINE:
                    self._fail_pending("MCP response line exceeds 4 MB")
                    return
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    logger.debug("Ignored non-JSON MCP stdout: %s", _safe_log(line))
                    continue
                if not isinstance(value, dict) or "id" not in value:
                    continue
                request_id = str(value["id"])
                with self._lock:
                    entry = self._pending.get(request_id)
                    if entry is not None:
                        entry["response"] = value
                        entry["event"].set()
        except (BrokenPipeError, OSError, ValueError) as error:
            logger.debug("MCP stdout reader stopped: %s", error)
        finally:
            self._fail_pending("MCP subprocess closed its stdout")

    def _drain_stderr(self) -> None:
        process = self._proc
        if process is None or process.stderr is None:
            return
        try:
            for line in process.stderr:
                safe = _safe_log(line.rstrip("\n"))
                if self._stderr_handler:
                    self._stderr_handler(safe)
                else:
                    logger.debug("MCP stderr: %s", safe)
        except (OSError, ValueError) as error:
            logger.debug("MCP stderr reader stopped: %s", error)

    def _fail_pending(self, message: str) -> None:
        with self._lock:
            for entry in self._pending.values():
                if entry.get("response") is None:
                    entry["response"] = {
                        "jsonrpc": "2.0",
                        "error": {"code": -1, "message": message},
                    }
                entry["event"].set()

    def _cleanup_process(self) -> None:
        process = self._proc
        self._proc = None
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
        except OSError:
            pass
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            except OSError:
                with contextlib.suppress(OSError):
                    process.kill()


def mcp_tool_to_langchain(tool_def: dict[str, Any]) -> dict[str, Any]:
    name = tool_def.get("name")
    if not isinstance(name, str) or not name:
        raise MCPError(-1, "MCP tool definition is missing a valid name")
    description = tool_def.get("description", "")
    if not isinstance(description, str):
        raise MCPError(-1, f"MCP tool '{name}' description must be a string")
    input_schema = tool_def.get("inputSchema", {})
    if not isinstance(input_schema, dict):
        raise MCPError(-1, f"MCP tool '{name}' inputSchema must be an object")
    input_schema = dict(input_schema)
    input_schema.setdefault("type", "object")
    input_schema.setdefault("properties", {})
    if input_schema["type"] != "object" or not isinstance(input_schema["properties"], dict):
        raise MCPError(-1, f"MCP tool '{name}' inputSchema must describe an object")
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": input_schema,
        },
    }


def format_blocked_message(error: MCPError) -> str:
    """Return the already-redacted proxy error message for trusted display."""
    return error.message


def _minimal_env(extra: Mapping[str, str] | None) -> dict[str, str]:
    environment = {name: os.environ[name] for name in _SAFE_ENV_NAMES if name in os.environ}
    if extra:
        for name, value in extra.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise ValueError("MCP env keys and values must be strings")
            environment[name] = value
    return environment


def _validate_tool_call(name: str, arguments: dict[str, Any]) -> None:
    if not isinstance(name, str) or not name:
        raise ValueError("tool name must be a non-empty string")
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be a dictionary")


def _parse_tool_content(response: dict[str, Any]) -> dict[str, Any]:
    content = response.get("content")
    if content is None:
        return response
    if not isinstance(content, list):
        raise MCPError(-1, "Invalid tools/call response: content must be an array")
    parsed_items: list[Any] = []
    for item in content:
        if not isinstance(item, dict):
            raise MCPError(-1, "Invalid tools/call content item")
        if item.get("type") != "text":
            parsed_items.append(item)
            continue
        text = item.get("text")
        if not isinstance(text, str):
            raise MCPError(-1, "Invalid text content item")
        try:
            parsed_items.append(json.loads(text))
        except json.JSONDecodeError:
            parsed_items.append(text)
    if len(parsed_items) == 1 and isinstance(parsed_items[0], dict):
        return parsed_items[0]
    return {"content": parsed_items}


def _safe_log(value: str) -> str:
    value = re.sub(r"\x1b\][^\x07]*(?:\x07|\x1b\\)", "", value)
    value = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-_])", "", value)
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "[REDACTED_API_KEY]", value)
    value = re.sub(r"\b(Bearer\s+)[A-Za-z0-9._-]+", r"\1[REDACTED]", value, flags=re.I)
    value = re.sub(
        r"\b(api[_-]?key|secret|token|password)(\s*[=:]\s*)[^\s,;]+",
        r"\1\2[REDACTED]",
        value,
        flags=re.I,
    )
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", value)[:4000]
