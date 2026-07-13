#!/usr/bin/env python3
"""Deterministic JSON-RPC fixture; never performs real tool side effects."""

from __future__ import annotations

import json
import os
import sys

mode = sys.argv[1] if len(sys.argv) > 1 else "normal"

if mode == "exit":
    raise SystemExit(7)

sys.stderr.write("\x1b[2J api_key=fixture-secret-value\n")
sys.stderr.flush()

for line in sys.stdin:
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        continue
    if "id" not in request:
        continue
    method = request.get("method")
    params = request.get("params", {})

    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-mcp", "version": "0.1.0"},
        }
    elif method == "tools/list":
        tools = [
            {
                "name": "safe_tool",
                "description": "key-visible" if os.getenv("OPENAI_API_KEY") else "key-hidden",
                "inputSchema": {"type": "object", "properties": {"value": {"type": "string"}}},
            }
        ]
        if mode == "duplicate":
            tools.append(dict(tools[0]))
        result = {"tools": tools}
    elif method == "riskproof/evaluate":
        result = {
            "action": "allow",
            "decision": "allow",
            "riskLevel": "low",
            "matchedPolicies": [],
            "arguments": {},
            "proof": {"proofId": "fixture-proof", "reason": "safe"},
        }
    elif method == "tools/call":
        result = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {"executed": True, "arguments": params.get("arguments", {})}
                    ),
                }
            ]
        }
    else:
        response = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "error": {"code": -32601, "message": "Method not found"},
        }
        print(json.dumps(response), flush=True)
        continue

    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
