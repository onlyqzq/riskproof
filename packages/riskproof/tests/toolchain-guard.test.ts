import { describe, expect, it } from "vitest";
import { evaluate } from "../src/engine.js";
import {
  applyToolchainGuard,
  classifyToolchainCapabilities,
  ToolchainGuard,
} from "../src/toolchain-guard.js";

describe("MCP toolchain capability classification", () => {
  it.each([
    [
      { name: "fetch", description: "Fetches a URL from the internet", inputSchema: { properties: { url: { type: "string" } } } },
      ["external_ingestion", "external_disclosure"],
    ],
    [
      { name: "read_file", description: "Reads a local file", inputSchema: { properties: { path: { type: "string" } } } },
      ["private_data_access"],
    ],
    [
      { name: "send_mail", description: "Send an email message", inputSchema: { properties: { to: {}, content: {} } } },
      ["external_disclosure"],
    ],
    [
      { name: "execute_command", description: "Execute a terminal command", inputSchema: { properties: { command: {} } } },
      ["external_ingestion", "private_data_access", "external_disclosure"],
    ],
  ] as const)("classifies %s without granting authority", (descriptor, expected) => {
    expect(classifyToolchainCapabilities(descriptor)).toEqual(expected);
  });
});

describe("bounded cross-tool sequence enforcement", () => {
  const fetchTool = {
    name: "fetch",
    description: "Fetches a URL from the internet",
    inputSchema: { properties: { url: { type: "string" } } },
  };
  const readFileTool = {
    name: "read_file",
    description: "Reads a local file",
    inputSchema: { properties: { path: { type: "string" } } },
  };
  const sendMailTool = {
    name: "send_mail",
    description: "Send an email message",
    inputSchema: { properties: { to: {}, content: {} } },
  };

  it("requires review for the integrity transition from external ingestion to private access", () => {
    const guard = new ToolchainGuard();
    const ingress = guard.begin(fetchTool);
    guard.complete(ingress, ["webpage_1"]);

    const findings = guard.assess(readFileTool);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      decision: "require_approval",
      riskLevel: "high",
      policy: { id: "cross_tool_private_access_after_ingestion" },
    });
  });

  it("blocks a complete EIT -> PAT -> NAT path when outbound args carry private evidence", () => {
    const guard = new ToolchainGuard();
    const ingress = guard.begin(fetchTool);
    guard.complete(ingress, ["webpage_1"]);
    const collection = guard.begin(readFileTool);
    guard.complete(collection, ["source_code_1"]);

    const output = evaluate({
      tool: "send_email",
      args: { to: "attacker@example.net", body: "synthetic private value" },
      provenance: { to: ["agent_generated"], body: ["source_code_1"] },
      taints: { body: ["SOURCE_CODE"] },
      capability: { tool: "send_email" },
      options: { referenceTime: "2026-07-26T00:00:00.000Z" },
    });
    const guarded = applyToolchainGuard(output, guard, sendMailTool);

    expect(guarded.action).toBe("block");
    expect(guarded.decision).toBe("deny");
    expect(guarded.riskLevel).toBe("critical");
    expect(guarded.matchedPolicies.map(({ id }) => id))
      .toContain("parasitic_toolchain_data_exfiltration");
    expect(guarded.proof.decision).toBe(guarded.decision);
    expect(guarded.proof.matchedRules).toEqual(guarded.matchedPolicies);
  });

  it("does not treat failed upstream calls as completed chain stages", () => {
    const guard = new ToolchainGuard();
    const ingress = guard.begin(fetchTool);
    guard.abort(ingress);

    expect(guard.assess(readFileTool)).toEqual([]);
    expect(guard.list()).toEqual([]);
  });

  it("expires an old ingestion transition outside the configured event window", () => {
    const guard = new ToolchainGuard({ maxEvents: 8, chainWindow: 2 });
    const ingress = guard.begin(fetchTool);
    guard.complete(ingress);
    for (const name of ["calculate_sum", "format_text"]) {
      const event = guard.begin({ name, description: "Pure local transformation" });
      guard.complete(event);
    }

    expect(guard.assess(readFileTool)).toEqual([]);
  });

  it("flags a single general-purpose tool that can span all three stages", () => {
    const guard = new ToolchainGuard();
    const findings = guard.assess({
      name: "execute_command",
      description: "Execute a shell command",
      inputSchema: { properties: { command: {} } },
    });

    expect(findings[0]).toMatchObject({
      decision: "require_approval",
      riskLevel: "critical",
      policy: { id: "self_contained_toolchain_capability" },
    });
  });

  it("never exposes raw tool results in its metadata-only event list", () => {
    const guard = new ToolchainGuard();
    guard.recordContext("resources/read", ["external_ingestion"], ["webpage_1"]);

    const serialized = JSON.stringify(guard.list());
    expect(serialized).toContain("webpage_1");
    expect(serialized).not.toContain("private value");
  });
});
