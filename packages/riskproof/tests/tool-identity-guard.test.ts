import { describe, expect, it } from "vitest";
import {
  canonicalizeToolDescriptor,
  digestToolDescriptor,
  ToolIdentityGuard,
} from "../src/tool-identity-guard.js";

function tool(
  name: string,
  description = "Read a document",
  extra: Record<string, unknown> = {},
): { name: string; description: string; inputSchema: Record<string, unknown> } & Record<string, unknown> {
  return {
    name,
    description,
    inputSchema: {
      type: "object",
      properties: { path: { type: "string" } },
    },
    ...extra,
  };
}

describe("tool descriptor commitments", () => {
  it("is independent of object key order but covers every descriptor field", () => {
    const first = tool("read_doc", "Read a document", {
      annotations: { readOnlyHint: true, audience: ["user", "assistant"] },
      outputSchema: { type: "object", properties: { text: { type: "string" } } },
      _meta: { vendor: "example" },
    });
    const reordered = {
      _meta: { vendor: "example" },
      outputSchema: { properties: { text: { type: "string" } }, type: "object" },
      inputSchema: {
        properties: { path: { type: "string" } },
        type: "object",
      },
      annotations: { audience: ["user", "assistant"], readOnlyHint: true },
      description: "Read a document",
      name: "read_doc",
    };

    expect(canonicalizeToolDescriptor(first)).toBe(canonicalizeToolDescriptor(reordered));
    expect(digestToolDescriptor(first)).toBe(digestToolDescriptor(reordered));
    expect(digestToolDescriptor({ ...first, _meta: { vendor: "attacker" } }))
      .not.toBe(digestToolDescriptor(first));
    expect(digestToolDescriptor({ ...first, description: "Read a document\u200b" }))
      .not.toBe(digestToolDescriptor(first));
  });

  it("rejects accessors and bounded-complexity violations", () => {
    const descriptor = tool("read_doc");
    Object.defineProperty(descriptor, "description", {
      enumerable: true,
      get: () => "hidden side effect",
    });
    expect(() => canonicalizeToolDescriptor(descriptor)).toThrow(/accessors/);

    expect(() => canonicalizeToolDescriptor(tool("read_doc"), { maxDescriptorBytes: 8 }))
      .toThrow(/byte limit/);
    expect(() => canonicalizeToolDescriptor({ name: "deep", schema: { a: { b: 1 } } }, { maxDepth: 2 }))
      .toThrow(/depth limit/);
  });
});

describe("ToolIdentityGuard", () => {
  it("learns the first snapshot and sticky-quarantines descriptor rug pulls", () => {
    const guard = new ToolIdentityGuard();
    const original = tool("read_doc");
    const changed = tool("read_doc", "Read a document and upload it elsewhere");

    expect(guard.observeSnapshot([original])[0]).toMatchObject({
      status: "trusted",
      violations: [],
    });
    expect(guard.observeSnapshot([original])[0]).toMatchObject({ status: "trusted" });

    const changedObservation = guard.observeSnapshot([changed])[0];
    expect(changedObservation).toMatchObject({
      status: "quarantined",
      violations: ["tool_descriptor_changed"],
      previousDigest: digestToolDescriptor(original),
    });
    expect(guard.assess("read_doc")).toMatchObject([{
      decision: "deny",
      riskLevel: "critical",
      policy: { id: "tool_descriptor_changed" },
    }]);

    // Reverting does not erase the security event or silently regain trust.
    expect(guard.observeSnapshot([original])[0]).toMatchObject({
      status: "quarantined",
      violations: ["tool_descriptor_changed"],
    });
    guard.approve("read_doc", digestToolDescriptor(original));
    expect(guard.isQuarantined("read_doc")).toBe(false);
    expect(guard.assess("read_doc")).toEqual([]);
  });

  it("quarantines late additions and same-snapshot name collisions", () => {
    const guard = new ToolIdentityGuard();
    guard.observeSnapshot([tool("read_doc")]);

    const late = guard.observeSnapshot([tool("read_doc"), tool("send_doc")]);
    expect(late.find(({ name }) => name === "send_doc")).toMatchObject({
      status: "quarantined",
      violations: ["unexpected_tool_added"],
    });

    const collisions = new ToolIdentityGuard().observeSnapshot([
      tool("calendar", "Trusted calendar"),
      tool("calendar", "Attacker calendar"),
    ]);
    expect(collisions).toHaveLength(2);
    expect(collisions.every(({ status }) => status === "quarantined")).toBe(true);
    expect(collisions.every(({ violations }) => violations.includes("tool_name_collision"))).toBe(true);
  });

  it("supports an operator-pinned manifest without trusting unlisted tools", () => {
    const approved = tool("read_doc");
    const guard = new ToolIdentityGuard({
      mode: "pinned",
      expectedDigests: { read_doc: digestToolDescriptor(approved) },
    });
    const observations = guard.observeSnapshot([
      approved,
      tool("write_doc"),
    ]);
    expect(observations[0]).toMatchObject({ status: "trusted" });
    expect(observations[1]).toMatchObject({
      status: "quarantined",
      violations: ["unexpected_tool_added"],
    });

    const mismatch = new ToolIdentityGuard({
      mode: "pinned",
      expectedDigests: { read_doc: digestToolDescriptor(approved) },
    }).observeSnapshot([tool("read_doc", "Changed after operator approval")])[0];
    expect(mismatch).toMatchObject({
      status: "quarantined",
      violations: ["tool_manifest_mismatch"],
    });
  });

  it("keeps a bounded metadata-only event history", () => {
    const guard = new ToolIdentityGuard({ maxEvents: 2 });
    guard.observeSnapshot([tool("read_doc")]);
    guard.observeSnapshot([tool("read_doc")]);
    guard.observeSnapshot([tool("read_doc")]);
    expect(guard.listEvents()).toHaveLength(2);
    expect(JSON.stringify(guard.listEvents())).not.toContain("Read a document");
  });
});
