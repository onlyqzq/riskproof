import { describe, expect, it } from "vitest";
import { ToolSelectionGuard } from "../src/tool-selection-guard.js";

const TOOL_A = "a".repeat(64);
const TOOL_B = "b".repeat(64);
const DESC_A = "c".repeat(64);
const DESC_B = "d".repeat(64);

function guard(options: { complete?: boolean; trustedReason?: boolean } = {}) {
  return new ToolSelectionGuard({
    version: "1",
    policyId: "approved-search-tools",
    requireCompleteSnapshot: options.complete,
    requireTrustedSelectionReason: options.trustedReason,
    candidates: [
      { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A, capabilityClass: "search.read" },
      { toolKeyDigest: TOOL_B, descriptorDigest: DESC_B, capabilityClass: "search.read" },
    ],
  });
}

describe("ToolSelectionGuard", () => {
  it("admits only exact operator-approved ToolKey and descriptor pairs", () => {
    const monitor = guard();
    const admission = monitor.admitSnapshot([
      { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A },
      { toolKeyDigest: "e".repeat(64), descriptorDigest: "f".repeat(64) },
      { toolKeyDigest: TOOL_B, descriptorDigest: "0".repeat(64) },
    ]);
    expect(admission.approvedIndices).toEqual([0]);
    expect(admission.decisions.map(({ policy }) => policy.id)).toEqual([
      "selection_candidate_not_approved",
      "selection_tool_identity_mismatch",
    ]);
  });

  it("allows a selected candidate only after it appeared in the admitted snapshot", () => {
    const monitor = guard();
    expect(monitor.assessSelection({
      selected: { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A },
      requestedCapability: "search.read",
      reason: "capability_match",
    })).toMatchObject([{ policy: { id: "selection_snapshot_not_observed" } }]);

    monitor.admitSnapshot([{ toolKeyDigest: TOOL_A, descriptorDigest: DESC_A }]);
    expect(monitor.assessSelection({
      selected: { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A },
      requestedCapability: "search.read",
      reason: "capability_match",
    })).toMatchObject([{
      decision: "allow",
      policy: { id: "selection_policy_matched" },
    }]);
  });

  it("blocks capability-class substitution and steps up metadata-driven selection", () => {
    const monitor = guard();
    monitor.admitSnapshot([{ toolKeyDigest: TOOL_A, descriptorDigest: DESC_A }]);
    expect(monitor.assessSelection({
      selected: { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A },
      requestedCapability: "payments.write",
      reason: "capability_match",
    })).toMatchObject([{ decision: "deny", policy: { id: "selection_capability_mismatch" } }]);
    expect(monitor.assessSelection({
      selected: { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A },
      requestedCapability: "search.read",
      reason: "model_metadata",
    })).toMatchObject([{ decision: "require_approval", policy: { id: "selection_metadata_influenced" } }]);
  });

  it("can require a complete approved candidate snapshot", () => {
    const admission = guard({ complete: true }).admitSnapshot([
      { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A },
    ]);
    expect(admission.decisions).toMatchObject([{
      policy: { id: "selection_candidate_set_mismatch" },
    }]);
  });

  it("can require an independently trusted selection reason", () => {
    const monitor = guard({ trustedReason: true });
    monitor.admitSnapshot([{ toolKeyDigest: TOOL_A, descriptorDigest: DESC_A }]);
    expect(monitor.assessSelection({
      selected: { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A },
    })).toMatchObject([{ policy: { id: "selection_metadata_influenced" } }]);
  });

  it("keeps bounded metadata-only traces and rejects unsafe inputs", () => {
    const monitor = new ToolSelectionGuard({
      version: "1",
      policyId: "bounded",
      candidates: [{ toolKeyDigest: TOOL_A, descriptorDigest: DESC_A, capabilityClass: "search.read" }],
    }, { maxEvents: 2 });
    monitor.admitSnapshot([{ toolKeyDigest: TOOL_A, descriptorDigest: DESC_A }]);
    monitor.assessSelection({ selected: { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A } });
    monitor.assessSelection({ selected: { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A } });
    expect(monitor.listEvents()).toHaveLength(2);
    expect(JSON.stringify(monitor.listEvents())).not.toContain("search.read");
    expect(() => new ToolSelectionGuard({
      version: "1",
      policyId: "bad",
      candidates: new Proxy([], {}),
    })).toThrow(/array/);
    expect(() => monitor.admitSnapshot([
      { toolKeyDigest: TOOL_A, descriptorDigest: DESC_A, extra: true } as never,
    ])).toThrow(/unsupported/);
  });
});
