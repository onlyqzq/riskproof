import { describe, expect, it } from "vitest";
import { ToolchainGuard } from "../../src/toolchain/guard.js";
import { RuntimeState } from "../../src/dsh/runtime-state.js";
import type { RiskProofConfig } from "../../src/config.js";
import { POLICY_DEFAULTS, PROOF_DEFAULTS, PROVENANCE_DEFAULTS, TOOLCHAIN_DEFAULTS } from "../../src/config.js";

function config(overrides: Partial<RiskProofConfig> = {}): RiskProofConfig {
  return {
    mode: "enforce",
    provenance: { ...PROVENANCE_DEFAULTS },
    taint: { enabled: true },
    toolchain: { ...TOOLCHAIN_DEFAULTS },
    classification: { overrides: {} },
    policy: { ...POLICY_DEFAULTS },
    proof: { ...PROOF_DEFAULTS },
    ...overrides,
  };
}

describe("ToolchainGuard", () => {
  it("reports no state for an empty history", () => {
    const guard = new ToolchainGuard();
    expect(guard.snapshot().sawIngestion).toBe(false);
    expect(guard.snapshot().sawPrivateAccess).toBe(false);
    expect(guard.snapshot().sawExternalAction).toBe(false);
  });

  it("observes EIT then PAT", () => {
    const guard = new ToolchainGuard();
    guard.recordEvent("web_fetch", ["EXTERNAL_INGESTION"], ["webpage_1"]);
    expect(guard.snapshot().sawIngestion).toBe(true);

    guard.recordEvent("database_query", ["PRIVATE_ACCESS"], ["customer_data_1"]);
    expect(guard.snapshot().sawPrivateAccess).toBe(true);
    expect(guard.snapshot().sawIngestion).toBe(true);
    expect(guard.snapshot().sawIngestionThenPrivateAccess).toBe(true);
  });

  it("does not confuse PAT then EIT with the protected order", () => {
    const guard = new ToolchainGuard();
    guard.recordEvent("database_query", ["PRIVATE_ACCESS"]);
    guard.recordEvent("web_fetch", ["EXTERNAL_INGESTION"]);
    const state = guard.snapshot();
    expect(state.sawIngestion).toBe(true);
    expect(state.sawPrivateAccess).toBe(true);
    expect(state.sawIngestionThenPrivateAccess).toBe(false);
    expect(state.path).toEqual(["private_access", "external_ingestion"]);
  });

  it("requires separate events for an ingestion-to-private transition", () => {
    const guard = new ToolchainGuard();
    guard.recordEvent("combined_reader", ["EXTERNAL_INGESTION", "PRIVATE_ACCESS"]);
    expect(guard.snapshot().sawIngestionThenPrivateAccess).toBe(false);
  });

  it("observes the full EIT → PAT → NAT path", () => {
    const guard = new ToolchainGuard();
    guard.recordEvent("web_fetch", ["EXTERNAL_INGESTION"]);
    guard.recordEvent("database_query", ["PRIVATE_ACCESS"]);
    guard.recordEvent("send_email", ["EXTERNAL_ACTION"]);
    const state = guard.snapshot();
    expect(state.sawIngestion).toBe(true);
    expect(state.sawPrivateAccess).toBe(true);
    expect(state.sawExternalAction).toBe(true);
    expect(state.path).toContain("external_ingestion");
    expect(state.path).toContain("private_access");
    expect(state.path).toContain("external_action");
  });

  it("bounds the retained event history", () => {
    const guard = new ToolchainGuard({ maxEvents: 2, chainWindow: 2 });
    for (let i = 0; i < 10; i += 1) guard.recordEvent("web_fetch", ["EXTERNAL_INGESTION"]);
    expect(guard.list().length).toBe(2);
  });
});

describe("RuntimeState session isolation", () => {
  it("keeps session A's toolchain out of session B", () => {
    const state = new RuntimeState(config());
    state.get("session-A").guard.recordEvent("web_fetch", ["EXTERNAL_INGESTION"]);
    expect(state.get("session-A").guard.snapshot().sawIngestion).toBe(true);
    expect(state.get("session-B").guard.snapshot().sawIngestion).toBe(false);
  });

  it("keeps per-session provenance trackers independent", () => {
    const state = new RuntimeState(config());
    state.get("session-A").tracker.record("customer_data", "CUST-1");
    const mapping = state.get("session-B").mapper.mapArguments({ body: "CUST-1" });
    expect(mapping.provenance.body).toEqual(["agent_generated"]);
  });

  it("clears state on disposal", () => {
    const state = new RuntimeState(config());
    state.get("session-A").guard.recordEvent("web_fetch", ["EXTERNAL_INGESTION"]);
    state.dispose("session-A");
    expect(state.get("session-A").guard.snapshot().sawIngestion).toBe(false);
  });
});
