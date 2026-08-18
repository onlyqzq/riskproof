import { describe, expect, it } from "vitest";
import { ProofStore, newProofId } from "../../src/proof/proof-store.js";
import { redactLogText, redactProof } from "../../src/proof/redaction.js";
import type { SecurityProof } from "../../src/core/types.js";

function proof(overrides: Partial<SecurityProof> = {}): SecurityProof {
  return {
    proofId: "rp_test",
    tool: "send_email",
    capabilities: ["EXTERNAL_ACTION"],
    decision: "deny",
    riskLevel: "critical",
    matchedRules: [{ id: "sensitive_data_external_action", triggeredArgs: ["body"], evidence: ["arg 'body' carries sensitive data"] }],
    provenanceSummary: { body: ["customer_data_1"] },
    taintSummary: { body: ["CUSTOMER_DATA"] },
    toolchain: { sawIngestion: true, sawPrivateAccess: true, sawExternalAction: false, path: ["external_ingestion", "private_access"] },
    reason: "sensitive data is being sent to attacker@external.com",
    timestamp: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("proof redaction", () => {
  it("scrubs api keys from free text", () => {
    expect(redactLogText("key sk-abcdefghijklmnopqrstuvwxyz123456")).not.toContain("sk-abcdefghij");
  });

  it("scrubs bearer tokens", () => {
    expect(redactLogText("Authorization: Bearer abc.def.ghi")).toContain("[REDACTED]");
  });

  it("scrubs key=value secrets", () => {
    expect(redactLogText("api_key=supersecret")).toContain("[REDACTED]");
  });

  it("redacts reason and evidence in a proof", () => {
    const sanitized = redactProof(proof({ reason: "sent api_key=sekret123" }));
    expect(JSON.stringify(sanitized)).not.toContain("sekret123");
  });
});

describe("ProofStore", () => {
  it("returns the proof id on save", () => {
    const store = new ProofStore({ maxRecords: 10 });
    const id = store.save(proof());
    expect(id).toBe("rp_test");
  });

  it("never persists raw arguments or results", () => {
    const store = new ProofStore({ maxRecords: 10 });
    store.save(proof());
    const saved = store.list()[0];
    // A SecurityProof has no raw value field by construction.
    expect(Object.keys(saved)).not.toContain("args");
    expect(Object.keys(saved)).not.toContain("result");
  });

  it("bounds the retained records", () => {
    const store = new ProofStore({ maxRecords: 2 });
    for (let i = 0; i < 5; i += 1) store.save(proof({ proofId: `rp_${i}` }));
    expect(store.list().length).toBe(2);
  });

  it("generates unique proof ids", () => {
    const a = newProofId("send_email", "deny", "2026-01-01T00:00:00.000Z");
    const b = newProofId("send_email", "deny", "2026-01-01T00:00:00.000Z");
    expect(a).not.toBe(b);
    expect(a).toMatch(/^rp_send_email_deny_/);
  });
});
