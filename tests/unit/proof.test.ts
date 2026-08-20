import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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
    remediations: ["remove sensitive fields"],
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

  it("returns defensive copies and aggregate stats", () => {
    const store = new ProofStore({ maxRecords: 10 });
    const original = proof();
    store.save(original);
    store.save(proof({ proofId: "rp_allow", decision: "allow", riskLevel: "low" }));
    original.matchedRules[0].evidence[0] = "mutated after save";
    const listed = store.list();
    listed[0].reason = "mutated by caller";
    expect(store.list()[0].reason).not.toBe("mutated by caller");
    expect(store.list()[0].matchedRules[0].evidence).not.toContain("mutated after save");
    expect(store.stats()).toEqual({
      retained: 2,
      decisions: { allow: 1, require_approval: 0, deny: 1 },
      risks: { low: 1, medium: 0, high: 0, critical: 1 },
      rules: { sensitive_data_external_action: 2 },
    });
  });

  it("optionally appends redacted JSONL with private file permissions", () => {
    const directory = mkdtempSync(join(tmpdir(), "riskproof-proof-"));
    const file = join(directory, "proofs.jsonl");
    try {
      const store = new ProofStore({ maxRecords: 10, file });
      store.save(proof({ reason: "api_key=supersecret" }));
      const persisted = readFileSync(file, "utf-8");
      expect(persisted).not.toContain("supersecret");
      expect(JSON.parse(persisted).proofId).toBe("rp_test");
      expect(statSync(file).mode & 0o777).toBe(0o600);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("generates unique proof ids", () => {
    const a = newProofId("send_email", "deny", "2026-01-01T00:00:00.000Z");
    const b = newProofId("send_email", "deny", "2026-01-01T00:00:00.000Z");
    expect(a).not.toBe(b);
    expect(a).toMatch(/^rp_send_email_deny_/);
  });

  it("sanitizes tool names embedded in proof ids", () => {
    const id = newProofId("插件/发送 邮件", "deny", "2026-01-01T00:00:00.000Z");
    expect(id).toMatch(/^rp_[A-Za-z0-9._-]+_deny_/);
    expect(id).not.toContain("插件");
  });

  it("validates public file and recent limits", () => {
    expect(() => new ProofStore({ file: "   " })).toThrow(/non-empty path/);
    expect(() => new ProofStore().recent(-1)).toThrow(/non-negative integer/);
  });
});
