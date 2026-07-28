import { describe, expect, it } from "vitest";
import { OpaPolicyEngine, evaluateWithOpa } from "../src/opa-policy.js";
import type { EngineInput } from "../src/types.js";

const INPUT: EngineInput = {
  tool: "shell_exec",
  args: { command: "deploy production" },
  capability: { tool: "shell_exec" },
  options: { referenceTime: "2026-07-17T00:00:00.000Z" },
};

describe("OPA/Rego policy-as-code", () => {
  it("monotonically merges valid opa-wasm decisions and regenerates a consistent proof", () => {
    const policy = new OpaPolicyEngine({
      evaluate: () => [{
        result: {
          matches: [{
            id: "deny_production_deploy",
            decision: "deny",
            riskLevel: "critical",
            triggeredArgs: ["command"],
            evidence: ["production deployment requires a release controller"],
            reason: "Production deployment is not authorized by this workflow",
          }],
        },
      }],
    }, { id: "release_guard" });

    const result = evaluateWithOpa(INPUT, [policy]);
    expect(result.action).toBe("block");
    expect(result.riskLevel).toBe("critical");
    expect(result.matchedPolicies.map(({ id }) => id)).toContain(
      "opa_release_guard_deny_production_deploy",
    );
    expect(result.proof.matchedRules).toEqual(result.matchedPolicies);
    expect(result.proof.evidence).toEqual(result.matchedPolicies.flatMap(({ evidence }) => evidence));
  });

  it("fails closed when a module returns an invalid contract", () => {
    const policy = new OpaPolicyEngine({ evaluate: () => [{ result: true }] }, { id: "broken" });
    const result = evaluateWithOpa(INPUT, [policy]);
    expect(result.decision).toBe("deny");
    expect(result.matchedPolicies.map(({ id }) => id)).toContain("opa_broken_evaluation_failure");
  });

  it("can throw policy contract errors explicitly in development mode", () => {
    const policy = new OpaPolicyEngine(
      { evaluate: () => [{ result: { id: "bad", decision: "permit", risk: "low" } }] },
      { id: "broken", failureMode: "throw" },
    );
    expect(() => evaluateWithOpa(INPUT, [policy])).toThrow(/OPA policy 'broken' evaluation failed/);
  });

  it("rejects unknown triggered arguments and excessive result sets", () => {
    const unknownArg = new OpaPolicyEngine({
      evaluate: () => [{ result: {
        id: "bad_arg",
        decision: "deny",
        risk: "critical",
        triggeredArgs: ["missing"],
      } }],
    }, { id: "strict" });
    expect(evaluateWithOpa(INPUT, [unknownArg]).matchedPolicies.map(({ id }) => id))
      .toContain("opa_strict_evaluation_failure");

    const oversized = new OpaPolicyEngine({
      evaluate: () => [{ result: { matches: Array.from({ length: 129 }, (_, id) => ({
        id: `rule_${id}`,
        decision: "deny",
        risk: "critical",
      })) } }],
    }, { id: "bounded" });
    expect(evaluateWithOpa(INPUT, [oversized]).matchedPolicies.map(({ id }) => id))
      .toContain("opa_bounded_evaluation_failure");
  });

  it("validates module identifiers before loading", () => {
    expect(() => new OpaPolicyEngine({ evaluate: () => [] }, { id: "../escape" })).toThrow(/policy id/);
  });

  it("uses the official WASM loader and rejects a non-OPA binary", async () => {
    await expect(OpaPolicyEngine.load(new Uint8Array([0, 97, 115, 109]), { id: "invalid" }))
      .rejects.toBeDefined();
  });

  it("redacts sensitive argument values echoed by a policy module", () => {
    const secret = "sk-abcdefghijklmnopqrstuvwxyz123456";
    const policy = new OpaPolicyEngine({
      evaluate: () => [{ result: {
        id: "echo",
        decision: "deny",
        risk: "critical",
        evidence: [`policy observed ${secret}`],
        reason: `do not expose ${secret}`,
      } }],
    }, { id: "redactor" });
    const result = evaluateWithOpa({
      tool: "http_request",
      args: { url: "https://outside.example", body: secret },
      capability: { tool: "http_request" },
      options: { referenceTime: "2026-07-17T00:00:00.000Z" },
    }, [policy]);
    expect(JSON.stringify(result.proof)).not.toContain(secret);
    expect(JSON.stringify(result.proof)).toContain("[REDACTED_");
  });
});
