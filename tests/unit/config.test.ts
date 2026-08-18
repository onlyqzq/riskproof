import { describe, expect, it } from "vitest";
import z from "@deepseek-ai/schemastery";
import { Config, POLICY_DEFAULTS, PROVENANCE_DEFAULTS, type RiskProofConfig } from "../../src/config.js";

function resolve(raw: unknown): RiskProofConfig {
  return z.resolve(raw, Config, {})[0] as RiskProofConfig;
}

describe("dsh-riskproof Config", () => {
  it("applies every default for an empty config", () => {
    const config = resolve({});
    expect(config.mode).toBe("enforce");
    expect(config.provenance).toEqual(PROVENANCE_DEFAULTS);
    expect(config.taint).toEqual({ enabled: true });
    expect(config.policy.sensitiveExternalAction).toBe("deny");
    expect(config.proof.enabled).toBe(true);
  });

  it("rejects an invalid mode enum", () => {
    expect(() => resolve({ mode: "bogus" })).toThrow();
  });

  it("rejects an invalid policy decision enum", () => {
    expect(() => resolve({ policy: { sensitiveExternalAction: "maybe" } })).toThrow();
  });

  it("rejects a non-positive integer", () => {
    expect(() => resolve({ provenance: { maxEntries: 0 } })).toThrow();
  });

  it("rejects a non-integer number", () => {
    expect(() => resolve({ provenance: { maxEntries: 1.5 } })).toThrow();
  });

  it("preserves a valid override while defaulting siblings", () => {
    const config = resolve({ policy: { sensitiveExternalAction: "ask" } });
    expect(config.policy.sensitiveExternalAction).toBe("ask");
    expect(config.policy.untrustedPrivateAccess).toBe(POLICY_DEFAULTS.untrustedPrivateAccess);
  });

  it("defaults classification.overrides to an empty object", () => {
    const config = resolve({});
    expect(config.classification.overrides).toEqual({});
  });

  it("keeps the schema default for untrustedPrivateAccess", () => {
    expect(POLICY_DEFAULTS.untrustedPrivateAccess).toBe("ask");
  });
});
