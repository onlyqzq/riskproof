import { describe, expect, it } from "vitest";
import z from "@deepseek-ai/schemastery";
import {
  Config,
  POLICY_DEFAULTS,
  POLICY_PRESETS,
  PROVENANCE_DEFAULTS,
  type RiskProofConfig,
} from "../../src/config.js";

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
    expect(config.policy.unlistedExternalAction).toBe("ask");
    expect(config.policy.preset).toBe("balanced");
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

  it("resolves strict and permissive presets", () => {
    expect(resolve({ policy: { preset: "strict" } }).policy.unknownTool).toBe("deny");
    expect(resolve({ policy: { preset: "strict" } }).policy.unlistedExternalAction).toBe("deny");
    expect(resolve({ policy: { preset: "permissive" } }).policy.unknownTool).toBe("allow");
  });

  it("lets an explicit decision override a preset", () => {
    const policy = resolve({ policy: { preset: "strict", unknownTool: "ask" } }).policy;
    expect(policy.unknownTool).toBe("ask");
    expect(policy.sensitivePathMutation).toBe(POLICY_PRESETS.strict.sensitivePathMutation);
  });

  it("normalizes and deduplicates policy domains", () => {
    const policy = resolve({ policy: { internalDomains: ["Acme.COM.", "acme.com"] } }).policy;
    expect(policy.internalDomains).toEqual(["acme.com"]);
  });

  it("rejects URLs and malformed wildcards in domain lists", () => {
    expect(() => resolve({ policy: { blockedDomains: ["https://evil.example"] } })).toThrow();
    expect(() => resolve({ policy: { allowedExternalDomains: ["api.*.example"] } })).toThrow();
  });

  it("accepts operator-sensitive path patterns", () => {
    expect(resolve({ policy: { sensitivePathPatterns: ["**/private/*.asc"] } })
      .policy.sensitivePathPatterns).toEqual(["**/private/*.asc"]);
  });

  it("defaults classification.overrides to an empty object", () => {
    const config = resolve({});
    expect(config.classification.overrides).toEqual({});
  });

  it("keeps the schema default for untrustedPrivateAccess", () => {
    expect(POLICY_DEFAULTS.untrustedPrivateAccess).toBe("ask");
  });

  it("rejects provenance entries larger than the total budget", () => {
    expect(() => resolve({ provenance: { maxEntryBytes: 2_000, maxTotalBytes: 1_000 } })).toThrow();
  });

  it("rejects a chain window larger than retained history", () => {
    expect(() => resolve({ toolchain: { maxEvents: 8, chainWindow: 9 } })).toThrow();
  });

  it("accepts an optional proof JSONL path", () => {
    expect(resolve({ proof: { file: "/tmp/riskproof.jsonl" } }).proof.file).toBe("/tmp/riskproof.jsonl");
  });

  it("rejects blank and non-string proof paths", () => {
    expect(() => resolve({ proof: { file: "  " } })).toThrow();
    expect(() => resolve({ proof: { file: 42 } })).toThrow();
  });
});
