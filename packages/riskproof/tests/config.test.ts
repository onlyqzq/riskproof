import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import { RE2JS } from "re2js";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CONFIG_COMPLEXITY_LIMITS,
  loadConfig,
  validateConfig,
} from "../src/config.js";
import { evaluate } from "../src/engine.js";
import type { RiskProofConfig } from "../src/config.js";

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("configuration validation", () => {
  it("applies safe defaults", () => {
    expect(validateConfig({ version: "1" })).toEqual({
      version: "1",
      internalDomains: undefined,
      rules: undefined,
      toolRisk: undefined,
      options: { defaultDecision: "allow" },
    });
  });

  it.each(["0", "2", "latest"])("rejects unsupported schema version %s", (version) => {
    expect(() => validateConfig({ version })).toThrow(/Unsupported config version/);
  });

  it.each([
    ["top-level config", []],
    ["options", { version: "1", options: [] }],
    ["toolRisk", { version: "1", toolRisk: [] }],
    ["custom rule", { version: "1", rules: [[]] }],
  ])("rejects an array where %s must be an object", (_label, config) => {
    expect(() => validateConfig(config)).toThrow(/must be an object/i);
  });

  it("rejects unsupported tool-risk keys", () => {
    expect(() => validateConfig({ version: "1", toolRisk: { shell_exce: "high" } }))
      .toThrow(/unsupported tool/i);
  });

  it("rejects unknown fields instead of silently ignoring security typos", () => {
    expect(() => validateConfig({ version: "1", internalDomain: ["company.example"] }))
      .toThrow(/unsupported field.*internalDomain/i);
    expect(() => validateConfig({
      version: "1",
      options: { defaultDecison: "deny" },
    })).toThrow(/unsupported field.*defaultDecison/i);
    expect(() => validateConfig({
      version: "1",
      rules: [{
        id: "custom_rule",
        description: "test",
        decision: "deny",
        risk: "critical",
        consequence: "test",
        enable: false,
      }],
    })).toThrow(/unsupported field.*enable/i);
  });

  it("rejects unsupported custom-rule tools", () => {
    expect(() => validateConfig({
      version: "1",
      rules: [{
        id: "custom_rule",
        description: "test",
        tool: "file_write",
        decision: "deny",
        risk: "critical",
        consequence: "test",
      }],
    })).toThrow(/must be "\*" or one of/);
  });

  it.each(["low", "medium"])("rejects custom rule risk %s", (risk) => {
    expect(() => validateConfig({
      version: "1",
      rules: [{
        id: "custom_rule",
        description: "test",
        decision: "deny",
        risk,
        consequence: "test",
      }],
    })).toThrow(/risk.*must be one of/i);
  });

  it("rejects built-in and duplicate rule IDs", () => {
    const rule = {
      description: "test",
      decision: "deny",
      risk: "critical",
      consequence: "test",
    };
    expect(() => validateConfig({
      version: "1",
      rules: [{ id: "dangerous_shell_pattern", ...rule }],
    })).toThrow(/reserved/);
    expect(() => validateConfig({
      version: "1",
      rules: [{ id: "custom_rule", ...rule }, { id: "custom_rule", ...rule }],
    })).toThrow(/duplicated/);
  });

  it("rejects invalid and excessively long regular expressions", () => {
    const base = {
      id: "custom_rule",
      description: "test",
      decision: "deny",
      risk: "critical",
      consequence: "test",
    };
    expect(() => validateConfig({ version: "1", rules: [{ ...base, pattern: "[" }] }))
      .toThrow(/not a valid regex/);
    expect(() => validateConfig({ version: "1", rules: [{ ...base, pattern: "x".repeat(2049) }] }))
      .toThrow(/2048/);
  });

  it("uses linear-time RE2 syntax for custom patterns", () => {
    const base = {
      id: "custom_rule",
      description: "test",
      decision: "deny",
      risk: "critical",
      consequence: "test",
    };
    expect(() => validateConfig({ version: "1", rules: [{ ...base, pattern: "(?=secret)" }] }))
      .toThrow(/RE2-compatible/);
    expect(() => validateConfig({ version: "1", rules: [{ ...base, pattern: "(a)\\1" }] }))
      .toThrow(/RE2-compatible/);

    const config = validateConfig({
      version: "1",
      rules: [{ ...base, tool: "shell_exec", field: "command", pattern: "(a+)+$" }],
    });
    const started = performance.now();
    const result = evaluate({
      tool: "shell_exec",
      args: { command: `${"a".repeat(100_000)}!` },
      capability: { tool: "shell_exec" },
    }, config);
    expect(result.action).toBe("allow");
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("validates programmatic config at the public evaluate boundary", () => {
    const input = {
      tool: "shell_exec" as const,
      args: { command: "echo safe" },
      capability: { tool: "shell_exec" as const },
    };
    expect(() => evaluate(input, {
      version: "2",
    })).toThrow(/Unsupported config version/);
    expect(() => evaluate(input, {
      version: "1",
      rules: [{
        id: "invalid_lookahead",
        description: "test",
        tool: "shell_exec",
        pattern: "(?=echo)",
        decision: "deny",
        risk: "critical",
        consequence: "test",
      }],
    })).toThrow(/RE2-compatible/);
  });

  it("snapshots config without invoking a time-of-check/time-of-use pattern getter", () => {
    let getterReads = 0;
    const rule: Record<string, unknown> = {
      id: "deny_delete",
      description: "deny delete commands",
      tool: "shell_exec",
      field: "command",
      decision: "deny",
      risk: "critical",
      consequence: "destructive command",
    };
    Object.defineProperty(rule, "pattern", {
      enumerable: true,
      get() {
        getterReads += 1;
        return getterReads < 4 ? "rm\\s+-rf" : "[";
      },
    });
    const config = { version: "1", rules: [rule] } as unknown as RiskProofConfig;

    expect(() => validateConfig(config)).toThrow(/accessors are not allowed/);
    expect(() => evaluate({
      tool: "shell_exec",
      args: { command: "rm -rf /critical/data" },
      capability: { tool: "shell_exec" },
    }, config)).toThrow(/accessors are not allowed/);
    expect(getterReads).toBe(0);
  });

  it("fails closed if an already-validated custom pattern unexpectedly cannot compile", () => {
    const originalCompile = RE2JS.compile.bind(RE2JS);
    const compile = vi.spyOn(RE2JS, "compile")
      .mockImplementationOnce((pattern) => originalCompile(pattern))
      .mockImplementationOnce(() => {
        throw new Error("synthetic post-validation failure");
      });
    try {
      expect(() => evaluate({
        tool: "shell_exec",
        args: { command: "delete everything" },
        capability: { tool: "shell_exec" },
      }, {
        version: "1",
        rules: [{
          id: "deny_delete",
          description: "deny delete commands",
          tool: "shell_exec",
          field: "command",
          pattern: "delete",
          decision: "deny",
          risk: "critical",
          consequence: "destructive command",
        }],
      })).toThrow(/failed RE2 compilation.*synthetic post-validation failure/);
    } finally {
      compile.mockRestore();
    }
  });

  it.each([
    ["Proxy", new Proxy({ version: "1" }, {})],
    ["Date", { version: "1", options: new Date("2026-07-12T00:00:00.000Z") }],
    ["Map", { version: "1", toolRisk: new Map([["shell_exec", "critical"]]) }],
    ["BigInt", { version: "1", unexpected: 1n }],
    ["Symbol", { version: "1", unexpected: Symbol("unsafe") }],
    ["function", { version: "1", unexpected: () => "unsafe" }],
  ])("rejects non-JSON-compatible %s config values", (_label, config) => {
    expect(() => validateConfig(config)).toThrow();
  });

  it("rejects circular config graphs and prototype-pollution keys", () => {
    const circular: Record<string, unknown> = { version: "1" };
    circular.options = circular;
    expect(() => validateConfig(circular)).toThrow(/circular reference/);

    for (const key of ["__proto__", "constructor", "prototype"]) {
      const polluted = Object.fromEntries([
        ["version", "1"],
        [key, { polluted: true }],
      ]);
      expect(() => validateConfig(polluted)).toThrow(/prototype-pollution key/);
    }
  });

  it("normalizes explicit undefined only for schema-defined optional config fields", () => {
    expect(validateConfig({
      version: "1",
      rules: undefined,
      options: { defaultDecision: undefined },
    })).toEqual({
      version: "1",
      internalDomains: undefined,
      rules: undefined,
      toolRisk: undefined,
      options: { defaultDecision: "allow" },
    });

    expect(() => validateConfig({
      version: "1",
      toolRisk: { shell_exec: undefined },
    })).toThrow(/JSON-compatible/);
  });

  it("enforces deterministic config rule, node, depth, and character budgets", () => {
    const baseRule = {
      description: "test",
      decision: "deny" as const,
      risk: "critical" as const,
      consequence: "test",
    };
    const tooManyRules = Array.from(
      { length: CONFIG_COMPLEXITY_LIMITS.maxRules + 1 },
      (_, index) => ({ id: `rule_${index}`, ...baseRule }),
    );
    expect(() => validateConfig({ version: "1", rules: tooManyRules }))
      .toThrow(/must not contain more than 256 rules/);

    expect(() => validateConfig({
      version: "1",
      rules: [{
        id: "oversized_description",
        ...baseRule,
        description: "x".repeat(CONFIG_COMPLEXITY_LIMITS.maxStringLength + 1),
      }],
    })).toThrow(/maximum string length/);

    expect(() => validateConfig({
      version: "1",
      internalDomains: Array.from(
        { length: CONFIG_COMPLEXITY_LIMITS.maxNodes },
        () => "internal.example",
      ),
    })).toThrow(/maximum node count/);

    expect(() => validateConfig({
      version: "1",
      internalDomains: Array.from(
        { length: 17 },
        () => "x".repeat(CONFIG_COMPLEXITY_LIMITS.maxStringLength),
      ),
    })).toThrow(/maximum total string size/);

    let deep: unknown = "leaf";
    for (let index = 0; index <= CONFIG_COMPLEXITY_LIMITS.maxDepth; index += 1) {
      deep = { child: deep };
    }
    expect(() => validateConfig({ version: "1", unexpected: deep }))
      .toThrow(/maximum depth/);
  });

  it("loads a JSON config from disk and reports parse context", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "riskproof-config-test-"));
    tempDirs.push(dir);
    const validPath = resolve(dir, "valid.json");
    const invalidPath = resolve(dir, "invalid.json");
    writeFileSync(validPath, JSON.stringify({ version: "1", options: { defaultDecision: "deny" } }));
    writeFileSync(invalidPath, "{not-json");
    expect(loadConfig(validPath).options?.defaultDecision).toBe("deny");
    expect(() => loadConfig(invalidPath)).toThrow(/Failed to parse JSON config/);
  });

  it("rejects an oversized config file before parsing it", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "riskproof-config-size-test-"));
    tempDirs.push(dir);
    expect(() => loadConfig(dir)).toThrow(/must refer to a regular file/);

    const path = resolve(dir, "oversized.json");
    writeFileSync(path, "x".repeat(CONFIG_COMPLEXITY_LIMITS.maxFileBytes + 1));

    expect(() => loadConfig(path)).toThrow(/exceeds the 1048576 byte limit/);
  });

  it("loads YAML through the documented optional peer dependency", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "riskproof-yaml-config-test-"));
    tempDirs.push(dir);
    const path = resolve(dir, "config.yaml");
    writeFileSync(path, [
      'version: "1"',
      "internalDomains:",
      "  - company.example",
      "options:",
      "  defaultDecision: deny",
      "",
    ].join("\n"));
    const config = loadConfig(path);
    expect(config.internalDomains).toEqual(["company.example"]);
    expect(config.options?.defaultDecision).toBe("deny");
  });

  it("keeps the published JSON Schema aligned with representative runtime validation", () => {
    const schemaPath = resolve(import.meta.dirname, "../../../riskproof.schema.json");
    const schema = JSON.parse(readFileSync(schemaPath, "utf-8")) as object;
    const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
    const example = JSON.parse(readFileSync(
      resolve(import.meta.dirname, "../../../riskproof.example.json"),
      "utf-8",
    ));
    expect(validateSchema(example), JSON.stringify(validateSchema.errors)).toBe(true);
    expect(() => validateConfig(example)).not.toThrow();
    const cases: Array<{ config: unknown; valid: boolean }> = [
      { config: { version: "1" }, valid: true },
      {
        config: {
          version: "1",
          internalDomains: ["company.example"],
          toolRisk: { shell_exec: "high" },
          options: { defaultDecision: "deny" },
          rules: [{
            id: "block_prod_deploy",
            description: "test",
            tool: "shell_exec",
            field: "command",
            pattern: "deploy.*prod",
            decision: "deny",
            risk: "critical",
            consequence: "test",
            enabled: true,
          }],
        },
        valid: true,
      },
      { config: { version: "2" }, valid: false },
      { config: { version: "1", internalDomain: ["company.example"] }, valid: false },
      { config: { version: "1", toolRisk: { shell_exce: "high" } }, valid: false },
      {
        config: {
          version: "1",
          rules: Array.from(
            { length: CONFIG_COMPLEXITY_LIMITS.maxRules + 1 },
            (_, index) => ({
              id: `schema_rule_${index}`,
              description: "test",
              decision: "deny",
              risk: "critical",
              consequence: "test",
            }),
          ),
        },
        valid: false,
      },
      {
        config: {
          version: "1",
          rules: [{
            id: "oversized_description",
            description: "x".repeat(CONFIG_COMPLEXITY_LIMITS.maxStringLength + 1),
            decision: "deny",
            risk: "critical",
            consequence: "test",
          }],
        },
        valid: false,
      },
      {
        config: {
          version: "1",
          rules: [{
            id: "custom_rule",
            description: "test",
            decision: "deny",
            risk: "low",
            consequence: "test",
          }],
        },
        valid: false,
      },
    ];

    for (const testCase of cases) {
      expect(validateSchema(testCase.config), JSON.stringify(validateSchema.errors)).toBe(testCase.valid);
      if (testCase.valid) expect(() => validateConfig(testCase.config)).not.toThrow();
      else expect(() => validateConfig(testCase.config)).toThrow();
    }
  });
});
