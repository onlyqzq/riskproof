// ============================================================================
// RiskProof — Configuration System
// ============================================================================
// Users can define custom rules, domain lists, and risk levels via JSON or YAML
// without modifying the TypeScript source.
//
// Zero production dependencies. JSON is the primary format; YAML is supported
// via dynamic import of the "yaml" package — a helpful error message is shown
// if the package is not installed.
// ============================================================================

import { readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { extname } from "node:path";
import { types as utilTypes } from "node:util";
import { RE2JS } from "re2js";

// ─── Config Types ─────────────────────────────────────────────────────────────

export interface RiskProofConfig {
  /** Config schema version. Currently "1". */
  version: string;
  /** Domains considered internal (e.g. ["mycompany.com", "subsidiary.io"]).
   *  Merged with per-request internalDomains from EngineOptions. */
  internalDomains?: string[];
  /** User-defined custom rules evaluated after built-in rules. */
  rules?: CustomRule[];
  /** Per-tool risk level override.
   *  Keys are tool names ("send_email", "http_request", "shell_exec").
   *  When set, the engine uses this risk level as a baseline for unmatched calls
   *  instead of the default "low". */
  toolRisk?: Record<string, "low" | "medium" | "high" | "critical">;
  /** Global options. */
  options?: ConfigOptions;
}

export interface ConfigOptions {
  /** Default decision for tool calls that don't match any rule.
   *  Built-in default is "allow"; set to "deny" for a deny-by-default posture. */
  defaultDecision?: "allow" | "deny";
}

export interface CustomRule {
  /** Unique rule identifier (e.g. "block_prod_deploy_from_web"). */
  id: string;
  /** Human-readable description of what this rule detects. */
  description: string;
  /** Restrict to a specific tool name, or "*" / undefined for all tools. */
  tool?: string;
  /** Specific argument field to check. If omitted, all arg values are checked. */
  field?: string;
  /** RE2-compatible regex pattern string to match against argument values. */
  pattern?: string;
  /** Decision when this rule matches. */
  decision: "deny" | "require_approval";
  /** Risk level when this rule matches. */
  risk: "high" | "critical";
  /** Human-readable consequence shown in approval prompts. */
  consequence: string;
  /** Whether this rule is active. Default true. */
  enabled?: boolean;
}

// ─── Validation ───────────────────────────────────────────────────────────────

const VALID_DECISIONS = new Set(["deny", "require_approval"]);
const VALID_RISK_LEVELS = new Set(["low", "medium", "high", "critical"]);
const VALID_CUSTOM_RISK_LEVELS = new Set(["high", "critical"]);
const VALID_TOOLS = new Set(["send_email", "http_request", "shell_exec"]);
const PROTOTYPE_POLLUTION_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const OPTIONAL_CONFIG_KEYS = new Set([
  "$schema", "internalDomains", "rules", "toolRisk", "options",
]);
const OPTIONAL_RULE_KEYS = new Set(["tool", "field", "pattern", "enabled"]);

export const CONFIG_COMPLEXITY_LIMITS = Object.freeze({
  maxRules: 256,
  maxDepth: 16,
  maxNodes: 10_000,
  maxStringLength: 65_536,
  maxTotalCharacters: 1_048_576,
  maxFileBytes: 1_048_576,
});

type ConfigJsonPrimitive = null | boolean | number | string;
type ConfigJsonValue =
  | ConfigJsonPrimitive
  | ConfigJsonValue[]
  | { [key: string]: ConfigJsonValue };

interface ConfigSnapshotState {
  nodes: number;
  characters: number;
  ancestors: Set<object>;
}

const BUILT_IN_RULE_IDS = new Set([
  "invariant_forbidden_tool",
  "invariant_protected_taint_modified",
  "invariant_numeric_range_violation",
  "capability_tool_mismatch",
  "capability_expired",
  "capability_forbidden_taint",
  "capability_recipient_domain_not_allowed",
  "secret_external_send",
  "secret_external_http",
  "dangerous_shell_pattern",
  "high_risk_tool_requires_capability",
  "capability_provenance_not_allowed",
  "customer_data_external_send",
  "sensitive_data_external_http",
  "untrusted_influenced_shell",
  "untrusted_provenance_email_to",
  "untrusted_provenance_shell",
  "default_deny_config",
]);

function rejectUnknownKeys(
  obj: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  context: string,
): void {
  const unknown = Object.keys(obj).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new Error(`${context} contains unsupported field(s): ${unknown.join(", ")}`);
  }
}

export function validateConfig(raw: unknown): RiskProofConfig {
  if (raw === null || raw === undefined) {
    throw new Error("Config must not be null or undefined");
  }
  const obj = snapshotConfig(raw);
  rejectUnknownKeys(
    obj,
    new Set(["$schema", "version", "internalDomains", "rules", "toolRisk", "options"]),
    "Config",
  );
  if (obj.$schema !== undefined && typeof obj.$schema !== "string") {
    throw new Error("Config '$schema' must be a string when provided");
  }

  // version (required)
  if (typeof obj.version !== "string" || obj.version.length === 0) {
    throw new Error("Config must have a non-empty 'version' string (e.g. \"1\")");
  }
  if (obj.version !== "1") {
    throw new Error(`Unsupported config version '${obj.version}'. Supported version: "1"`);
  }

  // internalDomains (optional)
  if (obj.internalDomains !== undefined) {
    if (!Array.isArray(obj.internalDomains)) {
      throw new Error("Config 'internalDomains' must be an array of strings");
    }
    for (let i = 0; i < obj.internalDomains.length; i++) {
      if (typeof obj.internalDomains[i] !== "string") {
        throw new Error(`Config 'internalDomains[${i}]' must be a string, got ${typeof obj.internalDomains[i]}`);
      }
    }
  }

  // toolRisk (optional)
  if (obj.toolRisk !== undefined) {
    if (typeof obj.toolRisk !== "object" || obj.toolRisk === null || Array.isArray(obj.toolRisk)) {
      throw new Error("Config 'toolRisk' must be an object mapping tool names to risk levels");
    }
    for (const [tool, level] of Object.entries(obj.toolRisk as Record<string, unknown>)) {
      if (!VALID_TOOLS.has(tool)) {
        throw new Error(
          `Config 'toolRisk.${tool}' uses an unsupported tool. ` +
          `Supported tools: ${[...VALID_TOOLS].join(", ")}`,
        );
      }
      if (typeof level !== "string" || !VALID_RISK_LEVELS.has(level)) {
        throw new Error(
          `Config 'toolRisk.${tool}' must be one of: ${[...VALID_RISK_LEVELS].join(", ")}, got '${level}'`,
        );
      }
    }
  }

  // options (optional)
  if (obj.options !== undefined) {
    if (typeof obj.options !== "object" || obj.options === null || Array.isArray(obj.options)) {
      throw new Error("Config 'options' must be an object");
    }
    const opts = obj.options as Record<string, unknown>;
    rejectUnknownKeys(opts, new Set(["defaultDecision"]), "Config 'options'");
    if (opts.defaultDecision !== undefined) {
      if (opts.defaultDecision !== "allow" && opts.defaultDecision !== "deny") {
        throw new Error(`Config 'options.defaultDecision' must be "allow" or "deny", got '${opts.defaultDecision}'`);
      }
    }
  }

  // rules (optional)
  if (obj.rules !== undefined) {
    if (!Array.isArray(obj.rules)) {
      throw new Error("Config 'rules' must be an array");
    }
    if (obj.rules.length > CONFIG_COMPLEXITY_LIMITS.maxRules) {
      throw new Error(
        `Config 'rules' must not contain more than ${CONFIG_COMPLEXITY_LIMITS.maxRules} rules`,
      );
    }
    const seenRuleIds = new Set<string>();
    for (let i = 0; i < obj.rules.length; i++) {
      const rule = obj.rules[i];
      if (typeof rule !== "object" || rule === null || Array.isArray(rule)) {
        throw new Error(`Config 'rules[${i}]' must be an object`);
      }
      const r = rule as Record<string, unknown>;
      rejectUnknownKeys(
        r,
        new Set([
          "id",
          "description",
          "tool",
          "field",
          "pattern",
          "decision",
          "risk",
          "consequence",
          "enabled",
        ]),
        `Config 'rules[${i}]'`,
      );

      if (typeof r.id !== "string" || r.id.length === 0) {
        throw new Error(`Config 'rules[${i}].id' must be a non-empty string`);
      }
      if (!/^[a-zA-Z][a-zA-Z0-9_-]{0,127}$/.test(r.id)) {
        throw new Error(
          `Config 'rules[${i}].id' must start with a letter and contain only letters, numbers, '_' or '-' (max 128 characters)`,
        );
      }
      if (seenRuleIds.has(r.id)) {
        throw new Error(`Config rule id '${r.id}' is duplicated`);
      }
      if (BUILT_IN_RULE_IDS.has(r.id)) {
        throw new Error(`Config rule id '${r.id}' is reserved by a built-in rule`);
      }
      seenRuleIds.add(r.id);

      if (typeof r.description !== "string") {
        throw new Error(`Config 'rules[${i}].description' must be a string`);
      }

      if (r.tool !== undefined && typeof r.tool !== "string") {
        throw new Error(`Config 'rules[${i}].tool' must be a string (tool name) or omitted`);
      }
      if (typeof r.tool === "string" && r.tool !== "*" && !VALID_TOOLS.has(r.tool)) {
        throw new Error(
          `Config 'rules[${i}].tool' must be "*" or one of: ${[...VALID_TOOLS].join(", ")}`,
        );
      }

      if (r.field !== undefined && typeof r.field !== "string") {
        throw new Error(`Config 'rules[${i}].field' must be a string (argument field name) or omitted`);
      }

      if (r.pattern !== undefined && typeof r.pattern !== "string") {
        throw new Error(`Config 'rules[${i}].pattern' must be a string (regex pattern) or omitted`);
      }

      // Compile against RE2 syntax at load time. RE2 matching is linear-time
      // and does not support backreferences/lookaround that require backtracking.
      if (typeof r.pattern === "string") {
        if (r.pattern.length > 2048) {
          throw new Error(`Config 'rules[${i}].pattern' must not exceed 2048 characters`);
        }
        try {
          RE2JS.compile(r.pattern);
        } catch (e) {
          throw new Error(
            `Config 'rules[${i}].pattern' is not a valid regex under RE2-compatible syntax: ` +
            `${e instanceof Error ? e.message : e}`,
          );
        }
      }

      if (typeof r.decision !== "string" || !VALID_DECISIONS.has(r.decision)) {
        throw new Error(
          `Config 'rules[${i}].decision' must be one of: ${[...VALID_DECISIONS].join(", ")}, got '${r.decision}'`,
        );
      }

      if (typeof r.risk !== "string" || !VALID_CUSTOM_RISK_LEVELS.has(r.risk)) {
        throw new Error(
          `Config 'rules[${i}].risk' must be one of: ${[...VALID_CUSTOM_RISK_LEVELS].join(", ")}, got '${r.risk}'`,
        );
      }

      if (typeof r.consequence !== "string" || r.consequence.length === 0) {
        throw new Error(`Config 'rules[${i}].consequence' must be a non-empty string`);
      }

      if (r.enabled !== undefined && typeof r.enabled !== "boolean") {
        throw new Error(`Config 'rules[${i}].enabled' must be a boolean or omitted`);
      }
    }
  }

  // Return a fully-defaulted config
  return {
    version: obj.version,
    internalDomains: obj.internalDomains as string[] | undefined,
    rules: (obj.rules as CustomRule[] | undefined)?.map((r) => ({
      ...r,
      enabled: r.enabled !== false, // default true
      tool: r.tool ?? "*",
    })),
    toolRisk: obj.toolRisk as RiskProofConfig["toolRisk"],
    options: {
      defaultDecision: ((obj.options as Record<string, unknown> | undefined)?.defaultDecision as "allow" | "deny" | undefined) ?? "allow",
    },
  };
}

function snapshotConfig(raw: unknown): Record<string, unknown> {
  const state: ConfigSnapshotState = {
    nodes: 0,
    characters: 0,
    ancestors: new Set<object>(),
  };
  const snapshot = cloneConfigValue(raw, "Config", 0, state);
  if (typeof snapshot !== "object" || snapshot === null || Array.isArray(snapshot)) {
    throw new Error(`Config must be an object, got ${Array.isArray(snapshot) ? "array" : typeof snapshot}`);
  }
  return snapshot as Record<string, unknown>;
}

function cloneConfigValue(
  value: unknown,
  path: string,
  depth: number,
  state: ConfigSnapshotState,
): ConfigJsonValue {
  state.nodes += 1;
  if (state.nodes > CONFIG_COMPLEXITY_LIMITS.maxNodes) {
    throw new Error(`Config exceeds maximum node count of ${CONFIG_COMPLEXITY_LIMITS.maxNodes}`);
  }

  if (value === null) return null;
  switch (typeof value) {
    case "string":
      accountConfigCharacters(value, path, state);
      return value;
    case "boolean":
      return value;
    case "number":
      if (!Number.isFinite(value)) throw new Error(`${path} must be a finite JSON number`);
      return value;
    case "object":
      return cloneConfigContainer(value, path, depth, state);
    default:
      throw new Error(`${path} must contain only JSON-compatible values; got ${typeof value}`);
  }
}

function cloneConfigContainer(
  value: object,
  path: string,
  depth: number,
  state: ConfigSnapshotState,
): ConfigJsonValue[] | { [key: string]: ConfigJsonValue } {
  if (utilTypes.isProxy(value)) {
    throw new Error(`${path} must not be a Proxy`);
  }
  if (depth > CONFIG_COMPLEXITY_LIMITS.maxDepth) {
    throw new Error(`Config exceeds maximum depth of ${CONFIG_COMPLEXITY_LIMITS.maxDepth}`);
  }
  if (state.ancestors.has(value)) {
    throw new Error(`${path} contains a circular reference`);
  }

  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return cloneConfigArray(value as unknown[], path, depth, state);
    }
    return cloneConfigObject(value, path, depth, state);
  } finally {
    state.ancestors.delete(value);
  }
}

function cloneConfigArray(
  value: unknown[],
  path: string,
  depth: number,
  state: ConfigSnapshotState,
): ConfigJsonValue[] {
  const keys = configOwnKeys(value, path);
  for (const key of keys) {
    if (key === "length") continue;
    if (typeof key !== "string" || !isArrayIndex(key)) {
      throw new Error(`${path} must be a plain JSON array without extra properties`);
    }
  }

  const lengthDescriptor = configOwnProperty(value, "length", path);
  const length = lengthDescriptor?.value;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) {
    throw new Error(`${path} has an invalid array length`);
  }
  if (state.nodes + length > CONFIG_COMPLEXITY_LIMITS.maxNodes) {
    throw new Error(`Config exceeds maximum node count of ${CONFIG_COMPLEXITY_LIMITS.maxNodes}`);
  }

  const result: ConfigJsonValue[] = [];
  for (let index = 0; index < length; index += 1) {
    const itemPath = `${path}[${index}]`;
    const descriptor = configOwnProperty(value, String(index), itemPath);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${path} must be a dense JSON array with data properties`);
    }
    result.push(cloneConfigValue(descriptor.value, itemPath, depth + 1, state));
  }
  return result;
}

function cloneConfigObject(
  value: object,
  path: string,
  depth: number,
  state: ConfigSnapshotState,
): { [key: string]: ConfigJsonValue } {
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
  } catch {
    throw new Error(`${path} cannot be inspected safely`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${path} must contain only plain JSON objects and arrays`);
  }

  const keys = configOwnKeys(value, path);
  if (state.nodes + keys.length > CONFIG_COMPLEXITY_LIMITS.maxNodes) {
    throw new Error(`Config exceeds maximum node count of ${CONFIG_COMPLEXITY_LIMITS.maxNodes}`);
  }

  const entries: Array<[string, ConfigJsonValue]> = [];
  for (const key of keys) {
    if (typeof key !== "string") {
      throw new Error(`${path} must not contain symbol-keyed properties`);
    }
    if (PROTOTYPE_POLLUTION_KEYS.has(key)) {
      throw new Error(`${path} contains forbidden prototype-pollution key '${key}'`);
    }
    accountConfigCharacters(key, `${path} object key`, state);
    const childPath = configPropertyPath(path, key);
    const descriptor = configOwnProperty(value, key, childPath);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error(`${childPath} must be an enumerable data property; accessors are not allowed`);
    }
    if (descriptor.value === undefined && isOptionalConfigProperty(path, key)) continue;
    entries.push([key, cloneConfigValue(descriptor.value, childPath, depth + 1, state)]);
  }
  return Object.fromEntries(entries);
}

function accountConfigCharacters(
  value: string,
  path: string,
  state: ConfigSnapshotState,
): void {
  if (value.length > CONFIG_COMPLEXITY_LIMITS.maxStringLength) {
    throw new Error(
      `${path} exceeds maximum string length of ` +
      `${CONFIG_COMPLEXITY_LIMITS.maxStringLength} characters`,
    );
  }
  state.characters += value.length;
  if (state.characters > CONFIG_COMPLEXITY_LIMITS.maxTotalCharacters) {
    throw new Error(
      `Config exceeds maximum total string size of ` +
      `${CONFIG_COMPLEXITY_LIMITS.maxTotalCharacters} characters`,
    );
  }
}

function isOptionalConfigProperty(parentPath: string, key: string): boolean {
  if (parentPath === "Config") return OPTIONAL_CONFIG_KEYS.has(key);
  if (parentPath === "Config.options") return key === "defaultDecision";
  if (/^Config\.rules\[\d+\]$/.test(parentPath)) return OPTIONAL_RULE_KEYS.has(key);
  return false;
}

function configOwnKeys(value: object, path: string): Array<string | symbol> {
  try {
    return Reflect.ownKeys(value);
  } catch {
    throw new Error(`${path} cannot be inspected safely`);
  }
}

function configOwnProperty(
  value: object,
  key: PropertyKey,
  path: string,
): PropertyDescriptor | undefined {
  try {
    return Object.getOwnPropertyDescriptor(value, key);
  } catch {
    throw new Error(`${path} cannot be inspected safely`);
  }
}

function isArrayIndex(value: string): boolean {
  if (!/^(0|[1-9]\d*)$/.test(value)) return false;
  const index = Number(value);
  return Number.isSafeInteger(index) && index >= 0 && index < 4_294_967_295;
}

function configPropertyPath(parent: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)
    ? `${parent}.${key}`
    : `${parent}[${JSON.stringify(key.slice(0, 64))}]`;
}

// ─── Loader ───────────────────────────────────────────────────────────────────

/**
 * Load and validate a RiskProof config from a file path.
 *
 * Supports `.json` (native) and `.yaml`/`.yml` files.
 * For YAML, the `yaml` npm package is required — a helpful error message
 * is shown if it is not installed.
 */
export function loadConfig(path: string): RiskProofConfig {
  const ext = extname(path).toLowerCase();
  const file = statSync(path);
  if (!file.isFile()) {
    throw new Error(`Config path '${path}' must refer to a regular file`);
  }
  const fileBytes = file.size;
  if (fileBytes > CONFIG_COMPLEXITY_LIMITS.maxFileBytes) {
    throw new Error(
      `Config file at '${path}' exceeds the ${CONFIG_COMPLEXITY_LIMITS.maxFileBytes} byte limit`,
    );
  }
  const raw = readFileSync(path, "utf-8");
  // Recheck after reading so a file changed between stat and read cannot bypass
  // the bound. Buffer.byteLength measures the encoded bytes, not UTF-16 units.
  if (Buffer.byteLength(raw, "utf-8") > CONFIG_COMPLEXITY_LIMITS.maxFileBytes) {
    throw new Error(
      `Config file at '${path}' exceeds the ${CONFIG_COMPLEXITY_LIMITS.maxFileBytes} byte limit`,
    );
  }

  let parsed: unknown;

  if (ext === ".json") {
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      throw new Error(`Failed to parse JSON config at '${path}': ${e instanceof Error ? e.message : e}`);
    }
  } else if (ext === ".yaml" || ext === ".yml") {
    // Dynamic import for optional YAML support — zero production dependencies
    try {
      // Use a require-style dynamic path so bundlers don't force yaml as a dep
      const yamlModule = requireYaml();
      parsed = yamlModule.parse(raw);
    } catch (e) {
      if (isModuleNotFound(e)) {
        throw new Error(
          `YAML config detected but the 'yaml' package is not installed.\n` +
          `Run: npm install yaml\n` +
          `Or use a JSON config file (.json) instead.`,
        );
      }
      throw new Error(`Failed to parse YAML config at '${path}': ${e instanceof Error ? e.message : e}`);
    }
  } else {
    throw new Error(
      `Unsupported config file extension '${ext}'. Use .json, .yaml, or .yml.`,
    );
  }

  try {
    return validateConfig(parsed);
  } catch (e) {
    throw new Error(`Invalid config at '${path}': ${e instanceof Error ? e.message : e}`);
  }
}

/**
 * Attempt to dynamically load the "yaml" package.
 * Uses a function wrapper so bundlers see this as a dynamic require.
 */
function requireYaml(): { parse(text: string): unknown } {
  const require = createRequire(import.meta.url);
  return require("yaml") as { parse(text: string): unknown };
}

function isModuleNotFound(e: unknown): boolean {
  if (e instanceof Error) {
    const msg = e.message.toLowerCase();
    return msg.includes("cannot find module") ||
      msg.includes("module not found") ||
      (e as NodeJS.ErrnoException).code === "ERR_MODULE_NOT_FOUND" ||
      (e as NodeJS.ErrnoException).code === "MODULE_NOT_FOUND";
  }
  return false;
}
