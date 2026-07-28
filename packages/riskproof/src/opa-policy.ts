// ============================================================================
// RiskProof — Open Policy Agent / Rego WebAssembly policy-as-code integration
// ============================================================================

import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { loadPolicy, type LoadedPolicy } from "@open-policy-agent/opa-wasm";
import { evaluate, mergePolicyDecisions, type AdditionalPolicyDecision } from "./engine.js";
import { parseEngineInput } from "./validation.js";
import type { RiskProofConfig } from "./config.js";
import type { Decision, EngineInput, EngineOutput, RiskLevel } from "./types.js";
import { redactLogText, sensitiveTaints } from "./redaction.js";

export interface OpaPolicyOptions {
  /** Stable module identifier used to namespace proof rule IDs. */
  id: string;
  /** OPA WASM entrypoint name or numeric ID. Defaults to the compiled default. */
  entrypoint?: string | number;
  /** Optional static OPA data document. */
  data?: object;
  /** Runtime/contract errors deny by default; "throw" is useful during development. */
  failureMode?: "deny" | "throw";
}

export interface OpaPolicyMatch {
  id: string;
  decision: Decision;
  riskLevel: RiskLevel;
  triggeredArgs?: string[];
  evidence?: string[];
  reason?: string;
}

interface EvaluatablePolicy {
  evaluate(input: unknown, entrypoint?: string | number): unknown;
  setData?(data: object): void;
}

const DECISIONS = new Set<Decision>(["allow", "require_approval", "deny"]);
const RISKS = new Set<RiskLevel>(["low", "medium", "high", "critical"]);
const MAX_OPA_RESULT_BYTES = 1024 * 1024;
const MAX_OPA_MATCHES = 128;
const MAX_OPA_STRING = 16 * 1024;
export const OPA_MAX_WASM_BYTES = 32 * 1024 * 1024;

export class OpaPolicyEngine {
  readonly id: string;
  private readonly policy: EvaluatablePolicy;
  private readonly entrypoint?: string | number;
  private readonly failureMode: "deny" | "throw";

  /** Prefer load()/loadFile(); public construction also supports policy adapters and tests. */
  constructor(policy: EvaluatablePolicy, options: OpaPolicyOptions) {
    if (typeof policy !== "object" || policy === null || typeof policy.evaluate !== "function") {
      throw new TypeError("OPA policy adapter must provide an evaluate function");
    }
    if (typeof options !== "object" || options === null) {
      throw new TypeError("OPA policy options must be an object");
    }
    const unknownOptions = Object.keys(options).filter((key) =>
      !["id", "entrypoint", "data", "failureMode"].includes(key));
    if (unknownOptions.length > 0) throw new TypeError("OPA policy options contain unsupported fields");
    if (!/^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(options.id)) {
      throw new TypeError("OPA policy id must start with a letter and contain only letters, numbers, '_' or '-'");
    }
    if (options.entrypoint !== undefined) {
      const validName = typeof options.entrypoint === "string" && options.entrypoint.length > 0;
      const validId = typeof options.entrypoint === "number" &&
        Number.isSafeInteger(options.entrypoint) && options.entrypoint >= 0;
      if (!validName && !validId) {
        throw new TypeError("OPA policy entrypoint must be a non-empty string or non-negative integer");
      }
    }
    if (options.failureMode !== undefined && options.failureMode !== "deny" && options.failureMode !== "throw") {
      throw new TypeError("OPA policy failureMode must be 'deny' or 'throw'");
    }
    this.id = options.id;
    this.policy = policy;
    this.entrypoint = options.entrypoint;
    this.failureMode = options.failureMode ?? "deny";
    if (options.data !== undefined) {
      if (!policy.setData) throw new TypeError("OPA policy adapter does not support a data document");
      policy.setData(options.data);
    }
  }

  static async load(wasm: BufferSource | WebAssembly.Module, options: OpaPolicyOptions): Promise<OpaPolicyEngine> {
    if (!(wasm instanceof WebAssembly.Module)) {
      const byteLength = wasm.byteLength;
      if (byteLength > OPA_MAX_WASM_BYTES) {
        throw new RangeError(`OPA WASM policy exceeds ${OPA_MAX_WASM_BYTES} bytes`);
      }
    }
    const policy: LoadedPolicy = await loadPolicy(wasm);
    return new OpaPolicyEngine(policy, options);
  }

  static async loadFile(path: string, options: OpaPolicyOptions): Promise<OpaPolicyEngine> {
    const resolved = resolve(path);
    const file = await stat(resolved);
    if (!file.isFile()) throw new TypeError("OPA policy path must refer to a regular file");
    if (file.size > OPA_MAX_WASM_BYTES) {
      throw new RangeError(`OPA WASM policy exceeds ${OPA_MAX_WASM_BYTES} bytes`);
    }
    const bytes = await readFile(resolved);
    if (bytes.byteLength > OPA_MAX_WASM_BYTES) {
      throw new RangeError(`OPA WASM policy exceeds ${OPA_MAX_WASM_BYTES} bytes`);
    }
    const wasm = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    return OpaPolicyEngine.load(wasm, options);
  }

  evaluateMatches(input: EngineInput, builtIn: EngineOutput): AdditionalPolicyDecision[] {
    try {
      const raw = this.policy.evaluate({
        input,
        riskproof: {
          action: builtIn.action,
          decision: builtIn.decision,
          riskLevel: builtIn.riskLevel,
          matchedPolicies: builtIn.matchedPolicies,
          arguments: builtIn.arguments,
          proof: builtIn.proof,
        },
      }, this.entrypoint);
      const sensitiveValues = Object.values(builtIn.arguments)
        .filter((argument) => sensitiveTaints(argument).length > 0)
        .flatMap((argument) => argumentSearchValues(argument.value));
      return normalizeOpaResult(
        raw,
        this.id,
        new Set(Object.keys(input.args)),
        sensitiveValues,
      );
    } catch (error) {
      if (this.failureMode === "throw") {
        throw new Error(`OPA policy '${this.id}' evaluation failed`, { cause: error });
      }
      return [failureDecision(this.id)];
    }
  }
}

/** Evaluate built-ins once, then monotonically aggregate every OPA/Rego module. */
export function evaluateWithOpa(
  rawInput: EngineInput,
  policies: readonly OpaPolicyEngine[],
  config?: RiskProofConfig,
): EngineOutput {
  const input = parseEngineInput(rawInput);
  const builtIn = evaluate(input, config);
  const additional = policies.flatMap((policy) => policy.evaluateMatches(input, builtIn));
  return mergePolicyDecisions(builtIn, additional);
}

function normalizeOpaResult(
  raw: unknown,
  moduleId: string,
  argumentNames: ReadonlySet<string>,
  sensitiveValues: readonly string[],
): AdditionalPolicyDecision[] {
  let encoded: string;
  try { encoded = JSON.stringify(raw); }
  catch { throw new TypeError("OPA result must be JSON-compatible"); }
  if (encoded === undefined || Buffer.byteLength(encoded, "utf-8") > MAX_OPA_RESULT_BYTES) {
    throw new RangeError(`OPA result exceeds ${MAX_OPA_RESULT_BYTES} bytes`);
  }

  // opa-wasm returns a result set shaped as [{ result: <entrypoint value> }].
  const resultSet = Array.isArray(raw) ? raw : [raw];
  const values = resultSet.map((item) => {
    if (isRecord(item) && Object.hasOwn(item, "result")) return item.result;
    return item;
  });
  const candidates = values.flatMap((value): unknown[] => {
    if (value === false || value === null || value === undefined) return [];
    if (isRecord(value) && Array.isArray(value.matches)) return value.matches;
    if (Array.isArray(value)) return value;
    if (isRecord(value)) return [value];
    throw new TypeError("OPA entrypoint must return a match object, matches array, or false");
  });
  if (candidates.length > MAX_OPA_MATCHES) throw new RangeError(`OPA result exceeds ${MAX_OPA_MATCHES} matches`);

  return candidates.map((candidate, index) => {
    if (!isRecord(candidate)) throw new TypeError(`OPA match ${index} must be an object`);
    const allowed = new Set([
      "id", "decision", "riskLevel", "risk", "triggeredArgs", "evidence", "reason",
    ]);
    const unknown = Object.keys(candidate).filter((key) => !allowed.has(key));
    if (unknown.length > 0) throw new TypeError(`OPA match ${index} contains unsupported fields`);
    const id = boundedString(candidate.id, `OPA match ${index}.id`, true);
    if (!/^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(id)) {
      throw new TypeError(`OPA match ${index}.id has an unsupported format`);
    }
    if (!DECISIONS.has(candidate.decision as Decision)) {
      throw new TypeError(`OPA match ${index}.decision is invalid`);
    }
    if (candidate.riskLevel !== undefined && candidate.risk !== undefined) {
      throw new TypeError(`OPA match ${index} must not define both riskLevel and risk`);
    }
    const riskValue = candidate.riskLevel ?? candidate.risk;
    if (!RISKS.has(riskValue as RiskLevel)) throw new TypeError(`OPA match ${index}.riskLevel is invalid`);
    const triggeredArgs = stringArray(candidate.triggeredArgs ?? [], `OPA match ${index}.triggeredArgs`);
    if (triggeredArgs.some((name) => !argumentNames.has(name))) {
      throw new TypeError(`OPA match ${index}.triggeredArgs references an unknown argument`);
    }
    const evidence = stringArray(candidate.evidence ?? [], `OPA match ${index}.evidence`)
      .map((value) => redactOpaText(value, sensitiveValues));
    const reason = candidate.reason === undefined
      ? `OPA policy ${moduleId} matched rule ${id}`
      : redactOpaText(boundedString(candidate.reason, `OPA match ${index}.reason`), sensitiveValues);
    return {
      policy: {
        id: `opa_${moduleId}_${id}`,
        triggeredArgs,
        evidence: evidence.length > 0 ? evidence : [`OPA policy '${moduleId}' matched '${id}'`],
        reason,
      },
      decision: candidate.decision as Decision,
      riskLevel: riskValue as RiskLevel,
    };
  });
}

function failureDecision(moduleId: string): AdditionalPolicyDecision {
  return {
    policy: {
      id: `opa_${moduleId}_evaluation_failure`,
      triggeredArgs: [],
      evidence: [`OPA policy '${moduleId}' failed closed`],
      reason: `OPA policy ${moduleId} could not produce a valid decision; execution is denied`,
    },
    decision: "deny",
    riskLevel: "critical",
  };
}

function stringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) throw new TypeError(`${path} must be an array`);
  return value.map((item, index) => boundedString(item, `${path}[${index}]`));
}

function boundedString(value: unknown, path: string, nonEmpty = false): string {
  if (typeof value !== "string" || (nonEmpty && value.length === 0)) {
    throw new TypeError(`${path} must be ${nonEmpty ? "a non-empty string" : "a string"}`);
  }
  if (value.length > MAX_OPA_STRING) throw new RangeError(`${path} exceeds ${MAX_OPA_STRING} characters`);
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function argumentSearchValues(value: unknown): string[] {
  const result: string[] = [];
  const visit = (item: unknown): void => {
    if (typeof item === "string" && item.length > 0) result.push(item);
    else if (typeof item === "number" || typeof item === "boolean") result.push(JSON.stringify(item));
    else if (Array.isArray(item)) item.forEach(visit);
    else if (isRecord(item)) Object.values(item).forEach(visit);
  };
  visit(value);
  return [...new Set(result)].sort((left, right) => right.length - left.length);
}

function redactOpaText(value: string, sensitiveValues: readonly string[]): string {
  let result = redactLogText(value);
  for (const sensitive of sensitiveValues) {
    if (sensitive) result = result.split(sensitive).join("[REDACTED_POLICY_VALUE]");
  }
  return result;
}
