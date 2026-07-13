// ============================================================================
// RiskProof — Runtime Input Validation
// ============================================================================
// TypeScript types disappear at runtime. Every JSON-facing entry point must
// validate untrusted data before it reaches the policy engine.
// ============================================================================

import type {
  Capability,
  EngineInput,
  EngineOptions,
  SafetyInvariant,
  TaintLabel,
  ToolName,
  TraceContext,
} from "./types.js";
import { parseRfc3339 } from "./timestamp.js";
import { redactLogText } from "./redaction.js";

export const SUPPORTED_TOOLS: readonly ToolName[] = [
  "send_email",
  "http_request",
  "shell_exec",
];

export const TAINT_LABELS: readonly TaintLabel[] = [
  "UNTRUSTED_WEB",
  "UNTRUSTED_EMAIL",
  "UNTRUSTED_TOOL_SCHEMA",
  "INTERNAL_DOC",
  "CUSTOMER_DATA",
  "PII",
  "SECRET",
  "API_KEY",
  "SOURCE_CODE",
  "FINANCIAL_DATA",
  "PATIENT_DATA",
];

const TOOL_SET = new Set<string>(SUPPORTED_TOOLS);
const TAINT_SET = new Set<string>(TAINT_LABELS);
const PROTOTYPE_POLLUTION_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const OPTIONAL_INPUT_KEYS = new Set([
  "provenance", "taints", "capability", "invariants", "trace", "options",
]);
const OPTIONAL_CAPABILITY_KEYS = new Set([
  "allowedRecipientDomains", "forbiddenTaints", "allowedProvenance", "expiresAt",
  "description",
]);
const OPTIONAL_INVARIANT_KEYS = new Set([
  "description", "forbiddenTools", "protectedTaints", "maxValues", "minValues",
]);
const OPTIONAL_TRACE_KEYS = new Set([
  "traceId", "stepId", "agentId", "taskId", "userId", "parentStepId",
]);
const OPTIONAL_OPTIONS_KEYS = new Set(["internalDomains", "referenceTime"]);
const INPUT_KEYS = new Set(["tool", "args", ...OPTIONAL_INPUT_KEYS]);
const CAPABILITY_KEYS = new Set(["tool", ...OPTIONAL_CAPABILITY_KEYS]);
const INVARIANT_KEYS = new Set(["name", ...OPTIONAL_INVARIANT_KEYS]);

/**
 * Complexity limits for values accepted by the public engine boundary.
 *
 * The HTTP adapter already caps encoded request bodies at 1 MiB. Programmatic
 * callers can provide values without that transport limit, so one deterministic
 * budget covers args, provenance, taints, capabilities, invariants, traces, and
 * options before any policy or parser processes them.
 */
export const ENGINE_INPUT_COMPLEXITY_LIMITS = Object.freeze({
  maxDepth: 32,
  maxNodes: 10_000,
  maxStringLength: 1_048_576,
  maxTotalCharacters: 2_097_152,
});

type JsonPrimitive = null | boolean | number | string;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

interface InputBudgetState {
  nodes: number;
  characters: number;
  ancestors: Set<object>;
}

export class InputValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputValidationError";
  }
}

export function parseEngineInput(raw: unknown): EngineInput {
  const input = record(snapshotEngineInput(raw), "input");
  rejectUnknownFields(input, INPUT_KEYS, "input");
  const tool = toolName(input.tool, "tool");
  const args = record(input.args, "args");
  for (const key of Object.keys(args)) {
    if (redactLogText(key) !== key) {
      fail("args contains a credential-like field name");
    }
  }
  const provenance = input.provenance === undefined
    ? undefined
    : stringArrayMap(input.provenance, "provenance");
  const taintsValue = input.taints === undefined
    ? undefined
    : taintMap(input.taints, "taints");
  const invariants = input.invariants === undefined
    ? undefined
    : parseInvariants(input.invariants);

  rejectOrphanArgumentMetadata(args, provenance, taintsValue, invariants);

  return {
    tool,
    args,
    ...(provenance === undefined ? {} : { provenance }),
    ...(taintsValue === undefined ? {} : { taints: taintsValue }),
    ...(input.capability === undefined
      ? {}
      : { capability: parseCapability(input.capability) }),
    ...(invariants === undefined ? {} : { invariants }),
    ...(input.trace === undefined ? {} : { trace: parseTrace(input.trace) }),
    ...(input.options === undefined ? {} : { options: parseOptions(input.options) }),
  };
}

/**
 * Validate and snapshot the complete engine input as deterministic JSON data.
 *
 * JSON-facing callers normally arrive as plain objects, but evaluate() is also
 * a public JavaScript API. Reject values that JSON.stringify would throw on,
 * silently omit, or serialize through user-controlled hooks. The snapshot also
 * prevents getters or mutable aliases from changing after validation.
 */
function snapshotEngineInput(value: unknown): JsonValue {
  const state: InputBudgetState = {
    nodes: 0,
    characters: 0,
    ancestors: new Set<object>(),
  };
  return cloneJsonValue(value, "input", 0, state);
}

function cloneJsonValue(
  value: unknown,
  path: string,
  depth: number,
  state: InputBudgetState,
): JsonValue {
  state.nodes += 1;
  if (state.nodes > ENGINE_INPUT_COMPLEXITY_LIMITS.maxNodes) {
    fail(`input exceeds maximum node count of ${ENGINE_INPUT_COMPLEXITY_LIMITS.maxNodes}`);
  }

  if (value === null) return null;

  switch (typeof value) {
    case "string":
      accountCharacters(value, path, state);
      return value;
    case "boolean":
      return value;
    case "number":
      if (!Number.isFinite(value)) {
        fail(`${path} must be a finite JSON number`);
      }
      return value;
    case "object":
      return cloneJsonContainer(value, path, depth, state);
    default:
      fail(`${path} must contain only JSON-compatible values; got ${typeof value}`);
  }
}

function cloneJsonContainer(
  value: object,
  path: string,
  depth: number,
  state: InputBudgetState,
): JsonValue[] | { [key: string]: JsonValue } {
  if (depth > ENGINE_INPUT_COMPLEXITY_LIMITS.maxDepth) {
    fail(`input exceeds maximum depth of ${ENGINE_INPUT_COMPLEXITY_LIMITS.maxDepth}`);
  }
  if (state.ancestors.has(value)) {
    fail(`${path} contains a circular reference`);
  }

  state.ancestors.add(value);
  try {
    const array = safeIsArray(value, path);
    if (array) return cloneJsonArray(value as unknown[], path, depth, state);
    return cloneJsonObject(value, path, depth, state);
  } finally {
    state.ancestors.delete(value);
  }
}

function cloneJsonArray(
  value: unknown[],
  path: string,
  depth: number,
  state: InputBudgetState,
): JsonValue[] {
  const keys = ownKeys(value, path);
  for (const key of keys) {
    if (key === "length") continue;
    if (typeof key !== "string" || !isArrayIndex(key)) {
      fail(`${path} must be a plain JSON array without extra properties`);
    }
  }

  const lengthDescriptor = ownProperty(value, "length", path);
  const length = lengthDescriptor?.value;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) {
    fail(`${path} has an invalid array length`);
  }
  if (state.nodes + length > ENGINE_INPUT_COMPLEXITY_LIMITS.maxNodes) {
    fail(`input exceeds maximum node count of ${ENGINE_INPUT_COMPLEXITY_LIMITS.maxNodes}`);
  }

  const result: JsonValue[] = [];
  for (let index = 0; index < length; index += 1) {
    const itemPath = `${path}[${index}]`;
    const descriptor = ownProperty(value, String(index), itemPath);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      fail(`${path} must be a dense JSON array with data properties`);
    }
    result.push(cloneJsonValue(descriptor.value, itemPath, depth + 1, state));
  }
  return result;
}

function cloneJsonObject(
  value: object,
  path: string,
  depth: number,
  state: InputBudgetState,
): { [key: string]: JsonValue } {
  const prototype = objectPrototype(value, path);
  if (prototype !== Object.prototype && prototype !== null) {
    fail(`${path} must contain only plain JSON objects and arrays`);
  }

  const keys = ownKeys(value, path);
  if (state.nodes + keys.length > ENGINE_INPUT_COMPLEXITY_LIMITS.maxNodes) {
    fail(`input exceeds maximum node count of ${ENGINE_INPUT_COMPLEXITY_LIMITS.maxNodes}`);
  }

  const entries: Array<[string, JsonValue]> = [];
  for (const key of keys) {
    if (typeof key !== "string") {
      fail(`${path} must not contain symbol-keyed properties`);
    }
    rejectPrototypePollutionKey(key, path);
    accountCharacters(key, `${path} object key`, state);
    const descriptor = ownProperty(value, key, propertyPath(path, key));
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      fail(`${propertyPath(path, key)} must be an enumerable data property`);
    }
    if (descriptor.value === undefined && isOptionalUndefinedProperty(path, key)) {
      continue;
    }
    entries.push([
      key,
      cloneJsonValue(descriptor.value, propertyPath(path, key), depth + 1, state),
    ]);
  }
  return Object.fromEntries(entries);
}

function accountCharacters(value: string, path: string, state: InputBudgetState): void {
  if (value.length > ENGINE_INPUT_COMPLEXITY_LIMITS.maxStringLength) {
    fail(
      `${path} exceeds maximum string length of ` +
      `${ENGINE_INPUT_COMPLEXITY_LIMITS.maxStringLength} characters`,
    );
  }
  state.characters += value.length;
  if (state.characters > ENGINE_INPUT_COMPLEXITY_LIMITS.maxTotalCharacters) {
    fail(
      `input exceeds maximum total string size of ` +
      `${ENGINE_INPUT_COMPLEXITY_LIMITS.maxTotalCharacters} characters`,
    );
  }
}

function isOptionalUndefinedProperty(parentPath: string, key: string): boolean {
  if (parentPath === "input") {
    return OPTIONAL_INPUT_KEYS.has(key);
  }
  if (parentPath === "input.capability") {
    return OPTIONAL_CAPABILITY_KEYS.has(key);
  }
  if (/^input\.invariants\[\d+\]$/.test(parentPath)) {
    return OPTIONAL_INVARIANT_KEYS.has(key);
  }
  if (parentPath === "input.trace") {
    return OPTIONAL_TRACE_KEYS.has(key);
  }
  if (parentPath === "input.options") {
    return OPTIONAL_OPTIONS_KEYS.has(key);
  }
  return false;
}

function safeIsArray(value: object, path: string): boolean {
  try {
    return Array.isArray(value);
  } catch {
    fail(`${path} cannot be inspected safely`);
  }
}

function objectPrototype(value: object, path: string): object | null {
  try {
    return Object.getPrototypeOf(value) as object | null;
  } catch {
    fail(`${path} cannot be inspected safely`);
  }
}

function ownKeys(value: object, path: string): Array<string | symbol> {
  try {
    return Reflect.ownKeys(value);
  } catch {
    fail(`${path} cannot be inspected safely`);
  }
}

function ownProperty(
  value: object,
  key: PropertyKey,
  path: string,
): PropertyDescriptor | undefined {
  try {
    return Object.getOwnPropertyDescriptor(value, key);
  } catch {
    fail(`${path} cannot be inspected safely`);
  }
}

function isArrayIndex(value: string): boolean {
  if (!/^(0|[1-9]\d*)$/.test(value)) return false;
  const index = Number(value);
  return Number.isSafeInteger(index) && index >= 0 && index < 4_294_967_295;
}

function propertyPath(parent: string, key: string): string {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key)
    ? `${parent}.${key}`
    : `${parent}[${JSON.stringify(key.slice(0, 64))}]`;
}

function parseCapability(raw: unknown): Capability {
  const value = record(raw, "capability");
  rejectUnknownFields(value, CAPABILITY_KEYS, "capability");
  const result: Capability = { tool: toolName(value.tool, "capability.tool") };

  if (value.allowedRecipientDomains !== undefined) {
    result.allowedRecipientDomains = stringArray(
      value.allowedRecipientDomains,
      "capability.allowedRecipientDomains",
    );
  }
  if (value.forbiddenTaints !== undefined) {
    result.forbiddenTaints = taints(value.forbiddenTaints, "capability.forbiddenTaints");
  }
  if (value.allowedProvenance !== undefined) {
    result.allowedProvenance = stringArray(
      value.allowedProvenance,
      "capability.allowedProvenance",
    );
  }
  if (value.expiresAt !== undefined) {
    result.expiresAt = timestamp(value.expiresAt, "capability.expiresAt");
  }
  if (value.description !== undefined) {
    result.description = string(value.description, "capability.description");
  }
  return result;
}

function parseInvariants(raw: unknown): SafetyInvariant[] {
  if (!Array.isArray(raw)) {
    fail("invariants must be an array");
  }

  return raw.map((item, index) => {
    const path = `invariants[${index}]`;
    const value = record(item, path);
    rejectUnknownFields(value, INVARIANT_KEYS, path);
    const name = string(value.name, `${path}.name`);
    if (name.length === 0) fail(`${path}.name must not be empty`);

    const result: SafetyInvariant = { name };
    if (value.description !== undefined) {
      result.description = string(value.description, `${path}.description`);
    }
    if (value.forbiddenTools !== undefined) {
      if (!Array.isArray(value.forbiddenTools)) {
        fail(`${path}.forbiddenTools must be an array`);
      }
      result.forbiddenTools = value.forbiddenTools.map((tool, toolIndex) =>
        toolName(tool, `${path}.forbiddenTools[${toolIndex}]`),
      );
    }
    if (value.protectedTaints !== undefined) {
      result.protectedTaints = taints(value.protectedTaints, `${path}.protectedTaints`);
    }
    if (value.maxValues !== undefined) {
      result.maxValues = numberMap(value.maxValues, `${path}.maxValues`);
    }
    if (value.minValues !== undefined) {
      result.minValues = numberMap(value.minValues, `${path}.minValues`);
    }
    return result;
  });
}

function parseTrace(raw: unknown): TraceContext {
  const value = record(raw, "trace");
  rejectUnknownFields(value, OPTIONAL_TRACE_KEYS, "trace");
  const result: TraceContext = {};
  for (const key of ["traceId", "stepId", "agentId", "taskId", "userId", "parentStepId"] as const) {
    if (value[key] === undefined) continue;
    result[key] = key === "traceId" || key === "stepId"
      ? auditIdentifier(value[key], `trace.${key}`)
      : string(value[key], `trace.${key}`);
  }
  return result;
}

function auditIdentifier(value: unknown, path: string): string {
  const result = string(value, path);
  if (
    result.length === 0 || result.length > 128 ||
    !/^[A-Za-z0-9._:-]+$/.test(result) || redactLogText(result) !== result
  ) {
    fail(`${path} must be an opaque identifier of 1-128 safe characters`);
  }
  return result;
}

function parseOptions(raw: unknown): EngineOptions {
  const value = record(raw, "options");
  rejectUnknownFields(value, OPTIONAL_OPTIONS_KEYS, "options");
  const result: EngineOptions = {};
  if (value.internalDomains !== undefined) {
    result.internalDomains = stringArray(value.internalDomains, "options.internalDomains");
  }
  if (value.referenceTime !== undefined) {
    result.referenceTime = timestamp(value.referenceTime, "options.referenceTime");
  }
  return result;
}

function record(
  value: unknown,
  path: string,
  rejectUnsafeKeys = true,
): Record<string, unknown> {
  let array = false;
  if (typeof value === "object" && value !== null) {
    array = safeIsArray(value, path);
  }
  if (typeof value !== "object" || value === null || array) {
    fail(`${path} must be an object`);
  }
  if (rejectUnsafeKeys) {
    for (const key of ownKeys(value, path)) {
      if (typeof key === "string") rejectPrototypePollutionKey(key, path);
    }
  }
  return value as Record<string, unknown>;
}

function rejectPrototypePollutionKey(key: string, path: string): void {
  if (PROTOTYPE_POLLUTION_KEYS.has(key)) {
    fail(`${path} contains forbidden prototype-pollution key '${key}'`);
  }
}

function rejectUnknownFields(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  path: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    fail(`${path} contains unsupported field(s): ${unknown.join(", ")}`);
  }
}

function string(value: unknown, path: string): string {
  if (typeof value !== "string") fail(`${path} must be a string`);
  return value;
}

function timestamp(value: unknown, path: string): string {
  const result = string(value, path);
  try {
    parseRfc3339(result, path);
  } catch {
    fail(`${path} must be a valid RFC 3339 timestamp`);
  }
  return result;
}

function rejectOrphanArgumentMetadata(
  args: Record<string, unknown>,
  provenance?: Record<string, string[]>,
  taintsValue?: Record<string, TaintLabel[]>,
  invariants?: SafetyInvariant[],
): void {
  const assertArgumentExists = (key: string, path: string): void => {
    if (!Object.hasOwn(args, key)) {
      fail(`${path} references missing args field '${key}'`);
    }
  };

  for (const key of Object.keys(provenance ?? {})) {
    assertArgumentExists(key, `provenance.${key}`);
  }
  for (const key of Object.keys(taintsValue ?? {})) {
    assertArgumentExists(key, `taints.${key}`);
  }
  invariants?.forEach((invariant, index) => {
    for (const key of Object.keys(invariant.maxValues ?? {})) {
      assertArgumentExists(key, `invariants[${index}].maxValues.${key}`);
    }
    for (const key of Object.keys(invariant.minValues ?? {})) {
      assertArgumentExists(key, `invariants[${index}].minValues.${key}`);
    }
  });
}

function toolName(value: unknown, path: string): ToolName {
  const result = string(value, path);
  if (!TOOL_SET.has(result)) {
    fail(`${path} must be one of: ${SUPPORTED_TOOLS.join(", ")}`);
  }
  return result as ToolName;
}

function stringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) fail(`${path} must be an array of strings`);
  return value.map((item, index) => string(item, `${path}[${index}]`));
}

function taints(value: unknown, path: string): TaintLabel[] {
  return stringArray(value, path).map((taint, index) => {
    if (!TAINT_SET.has(taint)) {
      fail(`${path}[${index}] must be one of: ${TAINT_LABELS.join(", ")}`);
    }
    return taint as TaintLabel;
  });
}

function stringArrayMap(value: unknown, path: string): Record<string, string[]> {
  const input = record(value, path);
  return Object.fromEntries(
    Object.entries(input).map(([key, item]) => [key, stringArray(item, `${path}.${key}`)]),
  );
}

function taintMap(value: unknown, path: string): Record<string, TaintLabel[]> {
  const input = record(value, path);
  return Object.fromEntries(
    Object.entries(input).map(([key, item]) => [key, taints(item, `${path}.${key}`)]),
  );
}

function numberMap(value: unknown, path: string): Record<string, number> {
  const input = record(value, path);
  return Object.fromEntries(
    Object.entries(input).map(([key, item]) => {
      if (typeof item !== "number" || !Number.isFinite(item)) {
        fail(`${path}.${key} must be a finite number`);
      }
      return [key, item];
    }),
  );
}

function fail(message: string): never {
  throw new InputValidationError(message);
}
