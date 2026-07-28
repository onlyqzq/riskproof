// ============================================================================
// RiskProof — MCP tool identity continuity guard
// ============================================================================
//
// MCP tool names and descriptions are model-visible authority-bearing inputs.
// A server can initially advertise a benign definition, gain trust, and later
// change the schema or metadata (a rug pull). Competing tools can also reuse one
// name (tool squatting/shadowing). This guard turns the complete JSON tool
// descriptor into a deterministic SHA-256 identity and keeps a sticky,
// metadata-only quarantine for identity violations.
//
// The default mode is trust-on-first-use (TOFU): the first complete tools/list
// snapshot becomes the in-process baseline. Pinned mode accepts only explicitly
// configured name/digest pairs. TOFU detects continuity violations but does not
// authenticate the first server; deployments that need origin authenticity
// must pin an operator-approved manifest and isolate the upstream process.

import { createHash } from "node:crypto";
import type { AdditionalPolicyDecision } from "./engine.js";

export type ToolIdentityMode = "tofu" | "pinned";

export type ToolIdentityViolation =
  | "tool_name_collision"
  | "tool_manifest_mismatch"
  | "tool_descriptor_changed"
  | "unexpected_tool_added";

export interface McpToolIdentityDescriptor extends Record<string, unknown> {
  name: string;
}

export interface ToolIdentityGuardOptions {
  /** TOFU learns the first snapshot; pinned accepts only expectedDigests. */
  mode?: ToolIdentityMode;
  /** Operator-approved SHA-256 descriptor digests keyed by exact MCP tool name. */
  expectedDigests?: Readonly<Record<string, string>>;
  maxTools?: number;
  maxDescriptorBytes?: number;
  maxDepth?: number;
  maxNodes?: number;
  maxEvents?: number;
}

export interface ToolIdentityObservation {
  sequence: number;
  name: string;
  digest: string;
  status: "trusted" | "quarantined";
  violations: ToolIdentityViolation[];
  previousDigest?: string;
}

export const TOOL_IDENTITY_LIMITS = Object.freeze({
  maxTools: 512,
  maxDescriptorBytes: 256 * 1024,
  maxDepth: 32,
  maxNodes: 10_000,
  maxEvents: 1_024,
});

const SHA256_DIGEST = /^[a-f0-9]{64}$/;

/**
 * Canonical JSON representation used for descriptor commitments.
 *
 * Object keys are sorted, while string contents and array order are preserved:
 * invisible Unicode, schema order inside arrays, annotations, outputSchema,
 * `_meta`, and future descriptor fields therefore all remain identity-bearing.
 */
export function canonicalizeToolDescriptor(
  descriptor: McpToolIdentityDescriptor,
  options: Pick<ToolIdentityGuardOptions, "maxDescriptorBytes" | "maxDepth" | "maxNodes"> = {},
): string {
  const limits = validateCanonicalLimits(options);
  const state = { nodes: 0 };
  const canonical = canonicalJson(descriptor, 0, state, limits);
  const bytes = Buffer.byteLength(canonical, "utf-8");
  if (bytes > limits.maxDescriptorBytes) {
    throw new RangeError(`MCP tool descriptor exceeds ${limits.maxDescriptorBytes} byte limit`);
  }
  return canonical;
}

export function digestToolDescriptor(
  descriptor: McpToolIdentityDescriptor,
  options: Pick<ToolIdentityGuardOptions, "maxDescriptorBytes" | "maxDepth" | "maxNodes"> = {},
): string {
  return createHash("sha256")
    .update(canonicalizeToolDescriptor(descriptor, options), "utf-8")
    .digest("hex");
}

/**
 * Stateful reference monitor for one logical MCP server identity.
 *
 * Quarantine is sticky: reverting a malicious descriptor does not silently
 * restore trust. A trusted operator must call approve() with the exact current
 * digest, or restart with an explicit pinned manifest.
 */
export class ToolIdentityGuard {
  private readonly mode: ToolIdentityMode;
  private readonly limits: Required<Omit<ToolIdentityGuardOptions, "mode" | "expectedDigests">>;
  private readonly baselines = new Map<string, string>();
  private readonly current = new Map<string, ToolIdentityObservation>();
  private readonly quarantine = new Map<string, ToolIdentityObservation>();
  private readonly events: ToolIdentityObservation[] = [];
  private initialized = false;
  private nextSequence = 0;

  constructor(options: ToolIdentityGuardOptions = {}) {
    if (!isPlainRecord(options)) throw new TypeError("ToolIdentityGuard options must be an object");
    const allowed = new Set([
      "mode", "expectedDigests", "maxTools", "maxDescriptorBytes",
      "maxDepth", "maxNodes", "maxEvents",
    ]);
    if (Object.keys(options).some((key) => !allowed.has(key))) {
      throw new TypeError("ToolIdentityGuard options contain unsupported field(s)");
    }

    const expected = options.expectedDigests ?? {};
    if (!isPlainRecord(expected)) throw new TypeError("expectedDigests must be an object");
    this.mode = options.mode ?? (Object.keys(expected).length > 0 ? "pinned" : "tofu");
    if (this.mode !== "tofu" && this.mode !== "pinned") {
      throw new TypeError("ToolIdentityGuard mode must be 'tofu' or 'pinned'");
    }
    this.limits = validateGuardLimits(options);

    for (const [name, rawDigest] of Object.entries(expected)) {
      const toolName = validateToolName(name);
      const digest = validateDigest(rawDigest, `expectedDigests.${name}`);
      this.baselines.set(toolName, digest);
    }
  }

  /** Observe one complete tools/list snapshot and return per-entry decisions. */
  observeSnapshot(
    descriptors: readonly McpToolIdentityDescriptor[],
  ): ToolIdentityObservation[] {
    if (!Array.isArray(descriptors)) throw new TypeError("MCP tool snapshot must be an array");
    if (descriptors.length > this.limits.maxTools) {
      throw new RangeError(`MCP tool snapshot exceeds ${this.limits.maxTools} tool limit`);
    }

    const prepared = descriptors.map((descriptor, index) => {
      if (!isPlainRecord(descriptor)) {
        throw new TypeError(`MCP tool descriptor at index ${index} must be a JSON object`);
      }
      const name = validateToolName(descriptor.name);
      const digest = digestToolDescriptor(descriptor, this.limits);
      return { name, digest };
    });
    const counts = new Map<string, number>();
    for (const { name } of prepared) counts.set(name, (counts.get(name) ?? 0) + 1);

    const firstSnapshot = !this.initialized;
    const observations: ToolIdentityObservation[] = [];
    this.current.clear();

    for (const { name, digest } of prepared) {
      const baseline = this.baselines.get(name);
      const violations: ToolIdentityViolation[] = [];
      if ((counts.get(name) ?? 0) > 1) violations.push("tool_name_collision");

      if (this.mode === "pinned") {
        if (baseline === undefined) violations.push("unexpected_tool_added");
        else if (baseline !== digest) violations.push("tool_manifest_mismatch");
      } else if (baseline === undefined) {
        if (firstSnapshot) this.baselines.set(name, digest);
        else violations.push("unexpected_tool_added");
      } else if (baseline !== digest) {
        violations.push("tool_descriptor_changed");
      }

      const sticky = this.quarantine.get(name);
      const effectiveViolations = uniqueViolations([
        ...violations,
        ...(sticky?.violations ?? []),
      ]);
      const observation: ToolIdentityObservation = {
        sequence: ++this.nextSequence,
        name,
        digest,
        status: effectiveViolations.length > 0 ? "quarantined" : "trusted",
        violations: effectiveViolations,
        ...(baseline !== undefined && baseline !== digest ? { previousDigest: baseline } : {}),
      };
      this.current.set(name, observation);
      if (observation.status === "quarantined") this.quarantine.set(name, observation);
      this.record(observation);
      observations.push(cloneObservation(observation));
    }

    this.initialized = true;
    return observations;
  }

  /** Explicit operator re-baseline for the descriptor currently being served. */
  approve(name: string, digest: string): void {
    const toolName = validateToolName(name);
    const normalizedDigest = validateDigest(digest, "digest");
    const current = this.current.get(toolName);
    if (!current || current.digest !== normalizedDigest) {
      throw new Error("approval digest does not match the currently observed tool descriptor");
    }
    this.baselines.set(toolName, normalizedDigest);
    this.quarantine.delete(toolName);
    const observation: ToolIdentityObservation = {
      sequence: ++this.nextSequence,
      name: toolName,
      digest: normalizedDigest,
      status: "trusted",
      violations: [],
    };
    this.current.set(toolName, observation);
    this.record(observation);
  }

  isQuarantined(name: string): boolean {
    return this.quarantine.has(name);
  }

  currentDigest(name: string): string | undefined {
    return this.current.get(name)?.digest;
  }

  currentObservation(name: string): ToolIdentityObservation | undefined {
    const value = this.current.get(name) ?? this.quarantine.get(name);
    return value ? cloneObservation(value) : undefined;
  }

  listEvents(): ToolIdentityObservation[] {
    return this.events.map(cloneObservation);
  }

  /** Convert sticky identity findings into monotonic RiskProof decisions. */
  assess(name: string): AdditionalPolicyDecision[] {
    const observation = this.quarantine.get(name);
    if (!observation) return [];
    return observation.violations.map((violation) => ({
      decision: "deny",
      riskLevel: "critical",
      policy: {
        id: violation,
        triggeredArgs: [],
        evidence: [
          `tool '${safeEvidenceName(name)}' descriptor sha256=${observation.digest}`,
          ...(observation.previousDigest
            ? [`approved/baseline descriptor sha256=${observation.previousDigest}`]
            : []),
        ],
        reason: identityViolationReason(violation),
      },
    }));
  }

  private record(observation: ToolIdentityObservation): void {
    this.events.push(cloneObservation(observation));
    while (this.events.length > this.limits.maxEvents) this.events.shift();
  }
}

function canonicalJson(
  value: unknown,
  depth: number,
  state: { nodes: number },
  limits: Required<Pick<ToolIdentityGuardOptions, "maxDescriptorBytes" | "maxDepth" | "maxNodes">>,
): string {
  state.nodes += 1;
  if (state.nodes > limits.maxNodes) {
    throw new RangeError(`MCP tool descriptor exceeds ${limits.maxNodes} node limit`);
  }
  if (depth > limits.maxDepth) {
    throw new RangeError(`MCP tool descriptor exceeds ${limits.maxDepth} depth limit`);
  }
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("MCP tool descriptor contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    assertDataProperties(value, "MCP tool descriptor array");
    return `[${value.map((item) => canonicalJson(item, depth + 1, state, limits)).join(",")}]`;
  }
  if (!isPlainRecord(value)) {
    throw new TypeError("MCP tool descriptor must contain only JSON values");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).sort();
  const entries: string[] = [];
  for (const key of keys) {
    const property = descriptors[key];
    if (!property.enumerable) continue;
    if (!("value" in property)) throw new TypeError("MCP tool descriptor must not contain accessors");
    if (property.value === undefined) throw new TypeError("MCP tool descriptor must not contain undefined");
    entries.push(`${JSON.stringify(key)}:${canonicalJson(property.value, depth + 1, state, limits)}`);
  }
  return `{${entries.join(",")}}`;
}

function assertDataProperties(value: readonly unknown[], label: string): void {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const property = descriptors[String(index)];
    if (!property || !("value" in property)) throw new TypeError(`${label} must be dense and accessor-free`);
    if (property.value === undefined) throw new TypeError(`${label} must not contain undefined`);
  }
  for (const key of Object.keys(descriptors)) {
    if (key === "length" || /^\d+$/.test(key)) continue;
    if (descriptors[key].enumerable) throw new TypeError(`${label} contains a non-JSON property`);
  }
}

function validateCanonicalLimits(
  options: Pick<ToolIdentityGuardOptions, "maxDescriptorBytes" | "maxDepth" | "maxNodes">,
): Required<Pick<ToolIdentityGuardOptions, "maxDescriptorBytes" | "maxDepth" | "maxNodes">> {
  return {
    maxDescriptorBytes: validateLimit(
      options.maxDescriptorBytes ?? TOOL_IDENTITY_LIMITS.maxDescriptorBytes,
      "maxDescriptorBytes",
      1,
      4 * 1024 * 1024,
    ),
    maxDepth: validateLimit(options.maxDepth ?? TOOL_IDENTITY_LIMITS.maxDepth, "maxDepth", 1, 128),
    maxNodes: validateLimit(options.maxNodes ?? TOOL_IDENTITY_LIMITS.maxNodes, "maxNodes", 1, 100_000),
  };
}

function validateGuardLimits(
  options: ToolIdentityGuardOptions,
): Required<Omit<ToolIdentityGuardOptions, "mode" | "expectedDigests">> {
  const canonical = validateCanonicalLimits(options);
  return {
    ...canonical,
    maxTools: validateLimit(options.maxTools ?? TOOL_IDENTITY_LIMITS.maxTools, "maxTools", 1, 4_096),
    maxEvents: validateLimit(options.maxEvents ?? TOOL_IDENTITY_LIMITS.maxEvents, "maxEvents", 1, 16_384),
  };
}

function validateLimit(value: unknown, name: string, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) {
    throw new RangeError(`${name} must be an integer between ${min} and ${max}`);
  }
  return value as number;
}

function validateToolName(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 512) {
    throw new TypeError("MCP tool name must be a non-empty string of at most 512 characters");
  }
  return value;
}

function validateDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value.toLowerCase())) {
    throw new TypeError(`${label} must be a 64-character SHA-256 hex digest`);
  }
  return value.toLowerCase();
}

function isPlainRecord<T>(value: T): value is T & Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function uniqueViolations(values: readonly ToolIdentityViolation[]): ToolIdentityViolation[] {
  return [...new Set(values)];
}

function cloneObservation(value: ToolIdentityObservation): ToolIdentityObservation {
  return { ...value, violations: [...value.violations] };
}

function safeEvidenceName(name: string): string {
  return name.replace(/[\u0000-\u001f\u007f]/g, "_").slice(0, 200);
}

function identityViolationReason(violation: ToolIdentityViolation): string {
  switch (violation) {
    case "tool_name_collision":
      return "同一 MCP Server 在一次工具快照中声明了重名工具，无法建立唯一身份，已隔离";
    case "tool_manifest_mismatch":
      return "工具完整定义与 operator-pinned manifest 不一致，可能发生冒名或供应链替换，已隔离";
    case "tool_descriptor_changed":
      return "工具在建立信任后修改了定义，构成潜在 rug pull；需由可信 operator 重新批准精确摘要";
    case "unexpected_tool_added":
      return "已建立工具快照后出现未批准的新工具，可能形成 tool squatting/shadowing，已隔离";
  }
}
