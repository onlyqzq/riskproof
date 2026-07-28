// ============================================================================
// RiskProof — host-held trusted task authorization contract
// ============================================================================
//
// LLM and MCP content are data, not authority. This guard therefore accepts a
// task contract only at construction time from the trusted host. Tool output
// cannot add tools, relax descriptor pins, extend expiry, or replenish call
// budgets. The contract gives RiskProof a deterministic approximation of
// action alignment and source authorization; an objective digest binds the
// execution to a host-approved task but does not prove semantic task alignment.

import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import { mergePolicyDecisions, type AdditionalPolicyDecision } from "./engine.js";
import type { EngineOutput } from "./types.js";

export interface TaskToolAuthorization {
  /** Exact upstream MCP tool name. */
  toolName: string;
  /** Optional operator-approved SHA-256 commitment to the complete descriptor. */
  descriptorDigest?: string;
  /** Optional per-tool budget, counting completed and currently pending calls. */
  maxCalls?: number;
  /** Exact host provenance IDs permitted to influence this tool call. */
  allowedProvenance?: readonly string[];
}

export interface TaskAuthorizationContract {
  /** Host-issued task identifier. Only its digest is exposed in diagnostics. */
  taskId: string;
  /** Binding to a trusted objective representation; not a semantic proof. */
  objectiveDigest?: string;
  /** Absolute expiry. Parsed once and held by the host-side guard. */
  expiresAt?: string;
  /** Optional task-wide call budget, including in-flight reservations. */
  maxCalls?: number;
  allowedTools: readonly TaskToolAuthorization[];
}

export interface TaskAuthorizationRequest {
  toolName: string;
  descriptorDigest?: string;
  /** Argument name -> host-derived ContextTracker provenance IDs. */
  provenance?: Readonly<Record<string, readonly string[]>>;
}

export type TaskAuthorizationViolation =
  | "task_contract_expired"
  | "task_tool_not_authorized"
  | "task_tool_identity_mismatch"
  | "task_call_budget_exhausted"
  | "task_tool_budget_exhausted"
  | "task_source_not_authorized";

export interface TaskAuthorizationReservation {
  reservation: number;
  /** Low-risk positive evidence binding the evaluation proof to this contract. */
  decisions: AdditionalPolicyDecision[];
}

export interface TaskAuthorizationRejection {
  decisions: AdditionalPolicyDecision[];
}

export type TaskAuthorizationResult =
  | TaskAuthorizationReservation
  | TaskAuthorizationRejection;

export interface TaskAuthorizationEvent {
  sequence: number;
  taskDigest: string;
  contractDigest: string;
  toolName: string;
  status: "denied" | "pending" | "completed" | "aborted";
  violations: TaskAuthorizationViolation[];
  descriptorDigest?: string;
  reservation?: number;
}

export interface TaskAuthorizationGuardOptions {
  maxEvents?: number;
  /** Trusted monotonic test/deployment clock; never sourced from an MCP request. */
  clock?: () => Date;
}

export const TASK_AUTHORIZATION_LIMITS = Object.freeze({
  maxTools: 512,
  maxProvenancePerTool: 256,
  maxStringLength: 256,
  maxCalls: 1_000_000,
  maxEvents: 1_024,
});

const SHA256_DIGEST = /^[a-f0-9]{64}$/;

interface NormalizedToolAuthorization {
  toolName: string;
  descriptorDigest?: string;
  maxCalls?: number;
  allowedProvenance?: readonly string[];
}

interface NormalizedContract {
  taskId: string;
  objectiveDigest?: string;
  expiresAt?: string;
  expiresAtMs?: number;
  maxCalls?: number;
  allowedTools: readonly NormalizedToolAuthorization[];
}

interface PendingReservation {
  toolName: string;
}

interface Finding {
  violation: TaskAuthorizationViolation;
  triggeredArgs: string[];
  evidence: string[];
  reason: string;
}

/**
 * Deterministic task-scoped reference monitor.
 *
 * reserve() combines authorization and budget reservation in one synchronous
 * operation, so concurrent calls cannot all pass a read-only budget check and
 * then overrun the contract. complete() consumes the reservation; abort()
 * releases it when dispatch fails or the user rejects a step-up decision.
 */
export class TaskAuthorizationGuard {
  private readonly contract: NormalizedContract;
  private readonly toolRules = new Map<string, NormalizedToolAuthorization>();
  private readonly contractDigest: string;
  private readonly taskDigest: string;
  private readonly maxEvents: number;
  private readonly clock: () => Date;
  private readonly pending = new Map<number, PendingReservation>();
  private readonly completedByTool = new Map<string, number>();
  private readonly events: TaskAuthorizationEvent[] = [];
  private completedCalls = 0;
  private nextSequence = 0;
  private nextReservation = 0;

  constructor(
    rawContract: TaskAuthorizationContract,
    options: TaskAuthorizationGuardOptions = {},
  ) {
    this.contract = normalizeContract(rawContract);
    for (const rule of this.contract.allowedTools) this.toolRules.set(rule.toolName, rule);
    this.contractDigest = sha256(stableContractJson(this.contract));
    this.taskDigest = sha256(this.contract.taskId);
    const normalizedOptions = normalizeOptions(options);
    this.maxEvents = normalizedOptions.maxEvents;
    this.clock = normalizedOptions.clock;
  }

  /** Read-only policy evaluation, suitable for a non-dispatch evaluate endpoint. */
  assess(rawRequest: TaskAuthorizationRequest): AdditionalPolicyDecision[] {
    const request = normalizeRequest(rawRequest);
    const findings = this.findings(request);
    return findings.length > 0
      ? findings.map(findingToDecision)
      : [this.authorizationEvidence(request)];
  }

  /** Atomically authorize and reserve task/global and per-tool budget. */
  reserve(rawRequest: TaskAuthorizationRequest): TaskAuthorizationResult {
    const request = normalizeRequest(rawRequest);
    const findings = this.findings(request);
    if (findings.length > 0) {
      const decisions = findings.map(findingToDecision);
      this.record({
        toolName: request.toolName,
        status: "denied",
        violations: findings.map(({ violation }) => violation),
        ...(request.descriptorDigest ? { descriptorDigest: request.descriptorDigest } : {}),
      });
      return { decisions };
    }

    const reservation = ++this.nextReservation;
    this.pending.set(reservation, { toolName: request.toolName });
    this.record({
      toolName: request.toolName,
      status: "pending",
      violations: [],
      reservation,
      ...(request.descriptorDigest ? { descriptorDigest: request.descriptorDigest } : {}),
    });
    return { reservation, decisions: [this.authorizationEvidence(request)] };
  }

  /** Consume a successful reservation. Unknown/already-finalized IDs are ignored. */
  complete(reservation: number): boolean {
    const pending = this.pending.get(reservation);
    if (!pending) return false;
    this.pending.delete(reservation);
    this.completedCalls += 1;
    this.completedByTool.set(
      pending.toolName,
      (this.completedByTool.get(pending.toolName) ?? 0) + 1,
    );
    this.record({
      toolName: pending.toolName,
      status: "completed",
      violations: [],
      reservation,
    });
    return true;
  }

  /** Release a failed, cancelled, or rejected reservation without consuming budget. */
  abort(reservation: number): boolean {
    const pending = this.pending.get(reservation);
    if (!pending) return false;
    this.pending.delete(reservation);
    this.record({
      toolName: pending.toolName,
      status: "aborted",
      violations: [],
      reservation,
    });
    return true;
  }

  getContractDigest(): string {
    return this.contractDigest;
  }

  getTaskDigest(): string {
    return this.taskDigest;
  }

  /** Metadata-only event history. No objective text, arguments, or raw results. */
  listEvents(): TaskAuthorizationEvent[] {
    return this.events.map((event) => ({
      ...event,
      violations: [...event.violations],
    }));
  }

  private findings(request: NormalizedRequest): Finding[] {
    const findings: Finding[] = [];
    const now = this.clock();
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
      throw new TypeError("TaskAuthorizationGuard clock must return a valid Date");
    }

    if (this.contract.expiresAtMs !== undefined && now.getTime() >= this.contract.expiresAtMs) {
      findings.push({
        violation: "task_contract_expired",
        triggeredArgs: [],
        evidence: [
          `task contract sha256=${this.contractDigest}`,
          `contract expired at ${this.contract.expiresAt}`,
        ],
        reason: "可信任务合同已经过期，不能继续授予工具调用权限",
      });
    }

    const rule = this.toolRules.get(request.toolName);
    if (!rule) {
      findings.push({
        violation: "task_tool_not_authorized",
        triggeredArgs: [],
        evidence: [
          `task contract sha256=${this.contractDigest}`,
          `tool '${safeLabel(request.toolName)}' is absent from the host-held allowlist`,
        ],
        reason: "当前工具不在可信主机签发的任务级最小权限清单中",
      });
      return findings;
    }

    if (
      rule.descriptorDigest !== undefined &&
      request.descriptorDigest !== rule.descriptorDigest
    ) {
      findings.push({
        violation: "task_tool_identity_mismatch",
        triggeredArgs: [],
        evidence: [
          `task contract expects descriptor sha256=${rule.descriptorDigest}`,
          request.descriptorDigest
            ? `observed descriptor sha256=${request.descriptorDigest}`
            : "no current descriptor digest was supplied by the host monitor",
        ],
        reason: "当前工具定义与任务合同绑定的描述符版本不一致",
      });
    }

    if (
      this.contract.maxCalls !== undefined &&
      this.completedCalls + this.pending.size >= this.contract.maxCalls
    ) {
      findings.push({
        violation: "task_call_budget_exhausted",
        triggeredArgs: [],
        evidence: [
          `task call budget=${this.contract.maxCalls}`,
          `completed=${this.completedCalls}, pending=${this.pending.size}`,
        ],
        reason: "任务级调用预算已经耗尽，拒绝继续扩张执行轨迹",
      });
    }

    const pendingForTool = [...this.pending.values()]
      .filter(({ toolName }) => toolName === request.toolName).length;
    const completedForTool = this.completedByTool.get(request.toolName) ?? 0;
    if (
      rule.maxCalls !== undefined &&
      completedForTool + pendingForTool >= rule.maxCalls
    ) {
      findings.push({
        violation: "task_tool_budget_exhausted",
        triggeredArgs: [],
        evidence: [
          `tool '${safeLabel(request.toolName)}' call budget=${rule.maxCalls}`,
          `completed=${completedForTool}, pending=${pendingForTool}`,
        ],
        reason: "该工具在当前任务中的调用预算已经耗尽",
      });
    }

    if (rule.allowedProvenance !== undefined) {
      const allowed = new Set(rule.allowedProvenance);
      const unauthorizedArguments: string[] = [];
      const unauthorizedDigests = new Set<string>();
      for (const [argument, sources] of Object.entries(request.provenance)) {
        for (const source of sources) {
          if (allowed.has(source)) continue;
          unauthorizedArguments.push(argument);
          unauthorizedDigests.add(sha256(source));
        }
      }
      if (unauthorizedArguments.length > 0) {
        findings.push({
          violation: "task_source_not_authorized",
          triggeredArgs: [...new Set(unauthorizedArguments)].sort(),
          evidence: [
            `tool '${safeLabel(request.toolName)}' received provenance outside its task contract`,
            ...[...unauthorizedDigests].sort().slice(0, 8)
              .map((digest) => `unauthorized provenance sha256=${digest}`),
          ],
          reason: "影响当前调用的数据来源不在可信任务合同允许的来源集合中",
        });
      }
    }
    return findings;
  }

  private authorizationEvidence(request: NormalizedRequest): AdditionalPolicyDecision {
    return {
      decision: "allow",
      riskLevel: "low",
      policy: {
        id: "task_contract_matched",
        triggeredArgs: [],
        evidence: [
          `task contract sha256=${this.contractDigest}`,
          `task identifier sha256=${this.taskDigest}`,
          `authorized tool '${safeLabel(request.toolName)}'`,
          ...(request.descriptorDigest
            ? [`authorized descriptor sha256=${request.descriptorDigest}`]
            : []),
          ...(this.contract.objectiveDigest
            ? [`bound objective sha256=${this.contract.objectiveDigest}`]
            : ["no semantic objective oracle is claimed"]),
        ],
        reason: "当前调用满足 Host 持有的结构化任务合同；该证据不表示已经语义证明 task alignment",
      },
    };
  }

  private record(
    event: Omit<TaskAuthorizationEvent, "sequence" | "taskDigest" | "contractDigest">,
  ): void {
    this.events.push({
      sequence: ++this.nextSequence,
      taskDigest: this.taskDigest,
      contractDigest: this.contractDigest,
      ...event,
      violations: [...event.violations],
    });
    while (this.events.length > this.maxEvents) this.events.shift();
  }
}

export function applyTaskAuthorizationGuard(
  output: EngineOutput,
  guard: TaskAuthorizationGuard,
  request: TaskAuthorizationRequest,
): EngineOutput {
  return mergePolicyDecisions(output, guard.assess(request));
}

interface NormalizedRequest {
  toolName: string;
  descriptorDigest?: string;
  provenance: Record<string, string[]>;
}

function normalizeContract(raw: TaskAuthorizationContract): NormalizedContract {
  const record = ownDataRecord(raw, "TaskAuthorizationContract");
  assertOnlyKeys(record, ["taskId", "objectiveDigest", "expiresAt", "maxCalls", "allowedTools"], "TaskAuthorizationContract");
  const taskId = boundedString(record.taskId, "taskId");
  const objectiveDigest = optionalDigest(record.objectiveDigest, "objectiveDigest");
  const maxCalls = optionalCallLimit(record.maxCalls, "maxCalls");
  const expiresAt = optionalExpiry(record.expiresAt);
  const allowedRaw = record.allowedTools;
  if (!Array.isArray(allowedRaw) || utilTypes.isProxy(allowedRaw)) {
    throw new TypeError("allowedTools must be an array");
  }
  assertDenseDataArray(allowedRaw, "allowedTools");
  if (allowedRaw.length === 0 || allowedRaw.length > TASK_AUTHORIZATION_LIMITS.maxTools) {
    throw new RangeError(`allowedTools must contain between 1 and ${TASK_AUTHORIZATION_LIMITS.maxTools} entries`);
  }
  const names = new Set<string>();
  const allowedTools = allowedRaw.map((value, index) => {
    const ruleRecord = ownDataRecord(value, `allowedTools[${index}]`);
    assertOnlyKeys(
      ruleRecord,
      ["toolName", "descriptorDigest", "maxCalls", "allowedProvenance"],
      `allowedTools[${index}]`,
    );
    const toolName = boundedString(ruleRecord.toolName, `allowedTools[${index}].toolName`);
    if (names.has(toolName)) throw new TypeError(`duplicate allowed tool name: ${safeLabel(toolName)}`);
    names.add(toolName);
    const descriptorDigest = optionalDigest(
      ruleRecord.descriptorDigest,
      `allowedTools[${index}].descriptorDigest`,
    );
    const toolMaxCalls = optionalCallLimit(ruleRecord.maxCalls, `allowedTools[${index}].maxCalls`);
    const allowedProvenance = optionalStringArray(
      ruleRecord.allowedProvenance,
      `allowedTools[${index}].allowedProvenance`,
    );
    return Object.freeze({
      toolName,
      ...(descriptorDigest ? { descriptorDigest } : {}),
      ...(toolMaxCalls !== undefined ? { maxCalls: toolMaxCalls } : {}),
      ...(allowedProvenance !== undefined ? { allowedProvenance: Object.freeze(allowedProvenance) } : {}),
    });
  }).sort((left, right) => left.toolName.localeCompare(right.toolName));

  return Object.freeze({
    taskId,
    ...(objectiveDigest ? { objectiveDigest } : {}),
    ...(expiresAt ? { expiresAt: expiresAt.iso, expiresAtMs: expiresAt.ms } : {}),
    ...(maxCalls !== undefined ? { maxCalls } : {}),
    allowedTools: Object.freeze(allowedTools),
  });
}

function normalizeRequest(raw: TaskAuthorizationRequest): NormalizedRequest {
  const record = ownDataRecord(raw, "TaskAuthorizationRequest");
  assertOnlyKeys(record, ["toolName", "descriptorDigest", "provenance"], "TaskAuthorizationRequest");
  const toolName = boundedString(record.toolName, "toolName");
  const descriptorDigest = optionalDigest(record.descriptorDigest, "descriptorDigest");
  const provenance: Record<string, string[]> = {};
  if (record.provenance !== undefined) {
    const provenanceRecord = ownDataRecord(record.provenance, "provenance");
    const entries = Object.entries(provenanceRecord);
    if (entries.length > TASK_AUTHORIZATION_LIMITS.maxProvenancePerTool) {
      throw new RangeError("provenance contains too many arguments");
    }
    for (const [argument, rawSources] of entries) {
      const safeArgument = boundedString(argument, "provenance argument name");
      const sources = optionalStringArray(rawSources, `provenance.${safeArgument}`) ?? [];
      provenance[safeArgument] = sources;
    }
  }
  return {
    toolName,
    ...(descriptorDigest ? { descriptorDigest } : {}),
    provenance,
  };
}

function normalizeOptions(
  raw: TaskAuthorizationGuardOptions,
): { maxEvents: number; clock: () => Date } {
  const record = ownDataRecord(raw, "TaskAuthorizationGuardOptions");
  assertOnlyKeys(record, ["maxEvents", "clock"], "TaskAuthorizationGuardOptions");
  const maxEvents = record.maxEvents === undefined
    ? TASK_AUTHORIZATION_LIMITS.maxEvents
    : positiveInteger(record.maxEvents, "maxEvents", 4_096);
  const clock = record.clock === undefined ? () => new Date() : record.clock;
  if (typeof clock !== "function") throw new TypeError("clock must be a function");
  return { maxEvents, clock: clock as () => Date };
}

function findingToDecision(finding: Finding): AdditionalPolicyDecision {
  return {
    decision: "deny",
    riskLevel: "critical",
    policy: {
      id: finding.violation,
      triggeredArgs: [...finding.triggeredArgs],
      evidence: [...finding.evidence],
      reason: finding.reason,
    },
  };
}

function stableContractJson(contract: NormalizedContract): string {
  return JSON.stringify({
    allowedTools: contract.allowedTools.map((rule) => ({
      ...(rule.allowedProvenance !== undefined
        ? { allowedProvenance: [...rule.allowedProvenance].sort() }
        : {}),
      ...(rule.descriptorDigest ? { descriptorDigest: rule.descriptorDigest } : {}),
      ...(rule.maxCalls !== undefined ? { maxCalls: rule.maxCalls } : {}),
      toolName: rule.toolName,
    })),
    ...(contract.expiresAt ? { expiresAt: contract.expiresAt } : {}),
    ...(contract.maxCalls !== undefined ? { maxCalls: contract.maxCalls } : {}),
    ...(contract.objectiveDigest ? { objectiveDigest: contract.objectiveDigest } : {}),
    taskId: contract.taskId,
  });
}

function ownDataRecord(value: unknown, label: string): Record<string, unknown> {
  if (
    typeof value !== "object" || value === null || Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const result: Record<string, unknown> = {};
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!descriptor.enumerable) continue;
    if (!("value" in descriptor)) throw new TypeError(`${label} must not contain accessors`);
    result[key] = descriptor.value;
  }
  return result;
}

function assertOnlyKeys(record: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const accepted = new Set(allowed);
  if (Object.keys(record).some((key) => !accepted.has(key))) {
    throw new TypeError(`${label} contains unsupported field(s)`);
  }
}

function assertDenseDataArray(value: readonly unknown[], label: string): void {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor)) {
      throw new TypeError(`${label} must be dense and accessor-free`);
    }
  }
  for (const key of Object.keys(descriptors)) {
    if (key === "length" || /^\d+$/.test(key)) continue;
    if (descriptors[key].enumerable) throw new TypeError(`${label} contains a non-JSON property`);
  }
}

function optionalStringArray(value: unknown, label: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || utilTypes.isProxy(value)) throw new TypeError(`${label} must be an array`);
  assertDenseDataArray(value, label);
  if (value.length > TASK_AUTHORIZATION_LIMITS.maxProvenancePerTool) {
    throw new RangeError(`${label} contains too many values`);
  }
  const normalized = value.map((entry, index) => boundedString(entry, `${label}[${index}]`));
  return [...new Set(normalized)].sort();
}

function boundedString(value: unknown, label: string): string {
  if (typeof value !== "string") throw new TypeError(`${label} must be a string`);
  if (value.length === 0 || value.length > TASK_AUTHORIZATION_LIMITS.maxStringLength) {
    throw new RangeError(`${label} must contain between 1 and ${TASK_AUTHORIZATION_LIMITS.maxStringLength} characters`);
  }
  if (/\p{Cc}/u.test(value)) throw new TypeError(`${label} must not contain control characters`);
  return value;
}

function optionalDigest(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function optionalCallLimit(value: unknown, label: string): number | undefined {
  if (value === undefined) return undefined;
  return positiveInteger(value, label, TASK_AUTHORIZATION_LIMITS.maxCalls);
}

function positiveInteger(value: unknown, label: string, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > max) {
    throw new RangeError(`${label} must be an integer between 1 and ${max}`);
  }
  return value as number;
}

function optionalExpiry(value: unknown): { iso: string; ms: number } | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length > 64) {
    throw new TypeError("expiresAt must be a valid date-time string");
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new TypeError("expiresAt must be a valid date-time string");
  return { iso: new Date(ms).toISOString(), ms };
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex");
}

function safeLabel(value: string): string {
  return value.replace(/[^\p{L}\p{N} .:/_-]/gu, "_").slice(0, 128) || "unnamed";
}
