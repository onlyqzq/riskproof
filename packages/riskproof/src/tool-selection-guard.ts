// ============================================================================
// RiskProof — Provider-aware tool selection integrity
// ============================================================================
// Identity answers "which tool is this?". Selection integrity additionally
// constrains which approved candidate set was exposed and whether the chosen
// identity is appropriate for the requested capability. Model-visible
// descriptions are not treated as authorization evidence.

import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import type { AdditionalPolicyDecision } from "./engine.js";

export type SelectionReason = "operator_pinned" | "capability_match" | "model_metadata" | "unknown";

export type ToolSelectionViolation =
  | "selection_candidate_not_approved"
  | "selection_tool_identity_mismatch"
  | "selection_capability_mismatch"
  | "selection_candidate_set_mismatch"
  | "selection_snapshot_not_observed"
  | "selection_metadata_influenced";

export interface ToolSelectionCandidatePolicy {
  toolKeyDigest: string;
  descriptorDigest: string;
  capabilityClass: string;
  effectClass?: string;
}

export interface ToolSelectionPolicy {
  version: "1";
  policyId: string;
  candidates: readonly ToolSelectionCandidatePolicy[];
  requireCompleteSnapshot?: boolean;
  requireTrustedSelectionReason?: boolean;
}

export interface ObservedSelectionCandidate {
  toolKeyDigest: string;
  descriptorDigest: string;
}

export interface ToolSelectionRequest {
  selected: ObservedSelectionCandidate;
  requestedCapability?: string;
  reason?: SelectionReason;
}

export interface ToolSelectionAdmission {
  approvedIndices: number[];
  snapshotDigest: string;
  decisions: AdditionalPolicyDecision[];
}

export interface ToolSelectionEvent {
  sequence: number;
  kind: "admission" | "selection";
  policyDigest: string;
  snapshotDigest?: string;
  selectedToolKeyDigest?: string;
  selectedDescriptorDigest?: string;
  requestedCapabilityDigest?: string;
  reason?: SelectionReason;
  violations: ToolSelectionViolation[];
}

export interface ToolSelectionGuardOptions {
  maxEvents?: number;
}

export const TOOL_SELECTION_LIMITS = Object.freeze({
  maxCandidates: 512,
  maxEvents: 1_024,
  maxStringLength: 512,
});

const SHA256 = /^[a-f0-9]{64}$/u;
const TRUSTED_REASONS = new Set<SelectionReason>(["operator_pinned", "capability_match"]);

interface NormalizedPolicy {
  version: "1";
  policyId: string;
  candidates: readonly Readonly<ToolSelectionCandidatePolicy>[];
  requireCompleteSnapshot: boolean;
  requireTrustedSelectionReason: boolean;
}

/**
 * Fail-closed candidate admission and selection monitor.
 *
 * Call admitSnapshot() on the exact candidate set before showing tools to the
 * model. Only approvedIndices should be exposed. assessSelection() then proves
 * that the selected identity appeared in that admitted snapshot and still
 * matches its pinned descriptor/capability policy.
 */
export class ToolSelectionGuard {
  private readonly policy: NormalizedPolicy;
  private readonly byToolKey = new Map<string, Readonly<ToolSelectionCandidatePolicy>>();
  private readonly policyDigest: string;
  private readonly maxEvents: number;
  private readonly events: ToolSelectionEvent[] = [];
  private admitted = new Map<string, string>();
  private lastSnapshotDigest?: string;
  private nextSequence = 0;

  constructor(rawPolicy: ToolSelectionPolicy, rawOptions: ToolSelectionGuardOptions = {}) {
    this.policy = normalizePolicy(rawPolicy);
    this.policy.candidates.forEach((candidate) => this.byToolKey.set(candidate.toolKeyDigest, candidate));
    this.policyDigest = sha256(stablePolicyJson(this.policy));
    const options = ownDataRecord(rawOptions, "ToolSelectionGuardOptions");
    assertOnlyKeys(options, ["maxEvents"], "ToolSelectionGuardOptions");
    this.maxEvents = boundedInteger(
      options.maxEvents ?? TOOL_SELECTION_LIMITS.maxEvents,
      "maxEvents",
      1,
      16_384,
    );
  }

  getPolicyDigest(): string {
    return this.policyDigest;
  }

  admitSnapshot(rawCandidates: readonly ObservedSelectionCandidate[]): ToolSelectionAdmission {
    const candidates = normalizeObservedCandidates(rawCandidates, "candidates");
    const snapshotDigest = digestSnapshot(candidates);
    const approvedIndices: number[] = [];
    const violations = new Set<ToolSelectionViolation>();
    const decisions: AdditionalPolicyDecision[] = [];
    const nextAdmitted = new Map<string, string>();

    candidates.forEach((candidate, index) => {
      const expected = this.byToolKey.get(candidate.toolKeyDigest);
      if (!expected) {
        violations.add("selection_candidate_not_approved");
        decisions.push(selectionDecision(
          "selection_candidate_not_approved",
          `unapproved ToolKey sha256=${candidate.toolKeyDigest}`,
        ));
        return;
      }
      if (expected.descriptorDigest !== candidate.descriptorDigest) {
        violations.add("selection_tool_identity_mismatch");
        decisions.push(selectionDecision(
          "selection_tool_identity_mismatch",
          `ToolKey sha256=${candidate.toolKeyDigest} has descriptor sha256=${candidate.descriptorDigest}`,
        ));
        return;
      }
      approvedIndices.push(index);
      nextAdmitted.set(candidate.toolKeyDigest, candidate.descriptorDigest);
    });

    if (this.policy.requireCompleteSnapshot) {
      const missing = this.policy.candidates
        .filter(({ toolKeyDigest }) => !nextAdmitted.has(toolKeyDigest));
      if (missing.length > 0) {
        violations.add("selection_candidate_set_mismatch");
        decisions.push(selectionDecision(
          "selection_candidate_set_mismatch",
          `${missing.length} operator-approved candidate(s) are absent from the observed snapshot`,
        ));
      }
    }

    this.admitted = nextAdmitted;
    this.lastSnapshotDigest = snapshotDigest;
    this.record({
      kind: "admission",
      policyDigest: this.policyDigest,
      snapshotDigest,
      violations: [...violations],
    });
    return { approvedIndices, snapshotDigest, decisions: deduplicateDecisions(decisions) };
  }

  assessSelection(rawRequest: ToolSelectionRequest): AdditionalPolicyDecision[] {
    const request = normalizeSelectionRequest(rawRequest);
    const expected = this.byToolKey.get(request.selected.toolKeyDigest);
    const violations = new Set<ToolSelectionViolation>();
    const decisions: AdditionalPolicyDecision[] = [];

    if (!expected) {
      violations.add("selection_candidate_not_approved");
      decisions.push(selectionDecision(
        "selection_candidate_not_approved",
        `selected ToolKey sha256=${request.selected.toolKeyDigest} is not operator approved`,
      ));
    } else if (expected.descriptorDigest !== request.selected.descriptorDigest) {
      violations.add("selection_tool_identity_mismatch");
      decisions.push(selectionDecision(
        "selection_tool_identity_mismatch",
        `selected descriptor sha256=${request.selected.descriptorDigest} does not match policy`,
      ));
    }

    if (this.admitted.get(request.selected.toolKeyDigest) !== request.selected.descriptorDigest) {
      violations.add("selection_snapshot_not_observed");
      decisions.push(selectionDecision(
        "selection_snapshot_not_observed",
        "selected identity was not present in the latest admitted candidate snapshot",
      ));
    }

    if (expected && request.requestedCapability !== undefined &&
        expected.capabilityClass !== request.requestedCapability) {
      violations.add("selection_capability_mismatch");
      decisions.push(selectionDecision(
        "selection_capability_mismatch",
        `selected candidate capability sha256=${sha256(expected.capabilityClass)} does not match requested capability sha256=${sha256(request.requestedCapability)}`,
      ));
    }

    if (request.reason === "model_metadata" ||
        (this.policy.requireTrustedSelectionReason && !TRUSTED_REASONS.has(request.reason))) {
      violations.add("selection_metadata_influenced");
      decisions.push({
        decision: "require_approval",
        riskLevel: "high",
        policy: {
          id: "selection_metadata_influenced",
          triggeredArgs: [],
          evidence: [
            `selection reason=${request.reason}`,
            "model-visible metadata is not authorization evidence",
          ],
          reason: "工具选择依赖模型可见 metadata 或缺少可信选择依据，需要升级审批",
        },
      });
    }

    if (decisions.length === 0) {
      decisions.push({
        decision: "allow",
        riskLevel: "low",
        policy: {
          id: "selection_policy_matched",
          triggeredArgs: [],
          evidence: [
            `selection policy sha256=${this.policyDigest}`,
            `candidate snapshot sha256=${this.lastSnapshotDigest}`,
            `selected ToolKey sha256=${request.selected.toolKeyDigest}`,
            `selected descriptor sha256=${request.selected.descriptorDigest}`,
            `selection reason=${request.reason}`,
          ],
          reason: "所选工具来自 operator 批准的候选集合，并匹配精确身份和能力约束",
        },
      });
    }

    this.record({
      kind: "selection",
      policyDigest: this.policyDigest,
      ...(this.lastSnapshotDigest ? { snapshotDigest: this.lastSnapshotDigest } : {}),
      selectedToolKeyDigest: request.selected.toolKeyDigest,
      selectedDescriptorDigest: request.selected.descriptorDigest,
      ...(request.requestedCapability
        ? { requestedCapabilityDigest: sha256(request.requestedCapability) }
        : {}),
      reason: request.reason,
      violations: [...violations],
    });
    return deduplicateDecisions(decisions);
  }

  listEvents(): ToolSelectionEvent[] {
    return this.events.map((event) => ({ ...event, violations: [...event.violations] }));
  }

  private record(event: Omit<ToolSelectionEvent, "sequence">): void {
    this.events.push({ sequence: ++this.nextSequence, ...event, violations: [...event.violations] });
    if (this.events.length > this.maxEvents) this.events.splice(0, this.events.length - this.maxEvents);
  }
}

function normalizePolicy(raw: ToolSelectionPolicy): NormalizedPolicy {
  const record = ownDataRecord(raw, "ToolSelectionPolicy");
  assertOnlyKeys(record, [
    "version", "policyId", "candidates", "requireCompleteSnapshot", "requireTrustedSelectionReason",
  ], "ToolSelectionPolicy");
  if (record.version !== "1") throw new TypeError("ToolSelectionPolicy.version must be '1'");
  const policyId = boundedIdentifier(record.policyId, "policyId");
  const rawCandidates = record.candidates;
  if (!Array.isArray(rawCandidates) || utilTypes.isProxy(rawCandidates)) throw new TypeError("candidates must be an array");
  assertDenseDataArray(rawCandidates, "candidates");
  if (rawCandidates.length === 0 || rawCandidates.length > TOOL_SELECTION_LIMITS.maxCandidates) {
    throw new RangeError(`candidates must contain between 1 and ${TOOL_SELECTION_LIMITS.maxCandidates} entries`);
  }
  const seen = new Set<string>();
  const candidates = rawCandidates.map((rawCandidate, index) => {
    const candidate = ownDataRecord(rawCandidate, `candidates[${index}]`);
    assertOnlyKeys(candidate, [
      "toolKeyDigest", "descriptorDigest", "capabilityClass", "effectClass",
    ], `candidates[${index}]`);
    const toolKeyDigest = requiredDigest(candidate.toolKeyDigest, `candidates[${index}].toolKeyDigest`);
    if (seen.has(toolKeyDigest)) throw new TypeError("candidate policy contains duplicate ToolKey digests");
    seen.add(toolKeyDigest);
    return Object.freeze({
      toolKeyDigest,
      descriptorDigest: requiredDigest(candidate.descriptorDigest, `candidates[${index}].descriptorDigest`),
      capabilityClass: boundedIdentifier(candidate.capabilityClass, `candidates[${index}].capabilityClass`),
      ...(candidate.effectClass === undefined
        ? {}
        : { effectClass: boundedIdentifier(candidate.effectClass, `candidates[${index}].effectClass`) }),
    });
  }).sort((left, right) => left.toolKeyDigest.localeCompare(right.toolKeyDigest));
  if (record.requireCompleteSnapshot !== undefined && typeof record.requireCompleteSnapshot !== "boolean") {
    throw new TypeError("requireCompleteSnapshot must be boolean");
  }
  if (record.requireTrustedSelectionReason !== undefined && typeof record.requireTrustedSelectionReason !== "boolean") {
    throw new TypeError("requireTrustedSelectionReason must be boolean");
  }
  return Object.freeze({
    version: "1",
    policyId,
    candidates: Object.freeze(candidates),
    requireCompleteSnapshot: record.requireCompleteSnapshot === true,
    requireTrustedSelectionReason: record.requireTrustedSelectionReason === true,
  });
}

function normalizeObservedCandidates(raw: readonly ObservedSelectionCandidate[], label: string): ObservedSelectionCandidate[] {
  if (!Array.isArray(raw) || utilTypes.isProxy(raw)) throw new TypeError(`${label} must be an array`);
  assertDenseDataArray(raw, label);
  if (raw.length > TOOL_SELECTION_LIMITS.maxCandidates) throw new RangeError(`${label} contains too many candidates`);
  const seen = new Set<string>();
  return raw.map((value, index) => {
    const record = ownDataRecord(value, `${label}[${index}]`);
    assertOnlyKeys(record, ["toolKeyDigest", "descriptorDigest"], `${label}[${index}]`);
    const toolKeyDigest = requiredDigest(record.toolKeyDigest, `${label}[${index}].toolKeyDigest`);
    if (seen.has(toolKeyDigest)) throw new TypeError(`${label} contains duplicate ToolKey digests`);
    seen.add(toolKeyDigest);
    return {
      toolKeyDigest,
      descriptorDigest: requiredDigest(record.descriptorDigest, `${label}[${index}].descriptorDigest`),
    };
  });
}

function normalizeSelectionRequest(raw: ToolSelectionRequest): Required<Pick<ToolSelectionRequest, "selected" | "reason">> & Pick<ToolSelectionRequest, "requestedCapability"> {
  const record = ownDataRecord(raw, "ToolSelectionRequest");
  assertOnlyKeys(record, ["selected", "requestedCapability", "reason"], "ToolSelectionRequest");
  const [selected] = normalizeObservedCandidates([record.selected as ObservedSelectionCandidate], "selected");
  const requestedCapability = record.requestedCapability === undefined
    ? undefined
    : boundedIdentifier(record.requestedCapability, "requestedCapability");
  const reason = record.reason ?? "unknown";
  if (!["operator_pinned", "capability_match", "model_metadata", "unknown"].includes(reason as string)) {
    throw new TypeError("invalid selection reason");
  }
  return { selected, ...(requestedCapability ? { requestedCapability } : {}), reason: reason as SelectionReason };
}

function selectionDecision(violation: Exclude<ToolSelectionViolation, "selection_metadata_influenced">, evidence: string): AdditionalPolicyDecision {
  return {
    decision: "deny",
    riskLevel: "critical",
    policy: {
      id: violation,
      triggeredArgs: [],
      evidence: [evidence],
      reason: selectionViolationReason(violation),
    },
  };
}

function selectionViolationReason(violation: Exclude<ToolSelectionViolation, "selection_metadata_influenced">): string {
  switch (violation) {
    case "selection_candidate_not_approved": return "候选工具不在 operator 批准的 provider-aware 选择策略中";
    case "selection_tool_identity_mismatch": return "候选或所选工具的完整身份与批准策略不一致";
    case "selection_capability_mismatch": return "所选工具不属于任务要求的能力等价类";
    case "selection_candidate_set_mismatch": return "观察到的候选集合与要求完整的批准集合不一致";
    case "selection_snapshot_not_observed": return "所选身份没有出现在最近一次已准入候选快照中";
  }
}

function stablePolicyJson(policy: NormalizedPolicy): string {
  return JSON.stringify({
    candidates: policy.candidates.map((candidate) => ({
      capabilityClass: candidate.capabilityClass,
      descriptorDigest: candidate.descriptorDigest,
      ...(candidate.effectClass ? { effectClass: candidate.effectClass } : {}),
      toolKeyDigest: candidate.toolKeyDigest,
    })),
    policyId: policy.policyId,
    requireCompleteSnapshot: policy.requireCompleteSnapshot,
    requireTrustedSelectionReason: policy.requireTrustedSelectionReason,
    version: policy.version,
  });
}

function digestSnapshot(candidates: readonly ObservedSelectionCandidate[]): string {
  return sha256(JSON.stringify([...candidates]
    .sort((left, right) => left.toolKeyDigest.localeCompare(right.toolKeyDigest))
    .map(({ toolKeyDigest, descriptorDigest }) => ({ descriptorDigest, toolKeyDigest }))));
}

function deduplicateDecisions(decisions: readonly AdditionalPolicyDecision[]): AdditionalPolicyDecision[] {
  const seen = new Set<string>();
  return decisions.filter(({ policy }) => {
    if (seen.has(policy.id)) return false;
    seen.add(policy.id);
    return true;
  });
}

function ownDataRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value) || utilTypes.isProxy(value)) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError(`${label} must be a plain object`);
  const result: Record<string, unknown> = {};
  for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
    if (!descriptor.enumerable) continue;
    if (!("value" in descriptor)) throw new TypeError(`${label} must not contain accessors`);
    result[key] = descriptor.value;
  }
  return result;
}

function assertOnlyKeys(record: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const accepted = new Set(allowed);
  if (Object.keys(record).some((key) => !accepted.has(key))) throw new TypeError(`${label} contains unsupported field(s)`);
}

function assertDenseDataArray(value: readonly unknown[], label: string): void {
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !("value" in descriptor) || descriptor.value === undefined) {
      throw new TypeError(`${label} must be dense, defined, and accessor-free`);
    }
  }
}

function requiredDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  return value;
}

function boundedIdentifier(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > TOOL_SELECTION_LIMITS.maxStringLength) {
    throw new RangeError(`${label} must contain between 1 and ${TOOL_SELECTION_LIMITS.maxStringLength} characters`);
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/u.test(value)) throw new TypeError(`${label} contains unsupported characters`);
  return value;
}

function boundedInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex");
}
