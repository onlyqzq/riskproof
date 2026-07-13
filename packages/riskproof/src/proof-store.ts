// ============================================================================
// RiskProof — Proof Store
// ============================================================================
// Audit persistence: saves EngineOutput + user decisions as JSON files.
// Structure: {proofDir}/YYYY-MM/{proofId}.json
// ============================================================================

import {
  chmodSync,
  closeSync,
  existsSync,
  fstatSync,
  linkSync,
  mkdirSync,
  openSync,
  opendirSync,
  readSync,
  readdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { randomUUID } from "node:crypto";
import { basename, resolve } from "node:path";
import { redactEngineOutput, redactLogText } from "./redaction.js";
import { parseRfc3339 } from "./timestamp.js";
import { TAINT_LABELS } from "./validation.js";
import type { EngineOutput, UserAction } from "./types.js";

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface ProofRecord {
  proofId: string;
  timestamp: string;
  tool: string;
  action: string;
  decision: string;
  riskLevel: string;
  matchedRuleIds: string[];
  userDecision: UserAction | null;
  userNote?: string;
  engineOutput: EngineOutput;
}

export interface ProofFilter {
  tool?: string;
  decision?: string;
  action?: string;
  riskLevel?: string;
  since?: string;
  until?: string;
  /** Maximum number of newest matching records to return (default 1000, max 10000). */
  limit?: number;
}

export type CorruptProofKind = "read_error" | "invalid_json" | "invalid_record";

export interface CorruptProofDiagnostic {
  filePath: string;
  kind: CorruptProofKind;
  /** Deliberately excludes file contents so diagnostics cannot echo stored secrets. */
  reason: string;
}

export interface ProofListResult {
  records: ProofRecord[];
  /** Diagnostics are bounded; corruptCount includes every corrupt file encountered. */
  corrupt: CorruptProofDiagnostic[];
  corruptCount: number;
  corruptDiagnosticsTruncated: boolean;
  /** True when matching records were dropped or older eligible months were not scanned. */
  mayHaveMoreRecords: boolean;
}

// ─── ProofStore ────────────────────────────────────────────────────────────────

const DEFAULT_DIR = ".riskproof/proofs";
export const DEFAULT_PROOF_LIST_LIMIT = 1_000;
export const MAX_PROOF_LIST_LIMIT = 10_000;
export const MAX_CORRUPT_DIAGNOSTICS = 100;
export const MAX_USER_NOTE_LENGTH = 4_096;
export const MAX_PROOF_FILE_BYTES = 4 * 1024 * 1024;

const MONTH_PATTERN = /^\d{4}-(?:0[1-9]|1[0-2])$/;
const TOOLS = new Set(["send_email", "http_request", "shell_exec"]);
const ACTIONS = new Set(["allow", "ask_approval", "block"]);
const DECISIONS = new Set(["allow", "require_approval", "deny"]);
const RISK_LEVELS = new Set(["low", "medium", "high", "critical"]);
const TAINTS = new Set<string>(TAINT_LABELS);
const ACTION_FOR_DECISION: Record<string, string> = {
  allow: "allow",
  require_approval: "ask_approval",
  deny: "block",
};
const USER_ACTIONS = new Set<UserAction>([
  "approve",
  "reject",
  "approve_with_redaction",
  "edit_parameters",
  "ask_agent_to_justify",
  "escalate",
  "run_in_sandbox",
]);
const PROOF_RECORD_FIELDS = new Set([
  "proofId", "timestamp", "tool", "action", "decision", "riskLevel",
  "matchedRuleIds", "userDecision", "userNote", "engineOutput",
]);
const ENGINE_OUTPUT_FIELDS = new Set([
  "action", "decision", "riskLevel", "matchedPolicies", "arguments", "proof",
]);
const ARGUMENT_EVIDENCE_FIELDS = new Set(["value", "source", "taints", "isSink", "risk"]);
const AUDIT_PROOF_FIELDS = new Set([
  "proofId", "tool", "traceId", "stepId", "decision", "riskLevel",
  "matchedRules", "evidence", "reason", "timestamp",
]);
const MATCHED_POLICY_FIELDS = new Set(["id", "triggeredArgs", "evidence", "reason"]);
const PROOF_FILTER_FIELDS = new Set([
  "tool", "decision", "action", "riskLevel", "since", "until", "limit",
]);

export class ProofStore {
  readonly baseDir: string;

  constructor(baseDir?: string) {
    this.baseDir = baseDir ? resolve(baseDir) : resolve(DEFAULT_DIR);
  }

  checkWritable(): void {
    mkdirPrivate(this.baseDir);
    const probe = resolve(this.baseDir, `.write-check-${randomUUID()}`);
    try {
      writeFileSync(probe, "", { encoding: "utf-8", flag: "wx", mode: 0o600 });
    } finally {
      try { unlinkSync(probe); } catch { /* probe was not created */ }
    }
  }

  save(output: EngineOutput, userDecision?: UserAction, userNote?: string): string {
    const ts = output.proof.timestamp;
    let timestampMs: number;
    try {
      timestampMs = parseRfc3339(ts, "proof timestamp");
    } catch {
      throw new Error("Cannot save proof with an invalid timestamp");
    }
    const safeUserDecision = prepareUserDecision(userDecision);
    const safeUserNote = prepareUserNote(userNote);
    const ym = monthForTimestamp(timestampMs);
    const dir = resolve(this.baseDir, ym);

    const record: ProofRecord = {
      proofId: output.proof.proofId,
      timestamp: ts,
      tool: output.proof.tool,
      action: output.action,
      decision: output.decision,
      riskLevel: output.riskLevel,
      matchedRuleIds: output.matchedPolicies.map((p) => p.id),
      userDecision: safeUserDecision,
      userNote: safeUserNote,
      engineOutput: redactEngineOutput(output),
    };
    const serialized = JSON.stringify(record, null, 2);
    if (Buffer.byteLength(serialized, "utf-8") > MAX_PROOF_FILE_BYTES) {
      throw new RangeError(`Serialized proof must not exceed ${MAX_PROOF_FILE_BYTES} bytes`);
    }

    mkdirPrivate(this.baseDir);
    mkdirPrivate(dir);
    const fileStem = sanitize(output.proof.proofId);
    const tempPath = resolve(dir, `.${fileStem}.${randomUUID()}.tmp`);

    try {
      writeFileSync(tempPath, serialized, {
        encoding: "utf-8",
        flag: "wx",
        mode: 0o600,
      });
      chmodSync(tempPath, 0o600);
      const filePath = commitUnique(tempPath, dir, fileStem);
      unlinkSync(tempPath);
      return filePath;
    } catch (err) {
      try { unlinkSync(tempPath); } catch { /* no temporary file to remove */ }
      throw err;
    }
  }

  load(proofId: string): ProofRecord | null {
    if (!existsSync(this.baseDir)) return null;
    const fileStem = sanitize(proofId);
    for (const ym of listDirs(this.baseDir)) {
      const dir = resolve(this.baseDir, ym);
      for (const fp of proofFiles(dir)) {
        const name = basename(fp);
        if (name !== `${fileStem}.json` && !name.startsWith(`${fileStem}_`)) continue;
        try {
          const record = readProofRecord(fp);
          if (record.proofId === proofId && monthForTimestamp(parseRfc3339(record.timestamp, "timestamp")) === ym) {
            return record;
          }
        } catch { /* keep looking for a valid matching record */ }
      }
    }
    return null;
  }

  list(filter?: ProofFilter): ProofRecord[] {
    return this.listDetailed(filter).records;
  }

  /**
   * List proofs while exposing bounded, content-free diagnostics for corrupt files.
   * The record and diagnostic collections are both bounded to avoid making a
   * damaged or unexpectedly large proof directory an unbounded API response.
   */
  listDetailed(filter?: ProofFilter): ProofListResult {
    const query = normalizeFilter(filter);
    if (!existsSync(this.baseDir)) return emptyListResult();

    const results: Array<{ record: ProofRecord; timestampMs: number }> = [];
    const corrupt: CorruptProofDiagnostic[] = [];
    let corruptCount = 0;
    let mayHaveMoreRecords = false;

    const months = listDirs(this.baseDir)
      .filter((month) => MONTH_PATTERN.test(month))
      .filter((month) => query.sinceMonth === undefined || month >= query.sinceMonth)
      .filter((month) => query.untilMonth === undefined || month <= query.untilMonth)
      .sort()
      .reverse();

    for (let monthIndex = 0; monthIndex < months.length; monthIndex += 1) {
      const ym = months[monthIndex];
      for (const filePath of proofFiles(resolve(this.baseDir, ym))) {
        try {
          const record = readProofRecord(filePath);
          const timestampMs = parseRfc3339(record.timestamp, "timestamp");
          if (monthForTimestamp(timestampMs) !== ym) {
            throw new ProofFileError(
              "invalid_record",
              "Record timestamp does not match its YYYY-MM directory",
            );
          }
          if (query.tool && record.tool !== query.tool) continue;
          if (query.decision && record.decision !== query.decision) continue;
          if (query.action && record.action !== query.action) continue;
          if (query.riskLevel && record.riskLevel !== query.riskLevel) continue;
          if (query.sinceMs !== undefined && timestampMs < query.sinceMs) continue;
          if (query.untilMs !== undefined && timestampMs > query.untilMs) continue;

          results.push({ record, timestampMs });
          if (results.length >= query.limit * 2) {
            mayHaveMoreRecords = trimToLimit(results, query.limit) || mayHaveMoreRecords;
          }
        } catch (error) {
          corruptCount += 1;
          if (corrupt.length < MAX_CORRUPT_DIAGNOSTICS) {
            corrupt.push(toDiagnostic(filePath, error));
          }
        }
      }

      mayHaveMoreRecords = trimToLimit(results, query.limit) || mayHaveMoreRecords;
      // All remaining directories are older. Once the newest matching records
      // fill the requested limit, scanning more months cannot change the result.
      if (results.length >= query.limit && monthIndex < months.length - 1) {
        mayHaveMoreRecords = true;
        break;
      }
    }

    mayHaveMoreRecords = trimToLimit(results, query.limit) || mayHaveMoreRecords;
    return {
      records: results.map(({ record }) => record),
      corrupt,
      corruptCount,
      corruptDiagnosticsTruncated: corruptCount > corrupt.length,
      mayHaveMoreRecords,
    };
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function sanitize(id: string): string {
  const sanitized = id.replace(/[^a-zA-Z0-9_\-]/g, "_").slice(0, 180);
  return sanitized || "proof";
}

function listDirs(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}

function* proofFiles(dir: string): Generator<string> {
  const directory = opendirSync(dir);
  try {
    let entry = directory.readSync();
    while (entry !== null) {
      if (entry.isFile() && entry.name.endsWith(".json")) {
        yield resolve(dir, entry.name);
      }
      entry = directory.readSync();
    }
  } finally {
    try { directory.closeSync(); } catch { /* directory was already closed */ }
  }
}

interface NormalizedFilter {
  limit: number;
  tool?: string;
  decision?: string;
  action?: string;
  riskLevel?: string;
  sinceMs?: number;
  untilMs?: number;
  sinceMonth?: string;
  untilMonth?: string;
}

function normalizeFilter(filter?: ProofFilter): NormalizedFilter {
  const snapshot = snapshotProofFilter(filter);
  const limit = snapshot.limit ?? DEFAULT_PROOF_LIST_LIMIT;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PROOF_LIST_LIMIT) {
    throw new RangeError(
      `ProofFilter.limit must be a positive integer no greater than ${MAX_PROOF_LIST_LIMIT}`,
    );
  }

  validateFilterEnum(snapshot.tool, "ProofFilter.tool", TOOLS);
  validateFilterEnum(snapshot.decision, "ProofFilter.decision", DECISIONS);
  validateFilterEnum(snapshot.action, "ProofFilter.action", ACTIONS);
  validateFilterEnum(snapshot.riskLevel, "ProofFilter.riskLevel", RISK_LEVELS);

  const sinceMs = snapshot.since === undefined
    ? undefined
    : parseRfc3339(snapshot.since, "ProofFilter.since");
  const untilMs = snapshot.until === undefined
    ? undefined
    : parseRfc3339(snapshot.until, "ProofFilter.until");
  if (sinceMs !== undefined && untilMs !== undefined && sinceMs > untilMs) {
    throw new RangeError("ProofFilter.since must not be later than ProofFilter.until");
  }

  return {
    limit,
    tool: snapshot.tool,
    decision: snapshot.decision,
    action: snapshot.action,
    riskLevel: snapshot.riskLevel,
    sinceMs,
    untilMs,
    sinceMonth: sinceMs === undefined ? undefined : monthForTimestamp(sinceMs),
    untilMonth: untilMs === undefined ? undefined : monthForTimestamp(untilMs),
  };
}

function snapshotProofFilter(filter?: ProofFilter): ProofFilter {
  if (filter === undefined) return {};
  if (typeof filter !== "object" || filter === null || Array.isArray(filter)) {
    throw new TypeError("ProofFilter must be an object");
  }
  const prototype = Object.getPrototypeOf(filter);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("ProofFilter must be a plain object");
  }

  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(filter)) {
    if (typeof key !== "string" || !PROOF_FILTER_FIELDS.has(key)) {
      throw new TypeError("ProofFilter contains unsupported field(s)");
    }
    const descriptor = Object.getOwnPropertyDescriptor(filter, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new TypeError(`ProofFilter.${key} must be an enumerable data property`);
    }
    if (descriptor.value !== undefined) result[key] = descriptor.value;
  }
  return result as ProofFilter;
}

function validateFilterEnum(
  value: unknown,
  label: string,
  allowed: ReadonlySet<string>,
): void {
  if (value !== undefined && (typeof value !== "string" || !allowed.has(value))) {
    throw new TypeError(`${label} has an unsupported value`);
  }
}

function emptyListResult(): ProofListResult {
  return {
    records: [],
    corrupt: [],
    corruptCount: 0,
    corruptDiagnosticsTruncated: false,
    mayHaveMoreRecords: false,
  };
}

function trimToLimit(
  results: Array<{ record: ProofRecord; timestampMs: number }>,
  limit: number,
): boolean {
  results.sort((a, b) =>
    b.timestampMs - a.timestampMs || a.record.proofId.localeCompare(b.record.proofId));
  const truncated = results.length > limit;
  if (truncated) results.length = limit;
  return truncated;
}

function monthForTimestamp(timestampMs: number): string {
  return new Date(timestampMs).toISOString().slice(0, 7);
}

function prepareUserNote(userNote: string | undefined): string | undefined {
  if (userNote === undefined) return undefined;
  if (typeof userNote !== "string") throw new TypeError("Proof userNote must be a string");
  if (userNote.length > MAX_USER_NOTE_LENGTH) {
    throw new RangeError(`Proof userNote must not exceed ${MAX_USER_NOTE_LENGTH} characters`);
  }
  return redactLogText(userNote);
}

function prepareUserDecision(userDecision: UserAction | undefined): UserAction | null {
  if (userDecision === undefined) return null;
  if (!USER_ACTIONS.has(userDecision)) {
    throw new TypeError("Proof userDecision has an unsupported value");
  }
  return userDecision;
}

class ProofFileError extends Error {
  constructor(readonly kind: CorruptProofKind, message: string) {
    super(message);
    this.name = "ProofFileError";
  }
}

function readProofRecord(filePath: string): ProofRecord {
  let serialized: string;
  let descriptor: number | undefined;
  try {
    descriptor = openSync(filePath, "r");
    const stats = fstatSync(descriptor);
    if (!stats.isFile()) {
      throw new ProofFileError("invalid_record", "Proof path is not a regular file");
    }
    if (stats.size > MAX_PROOF_FILE_BYTES) {
      throw new ProofFileError(
        "invalid_record",
        `Proof file exceeds the ${MAX_PROOF_FILE_BYTES} byte limit`,
      );
    }

    // Read from the already-open descriptor into a bounded buffer. The extra
    // byte detects a concurrent append at the configured size boundary.
    const buffer = Buffer.allocUnsafe(stats.size + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const count = readSync(descriptor, buffer, bytesRead, buffer.length - bytesRead, null);
      if (count === 0) break;
      bytesRead += count;
    }
    if (bytesRead > MAX_PROOF_FILE_BYTES) {
      throw new ProofFileError(
        "invalid_record",
        `Proof file exceeds the ${MAX_PROOF_FILE_BYTES} byte limit`,
      );
    }
    serialized = buffer.subarray(0, bytesRead).toString("utf-8");
  } catch (error) {
    if (error instanceof ProofFileError) throw error;
    throw new ProofFileError("read_error", "Proof file could not be read");
  } finally {
    if (descriptor !== undefined) {
      try { closeSync(descriptor); } catch { /* descriptor is already closed */ }
    }
  }

  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch {
    throw new ProofFileError("invalid_json", "Proof file is not valid JSON");
  }
  return validateProofRecord(raw);
}

function validateProofRecord(raw: unknown): ProofRecord {
  const record = proofObject(raw, "record");
  rejectProofUnknownFields(record, PROOF_RECORD_FIELDS, "record");
  const proofId = proofString(record.proofId, "record.proofId", true);
  const timestamp = proofString(record.timestamp, "record.timestamp", true);
  try {
    parseRfc3339(timestamp, "record.timestamp");
  } catch {
    throw new ProofFileError("invalid_record", "record.timestamp is not valid RFC 3339");
  }
  const tool = proofEnum(record.tool, "record.tool", TOOLS);
  const action = proofEnum(record.action, "record.action", ACTIONS);
  const decision = proofEnum(record.decision, "record.decision", DECISIONS);
  const riskLevel = proofEnum(record.riskLevel, "record.riskLevel", RISK_LEVELS);
  const matchedRuleIds = proofStringArray(record.matchedRuleIds, "record.matchedRuleIds");
  if (ACTION_FOR_DECISION[decision] !== action) {
    throw new ProofFileError("invalid_record", "record.action does not match record.decision");
  }

  if (record.userDecision !== null && !USER_ACTIONS.has(record.userDecision as UserAction)) {
    throw new ProofFileError("invalid_record", "record.userDecision is invalid");
  }
  if (record.userNote !== undefined) {
    const note = proofString(record.userNote, "record.userNote");
    if (note.length > MAX_USER_NOTE_LENGTH) {
      throw new ProofFileError("invalid_record", "record.userNote exceeds the supported length");
    }
  }

  const engine = proofObject(record.engineOutput, "record.engineOutput");
  rejectProofUnknownFields(engine, ENGINE_OUTPUT_FIELDS, "record.engineOutput");
  if (engine.action !== action || engine.decision !== decision || engine.riskLevel !== riskLevel) {
    throw new ProofFileError("invalid_record", "record summary does not match engineOutput");
  }
  const enginePolicies = validateMatchedPolicies(
    engine.matchedPolicies,
    "record.engineOutput.matchedPolicies",
  );
  const enginePolicyIds = enginePolicies.map((policy) => policy.id as string);
  if (!sameStringArray(matchedRuleIds, enginePolicyIds)) {
    throw new ProofFileError(
      "invalid_record",
      "record.matchedRuleIds does not match record.engineOutput.matchedPolicies",
    );
  }
  validateArguments(engine.arguments, "record.engineOutput.arguments");
  const proof = proofObject(engine.proof, "record.engineOutput.proof");
  rejectProofUnknownFields(proof, AUDIT_PROOF_FIELDS, "record.engineOutput.proof");
  if (
    proof.proofId !== proofId || proof.timestamp !== timestamp || proof.tool !== tool ||
    proof.decision !== decision || proof.riskLevel !== riskLevel
  ) {
    throw new ProofFileError("invalid_record", "record summary does not match engineOutput.proof");
  }
  const proofPolicies = validateMatchedPolicies(
    proof.matchedRules,
    "record.engineOutput.proof.matchedRules",
  );
  if (JSON.stringify(proofPolicies) !== JSON.stringify(enginePolicies)) {
    throw new ProofFileError(
      "invalid_record",
      "record.engineOutput policy summaries are inconsistent",
    );
  }
  const proofEvidence = proofStringArray(
    proof.evidence,
    "record.engineOutput.proof.evidence",
  );
  const expectedEvidence = enginePolicies.flatMap((policy) => policy.evidence as string[]);
  if (!sameStringArray(proofEvidence, expectedEvidence)) {
    throw new ProofFileError("invalid_record", "record.engineOutput.proof.evidence is inconsistent");
  }
  const proofReason = proofString(proof.reason, "record.engineOutput.proof.reason");
  const reasons = enginePolicies
    .map((policy) => policy.reason)
    .filter((reason): reason is string => typeof reason === "string" && reason.length > 0);
  const expectedReason = reasons.length > 0
    ? reasons.join("; ")
    : "未命中任何安全策略，允许执行";
  if (proofReason !== expectedReason) {
    throw new ProofFileError("invalid_record", "record.engineOutput.proof.reason is inconsistent");
  }
  if (proof.traceId !== undefined) proofString(proof.traceId, "record.engineOutput.proof.traceId");
  if (proof.stepId !== undefined) proofString(proof.stepId, "record.engineOutput.proof.stepId");

  const typed = raw as ProofRecord;
  return {
    ...typed,
    matchedRuleIds: [...typed.matchedRuleIds],
    userNote: typed.userNote === undefined ? undefined : redactLogText(typed.userNote),
    engineOutput: redactEngineOutput(typed.engineOutput),
  };
}

function validateArguments(value: unknown, path: string): void {
  const args = proofObject(value, path);
  for (const [name, argumentValue] of Object.entries(args)) {
    const argument = proofObject(argumentValue, `${path}.${name}`);
    rejectProofUnknownFields(argument, ARGUMENT_EVIDENCE_FIELDS, `${path}.${name}`);
    if (!Object.hasOwn(argument, "value")) {
      throw new ProofFileError("invalid_record", `${path}.${name}.value is required`);
    }
    proofStringArray(argument.source, `${path}.${name}.source`);
    const taints = proofStringArray(argument.taints, `${path}.${name}.taints`);
    if (taints.some((taint) => !TAINTS.has(taint))) {
      throw new ProofFileError("invalid_record", `${path}.${name}.taints contains an invalid label`);
    }
    if (argument.isSink !== undefined && typeof argument.isSink !== "boolean") {
      throw new ProofFileError("invalid_record", `${path}.${name}.isSink must be a boolean`);
    }
    if (argument.risk !== undefined) proofString(argument.risk, `${path}.${name}.risk`);
  }
}

function validateMatchedPolicies(value: unknown, path: string): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) {
    throw new ProofFileError("invalid_record", `${path} must be an array`);
  }
  value.forEach((policyValue, index) => {
    const policy = proofObject(policyValue, `${path}[${index}]`);
    rejectProofUnknownFields(policy, MATCHED_POLICY_FIELDS, `${path}[${index}]`);
    proofString(policy.id, `${path}[${index}].id`, true);
    proofStringArray(policy.triggeredArgs, `${path}[${index}].triggeredArgs`);
    proofStringArray(policy.evidence, `${path}[${index}].evidence`);
    if (policy.reason !== undefined) proofString(policy.reason, `${path}[${index}].reason`);
  });
  return value as Array<Record<string, unknown>>;
}

function sameStringArray(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function rejectProofUnknownFields(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  path: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw new ProofFileError(
      "invalid_record",
      `${path} contains unsupported field(s)`,
    );
  }
}

function proofObject(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProofFileError("invalid_record", `${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function proofString(value: unknown, path: string, nonEmpty = false): string {
  if (typeof value !== "string" || (nonEmpty && value.length === 0)) {
    throw new ProofFileError(
      "invalid_record",
      `${path} must be ${nonEmpty ? "a non-empty string" : "a string"}`,
    );
  }
  return value;
}

function proofStringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new ProofFileError("invalid_record", `${path} must be an array of strings`);
  }
  return value as string[];
}

function proofEnum(value: unknown, path: string, allowed: Set<string>): string {
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new ProofFileError("invalid_record", `${path} has an unsupported value`);
  }
  return value;
}

function toDiagnostic(filePath: string, error: unknown): CorruptProofDiagnostic {
  if (error instanceof ProofFileError) {
    return { filePath, kind: error.kind, reason: error.message };
  }
  return { filePath, kind: "read_error", reason: "Proof file could not be processed" };
}

function mkdirPrivate(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
}

function commitUnique(tempPath: string, dir: string, stem: string): string {
  let suffix = 1;
  let candidate = resolve(dir, `${stem}.json`);
  while (true) {
    try {
      // Hard-linking a fully-written temporary file is an atomic no-overwrite
      // commit, including when multiple RiskProof processes share a volume.
      linkSync(tempPath, candidate);
      return candidate;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      candidate = resolve(dir, `${stem}_${suffix}.json`);
      suffix += 1;
    }
  }
}
