// ============================================================================
// RiskProof — Decision-to-effect execution receipts
// ============================================================================
// A decision proof says what the reference monitor decided. An execution
// receipt additionally commits to the exact arguments, dispatch boundary,
// upstream outcome, and any independently observed effect evidence. Raw
// arguments and results are never persisted by this module.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  KeyObject,
  randomUUID,
  sign as signBytes,
  verify as verifyBytes,
  type KeyLike,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { basename, resolve } from "node:path";
import { types as utilTypes } from "node:util";

export type ExecutionOutcome =
  | "success"
  | "mcp_error"
  | "jsonrpc_error"
  | "timeout"
  | "transport_error"
  | "local_error";

export type NoDispatchReason =
  | "policy_block"
  | "approval_required"
  | "approval_rejected"
  | "authorization_failed"
  | "local_error";

export type EffectEvidenceKind = "canary" | "egress_gateway" | "sandbox" | "target_system" | "os_audit";
export type EffectEvidenceStatus = "confirmed" | "contradicted" | "inconclusive";

export interface EffectEvidence {
  kind: EffectEvidenceKind;
  status: EffectEvidenceStatus;
  /** Digest of an external attestation or observation; raw evidence stays in its owning system. */
  digest?: string;
}

export interface ExecutionScope {
  tenantId?: string;
  userId?: string;
  taskId?: string;
  sessionId?: string;
  traceId?: string;
  stepId?: string;
}

export interface StartExecutionReceiptInput {
  scope: ExecutionScope;
  toolKeyDigest: string;
  descriptorDigest: string;
  args: unknown;
  proofId: string;
  decision: "allow" | "require_approval" | "deny";
  riskLevel: "low" | "medium" | "high" | "critical";
  matchedRuleIds: readonly string[];
  policyDigest?: string;
  contractDigest?: string;
  toolManifestDigest?: string;
  selectionPolicyDigest?: string;
  ledgerPolicyDigest?: string;
  approvalTicketDigest?: string;
  timestamp?: string;
}

export interface DispatchReceiptInput {
  /** Exact JSON-RPC request or an equivalent host-side dispatch object. */
  request: unknown;
  timestamp?: string;
}

export interface SettleExecutionReceiptInput {
  outcome: ExecutionOutcome;
  /** Exact upstream result; only its canonical digest is retained. */
  result?: unknown;
  errorCode?: number | string;
  effectEvidence?: readonly EffectEvidence[];
  timestamp?: string;
}

export interface NoDispatchReceiptInput {
  reason: NoDispatchReason;
  timestamp?: string;
}

export interface ReceiptSignature {
  algorithm: "ed25519";
  keyId: string;
  value: string;
}

interface ReceiptEventBase {
  format: "riskproof.execution-receipt.event.v1";
  receiptId: string;
  sequence: number;
  timestamp: string;
  previousHash: string | null;
  eventHash: string;
  signature?: ReceiptSignature;
}

export interface DecisionReceiptEvent extends ReceiptEventBase {
  stage: "decision";
  data: {
    scopeDigest: string;
    toolKeyDigest: string;
    descriptorDigest: string;
    argsDigest: string;
    proofIdDigest: string;
    decision: StartExecutionReceiptInput["decision"];
    riskLevel: StartExecutionReceiptInput["riskLevel"];
    matchedRuleIds: string[];
    policyDigest: string;
    contractDigest?: string;
    toolManifestDigest?: string;
    selectionPolicyDigest?: string;
    ledgerPolicyDigest?: string;
    approvalTicketDigest?: string;
  };
}

export interface DispatchReceiptEvent extends ReceiptEventBase {
  stage: "dispatch";
  data: { requestDigest: string };
}

export interface ResultReceiptEvent extends ReceiptEventBase {
  stage: "result";
  data: {
    outcome: ExecutionOutcome;
    resultDigest?: string;
    errorCode?: number | string;
    effectEvidence: EffectEvidence[];
  };
}

export interface NoDispatchReceiptEvent extends ReceiptEventBase {
  stage: "not_dispatched";
  data: { reason: NoDispatchReason };
}

export type ExecutionReceiptEvent =
  | DecisionReceiptEvent
  | DispatchReceiptEvent
  | ResultReceiptEvent
  | NoDispatchReceiptEvent;

export interface ExecutionReceipt {
  receiptId: string;
  state: "decided" | "dispatched" | "settled" | "not_dispatched";
  events: ExecutionReceiptEvent[];
  chainHead: string;
  signed: boolean;
}

export interface ExecutionReceiptDiagnostic {
  receiptId: string;
  state: ExecutionReceipt["state"] | "corrupt";
  eventCount: number;
  chainHead?: string;
  signed?: boolean;
}

export interface ExecutionReceiptStoreOptions {
  baseDir?: string;
  clock?: () => Date;
  signing?: { keyId: string; privateKey: KeyLike };
  verificationKeys?: Readonly<Record<string, KeyLike>>;
  requireSignature?: boolean;
  maxReceipts?: number;
  maxCanonicalBytes?: number;
  maxDepth?: number;
  maxNodes?: number;
}

export const EXECUTION_RECEIPT_LIMITS = Object.freeze({
  maxReceipts: 10_000,
  maxCanonicalBytes: 1024 * 1024,
  maxEventBytes: 256 * 1024,
  maxDepth: 32,
  maxNodes: 20_000,
  maxStringLength: 8_192,
  maxMatchedRules: 512,
  maxEffectEvidence: 32,
});

const EVENT_FORMAT = "riskproof.execution-receipt.event.v1" as const;
const SHA256 = /^[a-f0-9]{64}$/u;
const RECEIPT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const EVENT_FILE = /^(01-decision|02-dispatch|02-not-dispatched|03-result)\.json$/u;

interface NormalizedStoreOptions {
  baseDir: string;
  clock: () => Date;
  signing?: { keyId: string; privateKey: ReturnType<typeof createPrivateKey> };
  verificationKeys: Map<string, ReturnType<typeof createPublicKey>>;
  requireSignature: boolean;
  maxReceipts: number;
  canonical: CanonicalLimits;
}

interface CanonicalLimits {
  maxCanonicalBytes: number;
  maxDepth: number;
  maxNodes: number;
}

export class ExecutionReceiptStore {
  readonly baseDir: string;
  private readonly options: NormalizedStoreOptions;

  constructor(rawOptions: ExecutionReceiptStoreOptions = {}) {
    this.options = normalizeStoreOptions(rawOptions);
    this.baseDir = this.options.baseDir;
  }

  start(rawInput: StartExecutionReceiptInput): ExecutionReceipt {
    const input = normalizeStartInput(rawInput, this.options.canonical);
    mkdirPrivate(this.baseDir);
    if (countReceiptDirs(this.baseDir) >= this.options.maxReceipts) {
      throw new RangeError(`execution receipt store reached ${this.options.maxReceipts} receipt limit`);
    }
    const receiptId = randomUUID();
    const directory = receiptDirectory(this.baseDir, receiptId);
    mkdirSync(directory, { mode: 0o700 });
    chmodSync(directory, 0o700);
    const policyDigest = input.policyDigest ?? digestCanonicalValue(
      { matchedRuleIds: [...input.matchedRuleIds].sort() },
      this.options.canonical,
    );
    const data: DecisionReceiptEvent["data"] = {
      scopeDigest: digestCanonicalValue(input.scope, this.options.canonical),
      toolKeyDigest: input.toolKeyDigest,
      descriptorDigest: input.descriptorDigest,
      argsDigest: digestCanonicalValue(input.args, this.options.canonical),
      proofIdDigest: sha256(input.proofId),
      decision: input.decision,
      riskLevel: input.riskLevel,
      matchedRuleIds: [...input.matchedRuleIds],
      policyDigest,
      ...(input.contractDigest ? { contractDigest: input.contractDigest } : {}),
      ...(input.toolManifestDigest ? { toolManifestDigest: input.toolManifestDigest } : {}),
      ...(input.selectionPolicyDigest ? { selectionPolicyDigest: input.selectionPolicyDigest } : {}),
      ...(input.ledgerPolicyDigest ? { ledgerPolicyDigest: input.ledgerPolicyDigest } : {}),
      ...(input.approvalTicketDigest ? { approvalTicketDigest: input.approvalTicketDigest } : {}),
    };
    const event = this.createEvent(receiptId, 1, "decision", data, null, input.timestamp) as DecisionReceiptEvent;
    writeEvent(directory, "01-decision.json", event);
    return receiptFromEvents(receiptId, [event]);
  }

  markDispatched(receiptId: string, rawInput: DispatchReceiptInput): ExecutionReceipt {
    const input = ownDataRecord(rawInput, "DispatchReceiptInput");
    assertOnlyKeys(input, ["request", "timestamp"], "DispatchReceiptInput");
    if (!Object.hasOwn(input, "request")) throw new TypeError("DispatchReceiptInput.request is required");
    const receipt = this.load(receiptId);
    if (receipt.state !== "decided") throw new Error(`receipt ${receiptId} cannot dispatch from ${receipt.state}`);
    const previous = receipt.events.at(-1)!;
    const data: DispatchReceiptEvent["data"] = {
      requestDigest: digestCanonicalValue(input.request, this.options.canonical),
    };
    const event = this.createEvent(
      receiptId,
      2,
      "dispatch",
      data,
      previous.eventHash,
      optionalTimestamp(input.timestamp, "timestamp"),
    ) as DispatchReceiptEvent;
    writeEvent(receiptDirectory(this.baseDir, receiptId), "02-dispatch.json", event);
    return receiptFromEvents(receiptId, [...receipt.events, event]);
  }

  settle(receiptId: string, rawInput: SettleExecutionReceiptInput): ExecutionReceipt {
    const input = normalizeSettlement(rawInput, this.options.canonical);
    const receipt = this.load(receiptId);
    if (receipt.state !== "dispatched") throw new Error(`receipt ${receiptId} cannot settle from ${receipt.state}`);
    const previous = receipt.events.at(-1)!;
    const data: ResultReceiptEvent["data"] = {
      outcome: input.outcome,
      ...(input.hasResult ? { resultDigest: digestCanonicalValue(input.result, this.options.canonical) } : {}),
      ...(input.errorCode !== undefined ? { errorCode: input.errorCode } : {}),
      effectEvidence: input.effectEvidence,
    };
    const event = this.createEvent(
      receiptId,
      3,
      "result",
      data,
      previous.eventHash,
      input.timestamp,
    ) as ResultReceiptEvent;
    writeEvent(receiptDirectory(this.baseDir, receiptId), "03-result.json", event);
    return receiptFromEvents(receiptId, [...receipt.events, event]);
  }

  recordNotDispatched(receiptId: string, rawInput: NoDispatchReceiptInput): ExecutionReceipt {
    const record = ownDataRecord(rawInput, "NoDispatchReceiptInput");
    assertOnlyKeys(record, ["reason", "timestamp"], "NoDispatchReceiptInput");
    if (!isNoDispatchReason(record.reason)) throw new TypeError("invalid no-dispatch reason");
    const receipt = this.load(receiptId);
    if (receipt.state !== "decided") {
      throw new Error(`receipt ${receiptId} cannot record non-dispatch from ${receipt.state}`);
    }
    const previous = receipt.events.at(-1)!;
    const event = this.createEvent(
      receiptId,
      2,
      "not_dispatched",
      { reason: record.reason },
      previous.eventHash,
      optionalTimestamp(record.timestamp, "timestamp"),
    ) as NoDispatchReceiptEvent;
    writeEvent(receiptDirectory(this.baseDir, receiptId), "02-not-dispatched.json", event);
    return receiptFromEvents(receiptId, [...receipt.events, event]);
  }

  load(rawReceiptId: string): ExecutionReceipt {
    const receiptId = validateReceiptId(rawReceiptId);
    const directory = receiptDirectory(this.baseDir, receiptId);
    assertPrivateDirectory(directory, "execution receipt directory");
    const names = readdirSync(directory).filter((name) => !name.startsWith("."));
    if (names.length === 0 || names.some((name) => !EVENT_FILE.test(name))) {
      throw new Error(`receipt ${receiptId} contains an invalid event set`);
    }
    const ordered = names.sort();
    const expected = ordered.includes("02-not-dispatched.json")
      ? ["01-decision.json", "02-not-dispatched.json"]
      : ordered.includes("03-result.json")
        ? ["01-decision.json", "02-dispatch.json", "03-result.json"]
        : ordered.includes("02-dispatch.json")
          ? ["01-decision.json", "02-dispatch.json"]
          : ["01-decision.json"];
    if (JSON.stringify(ordered) !== JSON.stringify(expected)) {
      throw new Error(`receipt ${receiptId} has an invalid state transition`);
    }
    const events = ordered.map((name) => parseAndVerifyEvent(
      readPrivateFile(resolve(directory, name)),
      receiptId,
      this.options,
    ));
    verifyEventChain(events);
    return receiptFromEvents(receiptId, events);
  }

  listDiagnostics(limit = 100): ExecutionReceiptDiagnostic[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
      throw new RangeError("receipt diagnostic limit must be between 1 and 10000");
    }
    if (!existsSync(this.baseDir)) return [];
    assertPrivateDirectory(this.baseDir, "execution receipt base directory");
    const names = readdirSync(this.baseDir)
      .filter((name) => RECEIPT_ID.test(name))
      .sort()
      .slice(0, limit);
    return names.map((receiptId) => {
      try {
        const receipt = this.load(receiptId);
        return {
          receiptId,
          state: receipt.state,
          eventCount: receipt.events.length,
          chainHead: receipt.chainHead,
          signed: receipt.signed,
        };
      } catch {
        return { receiptId, state: "corrupt", eventCount: 0 };
      }
    });
  }

  private createEvent(
    receiptId: string,
    sequence: number,
    stage: ExecutionReceiptEvent["stage"],
    data: ExecutionReceiptEvent["data"],
    previousHash: string | null,
    suppliedTimestamp?: string,
  ): ExecutionReceiptEvent {
    const timestamp = suppliedTimestamp ?? clockTimestamp(this.options.clock);
    const unsigned = { format: EVENT_FORMAT, receiptId, sequence, stage, timestamp, previousHash, data };
    const eventHash = digestCanonicalValue(unsigned, this.options.canonical);
    const signature = this.options.signing
      ? signEventHash(eventHash, this.options.signing.keyId, this.options.signing.privateKey)
      : undefined;
    return { ...unsigned, eventHash, ...(signature ? { signature } : {}) } as ExecutionReceiptEvent;
  }
}

export function digestCanonicalValue(
  value: unknown,
  rawLimits: Partial<CanonicalLimits> = {},
): string {
  const limits = normalizeCanonicalLimits(rawLimits);
  const state = { nodes: 0, ancestors: new Set<object>() };
  const canonical = canonicalJson(value, 0, state, limits);
  if (Buffer.byteLength(canonical, "utf-8") > limits.maxCanonicalBytes) {
    throw new RangeError(`canonical value exceeds ${limits.maxCanonicalBytes} byte limit`);
  }
  return sha256(canonical);
}

function normalizeStoreOptions(raw: ExecutionReceiptStoreOptions): NormalizedStoreOptions {
  const record = ownDataRecord(raw, "ExecutionReceiptStoreOptions");
  assertOnlyKeys(record, [
    "baseDir", "clock", "signing", "verificationKeys", "requireSignature",
    "maxReceipts", "maxCanonicalBytes", "maxDepth", "maxNodes",
  ], "ExecutionReceiptStoreOptions");
  const baseDir = record.baseDir === undefined
    ? resolve(".riskproof/receipts")
    : resolve(boundedString(record.baseDir, "baseDir", 4_096));
  const clock = record.clock === undefined ? () => new Date() : record.clock;
  if (typeof clock !== "function") throw new TypeError("clock must be a function");
  const signing = normalizeSigning(record.signing);
  const verificationKeys = normalizeVerificationKeys(record.verificationKeys);
  if (signing) verificationKeys.set(signing.keyId, createPublicKey(signing.privateKey));
  return {
    baseDir,
    clock: clock as () => Date,
    ...(signing ? { signing } : {}),
    verificationKeys,
    requireSignature: record.requireSignature === true,
    maxReceipts: boundedInteger(record.maxReceipts ?? EXECUTION_RECEIPT_LIMITS.maxReceipts, "maxReceipts", 1, 100_000),
    canonical: normalizeCanonicalLimits({
      maxCanonicalBytes: record.maxCanonicalBytes as number | undefined,
      maxDepth: record.maxDepth as number | undefined,
      maxNodes: record.maxNodes as number | undefined,
    }),
  };
}

function normalizeSigning(value: unknown): NormalizedStoreOptions["signing"] {
  if (value === undefined) return undefined;
  const record = ownDataRecord(value, "signing");
  assertOnlyKeys(record, ["keyId", "privateKey"], "signing");
  const keyId = boundedIdentifier(record.keyId, "signing.keyId");
  try {
    const privateKey = record.privateKey instanceof KeyObject
      ? record.privateKey
      : createPrivateKey(record.privateKey as Exclude<KeyLike, KeyObject>);
    if (privateKey.type !== "private") throw new TypeError("signing key must be private");
    if (privateKey.asymmetricKeyType !== "ed25519") throw new TypeError("signing key must be Ed25519");
    return { keyId, privateKey };
  } catch (error) {
    throw new TypeError(`invalid Ed25519 signing key: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function normalizeVerificationKeys(value: unknown): Map<string, ReturnType<typeof createPublicKey>> {
  const result = new Map<string, ReturnType<typeof createPublicKey>>();
  if (value === undefined) return result;
  const record = ownDataRecord(value, "verificationKeys");
  if (Object.keys(record).length > 64) throw new RangeError("verificationKeys exceeds 64 key limit");
  for (const [rawKeyId, rawKey] of Object.entries(record)) {
    const keyId = boundedIdentifier(rawKeyId, "verification key id");
    try {
      const publicKey = rawKey instanceof KeyObject && rawKey.type === "public"
        ? rawKey
        : createPublicKey(rawKey as Exclude<KeyLike, KeyObject>);
      if (publicKey.asymmetricKeyType !== "ed25519") throw new TypeError("verification key must be Ed25519");
      result.set(keyId, publicKey);
    } catch (error) {
      throw new TypeError(`invalid Ed25519 verification key '${keyId}': ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  return result;
}

function normalizeStartInput(raw: StartExecutionReceiptInput, limits: CanonicalLimits) {
  const record = ownDataRecord(raw, "StartExecutionReceiptInput");
  assertOnlyKeys(record, [
    "scope", "toolKeyDigest", "descriptorDigest", "args", "proofId", "decision",
    "riskLevel", "matchedRuleIds", "policyDigest", "contractDigest",
    "toolManifestDigest", "selectionPolicyDigest", "ledgerPolicyDigest",
    "approvalTicketDigest", "timestamp",
  ], "StartExecutionReceiptInput");
  if (!Object.hasOwn(record, "args")) throw new TypeError("args is required");
  const scope = normalizeScope(record.scope);
  // Canonicalize now so an accessor/cycle/oversized value cannot be retained
  // and changed between validation and the commitment below.
  digestCanonicalValue(record.args, limits);
  if (!isDecision(record.decision)) throw new TypeError("invalid receipt decision");
  if (!isRiskLevel(record.riskLevel)) throw new TypeError("invalid receipt risk level");
  const matchedRuleIds = stringArray(record.matchedRuleIds, "matchedRuleIds", EXECUTION_RECEIPT_LIMITS.maxMatchedRules);
  return {
    scope,
    toolKeyDigest: requiredDigest(record.toolKeyDigest, "toolKeyDigest"),
    descriptorDigest: requiredDigest(record.descriptorDigest, "descriptorDigest"),
    args: record.args,
    proofId: boundedString(record.proofId, "proofId"),
    decision: record.decision,
    riskLevel: record.riskLevel,
    matchedRuleIds,
    policyDigest: optionalDigest(record.policyDigest, "policyDigest"),
    contractDigest: optionalDigest(record.contractDigest, "contractDigest"),
    toolManifestDigest: optionalDigest(record.toolManifestDigest, "toolManifestDigest"),
    selectionPolicyDigest: optionalDigest(record.selectionPolicyDigest, "selectionPolicyDigest"),
    ledgerPolicyDigest: optionalDigest(record.ledgerPolicyDigest, "ledgerPolicyDigest"),
    approvalTicketDigest: optionalDigest(record.approvalTicketDigest, "approvalTicketDigest"),
    timestamp: optionalTimestamp(record.timestamp, "timestamp"),
  };
}

function normalizeScope(value: unknown): ExecutionScope {
  const record = ownDataRecord(value, "ExecutionScope");
  assertOnlyKeys(record, ["tenantId", "userId", "taskId", "sessionId", "traceId", "stepId"], "ExecutionScope");
  const result: ExecutionScope = {};
  for (const key of ["tenantId", "userId", "taskId", "sessionId", "traceId", "stepId"] as const) {
    if (record[key] !== undefined) result[key] = boundedString(record[key], `scope.${key}`);
  }
  if (Object.keys(result).length === 0) throw new TypeError("ExecutionScope must contain at least one identifier");
  return result;
}

function normalizeSettlement(raw: SettleExecutionReceiptInput, limits: CanonicalLimits) {
  const record = ownDataRecord(raw, "SettleExecutionReceiptInput");
  assertOnlyKeys(record, ["outcome", "result", "errorCode", "effectEvidence", "timestamp"], "SettleExecutionReceiptInput");
  if (!isOutcome(record.outcome)) throw new TypeError("invalid execution outcome");
  const hasResult = Object.hasOwn(record, "result");
  if (hasResult) digestCanonicalValue(record.result, limits);
  if (record.outcome === "success" && !hasResult) throw new TypeError("successful receipt settlement requires a result");
  if (record.errorCode !== undefined &&
      !(typeof record.errorCode === "string" || (Number.isSafeInteger(record.errorCode)))) {
    throw new TypeError("errorCode must be a safe integer or string");
  }
  const effectEvidence = normalizeEffectEvidence(record.effectEvidence);
  return {
    outcome: record.outcome,
    result: record.result,
    hasResult,
    errorCode: record.errorCode as number | string | undefined,
    effectEvidence,
    timestamp: optionalTimestamp(record.timestamp, "timestamp"),
  };
}

function normalizeEffectEvidence(value: unknown): EffectEvidence[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || utilTypes.isProxy(value)) throw new TypeError("effectEvidence must be an array");
  assertDenseDataArray(value, "effectEvidence");
  if (value.length > EXECUTION_RECEIPT_LIMITS.maxEffectEvidence) throw new RangeError("too many effect evidence entries");
  return value.map((entry, index) => {
    const record = ownDataRecord(entry, `effectEvidence[${index}]`);
    assertOnlyKeys(record, ["kind", "status", "digest"], `effectEvidence[${index}]`);
    if (!isEffectKind(record.kind)) throw new TypeError(`invalid effectEvidence[${index}].kind`);
    if (!isEffectStatus(record.status)) throw new TypeError(`invalid effectEvidence[${index}].status`);
    const digest = optionalDigest(record.digest, `effectEvidence[${index}].digest`);
    return { kind: record.kind, status: record.status, ...(digest ? { digest } : {}) };
  });
}

function parseAndVerifyEvent(raw: string, receiptId: string, options: NormalizedStoreOptions): ExecutionReceiptEvent {
  if (Buffer.byteLength(raw, "utf-8") > EXECUTION_RECEIPT_LIMITS.maxEventBytes) throw new RangeError("receipt event is too large");
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw new Error("receipt event contains invalid JSON"); }
  const record = ownDataRecord(parsed, "receipt event");
  assertOnlyKeys(record, [
    "format", "receiptId", "sequence", "stage", "timestamp", "previousHash",
    "data", "eventHash", "signature",
  ], "receipt event");
  if (record.format !== EVENT_FORMAT || record.receiptId !== receiptId) throw new Error("receipt event identity mismatch");
  if (!Number.isSafeInteger(record.sequence) || (record.sequence as number) < 1 || (record.sequence as number) > 3) {
    throw new Error("invalid receipt event sequence");
  }
  const timestamp = requiredTimestamp(record.timestamp, "event timestamp");
  const previousHash = record.previousHash === null ? null : requiredDigest(record.previousHash, "previousHash");
  const eventHash = requiredDigest(record.eventHash, "eventHash");
  const stage = record.stage;
  if (!["decision", "dispatch", "result", "not_dispatched"].includes(stage as string)) {
    throw new Error("invalid receipt event stage");
  }
  const unsigned = {
    format: EVENT_FORMAT,
    receiptId,
    sequence: record.sequence,
    stage,
    timestamp,
    previousHash,
    data: record.data,
  };
  if (digestCanonicalValue(unsigned, options.canonical) !== eventHash) throw new Error("receipt event hash mismatch");
  const signature = parseSignature(record.signature);
  if (options.requireSignature && !signature) throw new Error("receipt event signature is required");
  if (signature) {
    const publicKey = options.verificationKeys.get(signature.keyId);
    if (!publicKey) throw new Error(`unknown receipt signature key: ${signature.keyId}`);
    const valid = verifyBytes(null, Buffer.from(eventHash, "hex"), publicKey, Buffer.from(signature.value, "base64"));
    if (!valid) throw new Error("receipt event signature verification failed");
  }
  // Reuse the canonical normalizers for the data payload and reconstruct an
  // immutable typed event. This also rejects unknown fields inside data.
  const data = normalizeStoredEventData(stage as ExecutionReceiptEvent["stage"], record.data);
  return { ...unsigned, stage, data, eventHash, ...(signature ? { signature } : {}) } as ExecutionReceiptEvent;
}

function normalizeStoredEventData(stage: ExecutionReceiptEvent["stage"], value: unknown): ExecutionReceiptEvent["data"] {
  const record = ownDataRecord(value, `${stage} event data`);
  if (stage === "decision") {
    assertOnlyKeys(record, [
      "scopeDigest", "toolKeyDigest", "descriptorDigest", "argsDigest", "proofIdDigest",
      "decision", "riskLevel", "matchedRuleIds", "policyDigest", "contractDigest",
      "toolManifestDigest", "selectionPolicyDigest", "ledgerPolicyDigest", "approvalTicketDigest",
    ], "decision event data");
    if (!isDecision(record.decision) || !isRiskLevel(record.riskLevel)) throw new Error("invalid stored decision data");
    return {
      scopeDigest: requiredDigest(record.scopeDigest, "scopeDigest"),
      toolKeyDigest: requiredDigest(record.toolKeyDigest, "toolKeyDigest"),
      descriptorDigest: requiredDigest(record.descriptorDigest, "descriptorDigest"),
      argsDigest: requiredDigest(record.argsDigest, "argsDigest"),
      proofIdDigest: requiredDigest(record.proofIdDigest, "proofIdDigest"),
      decision: record.decision,
      riskLevel: record.riskLevel,
      matchedRuleIds: stringArray(record.matchedRuleIds, "matchedRuleIds", EXECUTION_RECEIPT_LIMITS.maxMatchedRules),
      policyDigest: requiredDigest(record.policyDigest, "policyDigest"),
      ...(record.contractDigest ? { contractDigest: requiredDigest(record.contractDigest, "contractDigest") } : {}),
      ...(record.toolManifestDigest
        ? { toolManifestDigest: requiredDigest(record.toolManifestDigest, "toolManifestDigest") }
        : {}),
      ...(record.selectionPolicyDigest
        ? { selectionPolicyDigest: requiredDigest(record.selectionPolicyDigest, "selectionPolicyDigest") }
        : {}),
      ...(record.ledgerPolicyDigest
        ? { ledgerPolicyDigest: requiredDigest(record.ledgerPolicyDigest, "ledgerPolicyDigest") }
        : {}),
      ...(record.approvalTicketDigest ? { approvalTicketDigest: requiredDigest(record.approvalTicketDigest, "approvalTicketDigest") } : {}),
    };
  }
  if (stage === "dispatch") {
    assertOnlyKeys(record, ["requestDigest"], "dispatch event data");
    return { requestDigest: requiredDigest(record.requestDigest, "requestDigest") };
  }
  if (stage === "not_dispatched") {
    assertOnlyKeys(record, ["reason"], "not-dispatched event data");
    if (!isNoDispatchReason(record.reason)) throw new Error("invalid stored no-dispatch reason");
    return { reason: record.reason };
  }
  assertOnlyKeys(record, ["outcome", "resultDigest", "errorCode", "effectEvidence"], "result event data");
  if (!isOutcome(record.outcome)) throw new Error("invalid stored execution outcome");
  if (record.errorCode !== undefined &&
      !(typeof record.errorCode === "string" || Number.isSafeInteger(record.errorCode))) {
    throw new Error("invalid stored error code");
  }
  return {
    outcome: record.outcome,
    ...(record.resultDigest ? { resultDigest: requiredDigest(record.resultDigest, "resultDigest") } : {}),
    ...(record.errorCode !== undefined ? { errorCode: record.errorCode as string | number } : {}),
    effectEvidence: normalizeEffectEvidence(record.effectEvidence),
  };
}

function verifyEventChain(events: ExecutionReceiptEvent[]): void {
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    if (event.sequence !== index + 1) throw new Error("receipt event sequence is not monotonic");
    const expectedPrevious = index === 0 ? null : events[index - 1].eventHash;
    if (event.previousHash !== expectedPrevious) throw new Error("receipt event hash chain is broken");
  }
  if (events[0]?.stage !== "decision") throw new Error("receipt must start with a decision event");
  if (events[1] && !["dispatch", "not_dispatched"].includes(events[1].stage)) throw new Error("invalid receipt second stage");
  if (events[2] && events[2].stage !== "result") throw new Error("dispatched receipt must end with a result event");
}

function receiptFromEvents(receiptId: string, events: ExecutionReceiptEvent[]): ExecutionReceipt {
  verifyEventChain(events);
  const last = events.at(-1)!;
  const state = last.stage === "decision"
    ? "decided"
    : last.stage === "dispatch"
      ? "dispatched"
      : last.stage === "result"
        ? "settled"
        : "not_dispatched";
  return {
    receiptId,
    state,
    events: events.map((event) => structuredClone(event)),
    chainHead: last.eventHash,
    signed: events.every((event) => event.signature !== undefined),
  };
}

function signEventHash(eventHash: string, keyId: string, privateKey: ReturnType<typeof createPrivateKey>): ReceiptSignature {
  return {
    algorithm: "ed25519",
    keyId,
    value: signBytes(null, Buffer.from(eventHash, "hex"), privateKey).toString("base64"),
  };
}

function parseSignature(value: unknown): ReceiptSignature | undefined {
  if (value === undefined) return undefined;
  const record = ownDataRecord(value, "receipt signature");
  assertOnlyKeys(record, ["algorithm", "keyId", "value"], "receipt signature");
  if (record.algorithm !== "ed25519") throw new Error("unsupported receipt signature algorithm");
  const keyId = boundedIdentifier(record.keyId, "signature keyId");
  const signature = boundedString(record.value, "signature value", 512);
  const decoded = Buffer.from(signature, "base64");
  if (decoded.length !== 64 || decoded.toString("base64") !== signature) throw new Error("invalid Ed25519 signature encoding");
  return { algorithm: "ed25519", keyId, value: signature };
}

function canonicalJson(value: unknown, depth: number, state: { nodes: number; ancestors: Set<object> }, limits: CanonicalLimits): string {
  if (depth > limits.maxDepth) throw new RangeError(`canonical value exceeds depth ${limits.maxDepth}`);
  state.nodes += 1;
  if (state.nodes > limits.maxNodes) throw new RangeError(`canonical value exceeds ${limits.maxNodes} node limit`);
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(boundedString(value, "canonical string", EXECUTION_RECEIPT_LIMITS.maxStringLength));
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonical value contains a non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw new TypeError(`canonical value contains unsupported ${typeof value}`);
  if (utilTypes.isProxy(value)) throw new TypeError("canonical value must not contain Proxy objects");
  if (state.ancestors.has(value)) throw new TypeError("canonical value must not contain cycles");
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      assertDenseDataArray(value, "canonical array");
      return `[${value.map((entry) => canonicalJson(entry, depth + 1, state, limits)).join(",")}]`;
    }
    const record = ownDataRecord(value, "canonical object");
    const entries = Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(record[key], depth + 1, state, limits)}`);
    return `{${entries.join(",")}}`;
  } finally {
    state.ancestors.delete(value);
  }
}

function normalizeCanonicalLimits(raw: Partial<CanonicalLimits>): CanonicalLimits {
  return {
    maxCanonicalBytes: boundedInteger(
      raw.maxCanonicalBytes ?? EXECUTION_RECEIPT_LIMITS.maxCanonicalBytes,
      "maxCanonicalBytes", 1, 16 * 1024 * 1024,
    ),
    maxDepth: boundedInteger(raw.maxDepth ?? EXECUTION_RECEIPT_LIMITS.maxDepth, "maxDepth", 1, 128),
    maxNodes: boundedInteger(raw.maxNodes ?? EXECUTION_RECEIPT_LIMITS.maxNodes, "maxNodes", 1, 200_000),
  };
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
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (key === "length" || /^\d+$/u.test(key)) continue;
    if (descriptor.enumerable) throw new TypeError(`${label} contains a non-JSON property`);
  }
}

function stringArray(value: unknown, label: string, maximum: number): string[] {
  if (!Array.isArray(value) || utilTypes.isProxy(value)) throw new TypeError(`${label} must be an array`);
  assertDenseDataArray(value, label);
  if (value.length > maximum) throw new RangeError(`${label} exceeds ${maximum} item limit`);
  const normalized = value.map((entry, index) => boundedIdentifier(entry, `${label}[${index}]`));
  if (new Set(normalized).size !== normalized.length) throw new TypeError(`${label} contains duplicates`);
  return normalized;
}

function writeEvent(directory: string, name: string, event: ExecutionReceiptEvent): void {
  assertPrivateDirectory(directory, "execution receipt directory");
  const serialized = `${JSON.stringify(event)}\n`;
  if (Buffer.byteLength(serialized, "utf-8") > EXECUTION_RECEIPT_LIMITS.maxEventBytes) throw new RangeError("receipt event is too large");
  const path = resolve(directory, name);
  writeFileSync(path, serialized, { encoding: "utf-8", flag: "wx", mode: 0o600 });
  chmodSync(path, 0o600);
}

function readPrivateFile(path: string): string {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const stats = fstatSync(fd);
    if (!stats.isFile() || stats.size > EXECUTION_RECEIPT_LIMITS.maxEventBytes) throw new Error("invalid receipt event file");
    return readFileSync(fd, "utf-8");
  } finally {
    closeSync(fd);
  }
}

function mkdirPrivate(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  chmodSync(path, 0o700);
  assertPrivateDirectory(path, "execution receipt base directory");
}

function assertPrivateDirectory(path: string, label: string): void {
  const stats = lstatSync(path);
  if (!stats.isDirectory() || stats.isSymbolicLink()) throw new Error(`${label} must be a real directory`);
}

function countReceiptDirs(baseDir: string): number {
  return readdirSync(baseDir).filter((name) => RECEIPT_ID.test(name)).length;
}

function receiptDirectory(baseDir: string, receiptId: string): string {
  const validated = validateReceiptId(receiptId);
  const path = resolve(baseDir, validated);
  if (basename(path) !== validated) throw new Error("invalid receipt path");
  return path;
}

function validateReceiptId(value: unknown): string {
  if (typeof value !== "string" || !RECEIPT_ID.test(value)) throw new TypeError("invalid execution receipt id");
  return value;
}

function requiredDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError(`${label} must be a lowercase SHA-256 digest`);
  return value;
}

function optionalDigest(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : requiredDigest(value, label);
}

function boundedString(
  value: unknown,
  label: string,
  maximum: number = EXECUTION_RECEIPT_LIMITS.maxStringLength,
): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new RangeError(`${label} must contain between 1 and ${maximum} characters`);
  }
  if (/\p{Cc}/u.test(value)) throw new TypeError(`${label} must not contain control characters`);
  return value;
}

function boundedIdentifier(value: unknown, label: string): string {
  const result = boundedString(value, label, 256);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u.test(result)) throw new TypeError(`${label} contains unsupported characters`);
  return result;
}

function boundedInteger(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new RangeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function requiredTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length > 64) throw new TypeError(`${label} must be an RFC3339 timestamp`);
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) throw new TypeError(`${label} must be an RFC3339 timestamp`);
  return new Date(parsed).toISOString();
}

function optionalTimestamp(value: unknown, label: string): string | undefined {
  return value === undefined ? undefined : requiredTimestamp(value, label);
}

function clockTimestamp(clock: () => Date): string {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new TypeError("receipt clock must return a valid Date");
  return value.toISOString();
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex");
}

function isDecision(value: unknown): value is StartExecutionReceiptInput["decision"] {
  return value === "allow" || value === "require_approval" || value === "deny";
}

function isRiskLevel(value: unknown): value is StartExecutionReceiptInput["riskLevel"] {
  return value === "low" || value === "medium" || value === "high" || value === "critical";
}

function isOutcome(value: unknown): value is ExecutionOutcome {
  return ["success", "mcp_error", "jsonrpc_error", "timeout", "transport_error", "local_error"].includes(value as string);
}

function isNoDispatchReason(value: unknown): value is NoDispatchReason {
  return ["policy_block", "approval_required", "approval_rejected", "authorization_failed", "local_error"].includes(value as string);
}

function isEffectKind(value: unknown): value is EffectEvidenceKind {
  return ["canary", "egress_gateway", "sandbox", "target_system", "os_audit"].includes(value as string);
}

function isEffectStatus(value: unknown): value is EffectEvidenceStatus {
  return value === "confirmed" || value === "contradicted" || value === "inconclusive";
}
