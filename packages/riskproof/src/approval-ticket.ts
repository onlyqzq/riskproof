// ============================================================================
// RiskProof — single-use, parameter-bound approval tickets
// ============================================================================
//
// An approval is authority, not model-controlled metadata. This module issues
// short-lived Ed25519 tickets whose signed payload binds the complete execution
// context: tenant/user/task/session/trace, ToolKey, descriptor and canonical
// arguments, effect/resource/destination, principal, and policy/contract state.
//
// Verification and replay consumption are intentionally exposed as one
// operation. A replay-store implementation MUST provide atomic insert-if-absent
// semantics. The in-memory implementation does so for one Node.js process;
// distributed deployments must back the interface with a durable unique key.

import {
  createHash,
  randomBytes,
  sign as ed25519Sign,
  timingSafeEqual,
  verify as ed25519Verify,
  KeyObject,
} from "node:crypto";
import { types as utilTypes } from "node:util";

export const APPROVAL_TICKET_VERSION = "riskproof-approval-v1" as const;
export const APPROVAL_TICKET_ALGORITHM = "Ed25519" as const;

export const APPROVAL_TICKET_LIMITS = Object.freeze({
  maxTicketBytes: 64 * 1024,
  maxArgumentsBytes: 512 * 1024,
  maxArgumentDepth: 32,
  maxArgumentNodes: 20_000,
  maxIdentifierBytes: 256,
  maxResourceBytes: 4 * 1024,
  maxJsonDepth: 8,
  maxJsonNodes: 128,
  defaultTtlMs: 5 * 60 * 1_000,
  maxTtlMs: 15 * 60 * 1_000,
  maxClockSkewMs: 30 * 1_000,
  maxEvents: 1_024,
  maxReplayEntries: 100_000,
});

const SHA256_DIGEST = /^[a-f0-9]{64}$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/;
const SAFE_KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const SIGNATURE_DOMAIN = "RiskProof Approval Ticket v1\0";
const REPLAY_DOMAIN = "RiskProof Approval Ticket Replay v1\0";
const TOOL_KEY_DOMAIN = "RiskProof ToolKey v1\0";

type JsonPrimitive = null | boolean | number | string;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface ApprovalTicketToolKey {
  readonly providerId: string;
  readonly serverId: string;
  readonly toolName: string;
}

export interface ApprovalTicketEffect {
  readonly type: string;
  readonly resource: string;
  /** Explicit null means the approved effect has no external destination. */
  readonly destination: string | null;
}

export interface ApprovalTicketPrincipal {
  readonly type: string;
  readonly id: string;
}

/** Host-side issuance request. `arguments` are committed, never embedded. */
export interface ApprovalTicketBinding {
  readonly tenantId: string;
  readonly userId: string;
  readonly taskId: string;
  readonly sessionId: string;
  readonly traceId: string;
  readonly tool: ApprovalTicketToolKey;
  readonly descriptorDigest: string;
  readonly arguments: unknown;
  readonly effect: ApprovalTicketEffect;
  readonly principal: ApprovalTicketPrincipal;
  readonly policyDigest: string;
  readonly contractDigest: string;
}

export interface ApprovalTicketPayload {
  readonly version: typeof APPROVAL_TICKET_VERSION;
  readonly algorithm: typeof APPROVAL_TICKET_ALGORITHM;
  readonly keyId: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly taskId: string;
  readonly sessionId: string;
  readonly traceId: string;
  readonly tool: ApprovalTicketToolKey;
  readonly descriptorDigest: string;
  readonly argumentsDigest: string;
  readonly effect: ApprovalTicketEffect;
  readonly principal: ApprovalTicketPrincipal;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly nonce: string;
  readonly policyDigest: string;
  readonly contractDigest: string;
}

export interface SignedApprovalTicket {
  readonly payload: ApprovalTicketPayload;
  /** Canonical unpadded base64url Ed25519 signature (64 bytes). */
  readonly signature: string;
}

export interface ApprovalTicketIssuerOptions {
  readonly keyId: string;
  readonly privateKey: KeyObject;
  readonly ttlMs?: number;
  readonly clock?: () => Date;
  /** Test/HSM hook. Production callers should use the random default. */
  readonly nonceFactory?: () => string;
}

export interface ApprovalTicketTrustStore {
  /** Return only an operator-trusted Ed25519 public key for this exact keyId. */
  getPublicKey(keyId: string): KeyObject | undefined | Promise<KeyObject | undefined>;
}

export interface ApprovalTicketReplayRecord {
  /** SHA-256 domain-separated commitment to keyId + nonce. */
  readonly replayKey: string;
  readonly ticketDigest: string;
  readonly expiresAtMs: number;
}

/**
 * Replay persistence contract.
 *
 * Implementations MUST atomically insert `replayKey` iff it does not exist and
 * return true exactly once. Use a UNIQUE/conditional-write key in persistent
 * stores, retain it at least through expiresAtMs, return false on conflict, and
 * throw on storage uncertainty. Never evict an unexpired entry to make room.
 */
export interface ApprovalTicketReplayStore {
  consumeOnce(
    record: ApprovalTicketReplayRecord,
  ): boolean | Promise<boolean>;
}

export type ApprovalTicketBindingField =
  | "tenant"
  | "user"
  | "task"
  | "session"
  | "trace"
  | "tool"
  | "descriptor"
  | "arguments"
  | "effect"
  | "principal"
  | "policy"
  | "contract";

export type ApprovalTicketFailureCode =
  | "malformed_ticket"
  | "unknown_key"
  | "invalid_signature"
  | "not_yet_valid"
  | "expired"
  | "ttl_exceeded"
  | "binding_mismatch"
  | "replayed"
  | "trust_store_error"
  | "replay_store_error";

export interface ApprovalTicketAccepted {
  readonly ok: true;
  readonly ticketDigest: string;
  readonly keyIdDigest: string;
  readonly expiresAt: string;
}

export interface ApprovalTicketDenied {
  readonly ok: false;
  readonly code: ApprovalTicketFailureCode;
  readonly binding?: ApprovalTicketBindingField;
}

export type ApprovalTicketVerificationResult =
  | ApprovalTicketAccepted
  | ApprovalTicketDenied;

export interface ApprovalTicketAuditEvent {
  readonly sequence: number;
  readonly observedAt: string;
  readonly outcome: "accepted" | "denied" | "error";
  readonly code: "accepted" | ApprovalTicketFailureCode;
  readonly binding?: ApprovalTicketBindingField;
  readonly ticketDigest?: string;
  readonly keyIdDigest?: string;
  readonly nonceDigest?: string;
  readonly taskDigest?: string;
  readonly sessionDigest?: string;
  readonly traceDigest?: string;
  readonly toolKeyDigest?: string;
}

export interface ApprovalTicketVerifierOptions {
  readonly trustStore: ApprovalTicketTrustStore;
  readonly replayStore: ApprovalTicketReplayStore;
  readonly clock?: () => Date;
  readonly maxClockSkewMs?: number;
  readonly maxTtlMs?: number;
  readonly maxEvents?: number;
}

export interface InMemoryApprovalTicketReplayStoreOptions {
  readonly clock?: () => Date;
  readonly maxEntries?: number;
}

export class ApprovalTicketValidationError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalTicketValidationError";
  }
}

/** Static, immutable keyId -> Ed25519 public-key trust store. */
export class StaticApprovalTicketTrustStore implements ApprovalTicketTrustStore {
  private readonly keys = new Map<string, KeyObject>();

  constructor(entries: Readonly<Record<string, KeyObject>> | ReadonlyMap<string, KeyObject>) {
    const iterable: Iterable<readonly [string, KeyObject]> = entries instanceof Map
      ? entries.entries()
      : Object.entries(ownDataRecord(entries, "approval trust store"))
        .map(([keyId, value]) => [keyId, value as KeyObject] as const);
    for (const [rawKeyId, rawKey] of iterable) {
      const keyId = boundedIdentifier(rawKeyId, "keyId", true);
      const key = requireEd25519Key(rawKey, "public", `trust store key '${keyId}'`);
      if (this.keys.has(keyId)) throw validationError("approval trust store contains duplicate keyId");
      this.keys.set(keyId, key);
    }
    if (this.keys.size === 0) throw validationError("approval trust store must contain a key");
  }

  getPublicKey(keyId: string): KeyObject | undefined {
    return this.keys.get(keyId);
  }
}

/**
 * Process-local atomic replay protection.
 *
 * JavaScript execution is run-to-completion, so the check+set below is atomic
 * within one process even when many verifier promises converge concurrently.
 * State is lost on restart and is not shared across workers or replicas.
 */
export class InMemoryApprovalTicketReplayStore implements ApprovalTicketReplayStore {
  private readonly entries = new Map<string, number>();
  private readonly clock: () => Date;
  private readonly maxEntries: number;
  private clockHighWatermarkMs = Number.NEGATIVE_INFINITY;

  constructor(options: InMemoryApprovalTicketReplayStoreOptions = {}) {
    const record = ownDataRecord(options, "InMemoryApprovalTicketReplayStore options");
    assertOnlyKeys(record, ["clock", "maxEntries"], "InMemoryApprovalTicketReplayStore options");
    this.clock = optionalClock(record.clock, "replay-store clock");
    this.maxEntries = record.maxEntries === undefined
      ? APPROVAL_TICKET_LIMITS.maxReplayEntries
      : boundedPositiveInteger(
        record.maxEntries,
        "maxEntries",
        APPROVAL_TICKET_LIMITS.maxReplayEntries,
      );
  }

  consumeOnce(rawRecord: ApprovalTicketReplayRecord): boolean {
    const record = normalizeReplayRecord(rawRecord);
    const now = this.currentTimeMs();
    this.purgeExpired(now);
    if (record.expiresAtMs <= now) {
      throw new Error("cannot consume an already-expired approval replay record");
    }
    if (this.entries.has(record.replayKey)) return false;
    if (this.entries.size >= this.maxEntries) {
      throw new Error("approval replay store is full; refusing to evict unexpired entries");
    }
    this.entries.set(record.replayKey, record.expiresAtMs);
    return true;
  }

  size(): number {
    this.purgeExpired(this.currentTimeMs());
    return this.entries.size;
  }

  private currentTimeMs(): number {
    const observed = trustedNow(this.clock, "replay-store clock").getTime();
    this.clockHighWatermarkMs = Math.max(this.clockHighWatermarkMs, observed);
    return this.clockHighWatermarkMs;
  }

  private purgeExpired(now: number): void {
    for (const [key, expiresAt] of this.entries) {
      if (expiresAt <= now) this.entries.delete(key);
    }
  }
}

/** Canonical, bounded JSON commitment for actual MCP tool arguments. */
export function canonicalizeApprovalArguments(value: unknown): string {
  const state: CanonicalState = { nodes: 0, scalarBytes: 0, ancestors: new Set<object>() };
  const canonical = canonicalJsonValue(
    value,
    "arguments",
    0,
    state,
    APPROVAL_TICKET_LIMITS.maxArgumentDepth,
    APPROVAL_TICKET_LIMITS.maxArgumentNodes,
  );
  if (Buffer.byteLength(canonical, "utf8") > APPROVAL_TICKET_LIMITS.maxArgumentsBytes) {
    throw new RangeError(
      `arguments exceed ${APPROVAL_TICKET_LIMITS.maxArgumentsBytes} byte limit`,
    );
  }
  return canonical;
}

export function digestApprovalArguments(value: unknown): string {
  return sha256(canonicalizeApprovalArguments(value));
}

/** Issue a short-lived, single-purpose Ed25519 ticket. */
export function issueApprovalTicket(
  rawBinding: ApprovalTicketBinding,
  rawOptions: ApprovalTicketIssuerOptions,
): SignedApprovalTicket {
  const binding = normalizeBinding(rawBinding);
  const options = normalizeIssuerOptions(rawOptions);
  const now = trustedNow(options.clock, "approval issuer clock");
  const issuedAtMs = now.getTime();
  const expiresAtMs = issuedAtMs + options.ttlMs;
  if (!Number.isSafeInteger(expiresAtMs)) throw new RangeError("approval ticket expiry is out of range");
  const nonce = normalizeNonce(options.nonceFactory());
  const payload = freezePayload({
    version: APPROVAL_TICKET_VERSION,
    algorithm: APPROVAL_TICKET_ALGORITHM,
    keyId: options.keyId,
    tenantId: binding.tenantId,
    userId: binding.userId,
    taskId: binding.taskId,
    sessionId: binding.sessionId,
    traceId: binding.traceId,
    tool: binding.tool,
    descriptorDigest: binding.descriptorDigest,
    argumentsDigest: binding.argumentsDigest,
    effect: binding.effect,
    principal: binding.principal,
    issuedAt: new Date(issuedAtMs).toISOString(),
    expiresAt: new Date(expiresAtMs).toISOString(),
    nonce,
    policyDigest: binding.policyDigest,
    contractDigest: binding.contractDigest,
  });
  const signature = ed25519Sign(
    null,
    signatureInput(payload),
    options.privateKey,
  ).toString("base64url");
  return Object.freeze({ payload, signature });
}

/** Strictly parse/snapshot either raw JSON or an object-form signed ticket. */
export function parseApprovalTicket(value: string | unknown): SignedApprovalTicket {
  let parsed: unknown = value;
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > APPROVAL_TICKET_LIMITS.maxTicketBytes) {
      throw new RangeError(`approval ticket exceeds ${APPROVAL_TICKET_LIMITS.maxTicketBytes} byte limit`);
    }
    parsed = new StrictJsonParser(value).parse();
  }
  const envelope = ownDataRecord(parsed, "approval ticket");
  assertOnlyKeys(envelope, ["payload", "signature"], "approval ticket");
  const payload = normalizePayload(envelope.payload);
  const signature = normalizeSignature(envelope.signature);
  const ticket = Object.freeze({ payload, signature });
  if (Buffer.byteLength(canonicalSerializeTicket(ticket), "utf8") > APPROVAL_TICKET_LIMITS.maxTicketBytes) {
    throw new RangeError(`approval ticket exceeds ${APPROVAL_TICKET_LIMITS.maxTicketBytes} byte limit`);
  }
  return ticket;
}

/** Stable transport form. `parseApprovalTicket()` accepts ordinary JSON too. */
export function serializeApprovalTicket(ticket: SignedApprovalTicket): string {
  return canonicalSerializeTicket(parseApprovalTicket(ticket));
}

function canonicalSerializeTicket(ticket: SignedApprovalTicket): string {
  return canonicalJsonValue(
    ticket,
    "approval ticket",
    0,
    { nodes: 0, scalarBytes: 0, ancestors: new Set<object>() },
    APPROVAL_TICKET_LIMITS.maxJsonDepth,
    APPROVAL_TICKET_LIMITS.maxJsonNodes,
  );
}

/**
 * Reference monitor that never exposes a reusable "verified but unconsumed"
 * state. Every successful return follows one atomic replay-store consumption.
 */
export class ApprovalTicketVerifier {
  private readonly trustStore: ApprovalTicketTrustStore;
  private readonly replayStore: ApprovalTicketReplayStore;
  private readonly clock: () => Date;
  private readonly maxClockSkewMs: number;
  private readonly maxTtlMs: number;
  private readonly maxEvents: number;
  private readonly events: ApprovalTicketAuditEvent[] = [];
  private nextSequence = 0;
  private clockHighWatermarkMs = Number.NEGATIVE_INFINITY;

  constructor(rawOptions: ApprovalTicketVerifierOptions) {
    const options = ownDataRecord(rawOptions, "ApprovalTicketVerifier options");
    assertOnlyKeys(
      options,
      ["trustStore", "replayStore", "clock", "maxClockSkewMs", "maxTtlMs", "maxEvents"],
      "ApprovalTicketVerifier options",
    );
    if (!hasCallableMethod(options.trustStore, "getPublicKey")) {
      throw validationError("trustStore must implement getPublicKey(keyId)");
    }
    if (!hasCallableMethod(options.replayStore, "consumeOnce")) {
      throw validationError("replayStore must implement consumeOnce(record)");
    }
    this.trustStore = options.trustStore as ApprovalTicketTrustStore;
    this.replayStore = options.replayStore as ApprovalTicketReplayStore;
    this.clock = optionalClock(options.clock, "approval verifier clock");
    this.maxClockSkewMs = options.maxClockSkewMs === undefined
      ? APPROVAL_TICKET_LIMITS.maxClockSkewMs
      : boundedNonNegativeInteger(
        options.maxClockSkewMs,
        "maxClockSkewMs",
        APPROVAL_TICKET_LIMITS.maxClockSkewMs,
      );
    this.maxTtlMs = options.maxTtlMs === undefined
      ? APPROVAL_TICKET_LIMITS.maxTtlMs
      : boundedPositiveInteger(options.maxTtlMs, "maxTtlMs", APPROVAL_TICKET_LIMITS.maxTtlMs);
    this.maxEvents = options.maxEvents === undefined
      ? APPROVAL_TICKET_LIMITS.maxEvents
      : boundedPositiveInteger(options.maxEvents, "maxEvents", 4_096);
  }

  async verifyAndConsume(
    rawTicket: string | SignedApprovalTicket,
    rawExpected: ApprovalTicketBinding,
  ): Promise<ApprovalTicketVerificationResult> {
    const observedAt = this.currentTime();
    let ticket: SignedApprovalTicket;
    let metadata: AuditMetadata = {};
    try {
      ticket = parseApprovalTicket(rawTicket);
      metadata = auditMetadata(ticket);
    } catch {
      return this.deny("malformed_ticket", observedAt, {}, "denied");
    }

    let expected: NormalizedBinding;
    try {
      expected = normalizeBinding(rawExpected);
    } catch {
      return this.deny("binding_mismatch", observedAt, metadata, "denied");
    }

    let publicKey: KeyObject | undefined;
    try {
      publicKey = await this.trustStore.getPublicKey(ticket.payload.keyId);
    } catch {
      return this.deny("trust_store_error", observedAt, metadata, "error");
    }
    if (publicKey === undefined) {
      return this.deny("unknown_key", observedAt, metadata, "denied");
    }
    try {
      requireEd25519Key(publicKey, "public", "trusted approval public key");
    } catch {
      return this.deny("trust_store_error", observedAt, metadata, "error");
    }

    let signatureValid = false;
    try {
      signatureValid = ed25519Verify(
        null,
        signatureInput(ticket.payload),
        publicKey,
        Buffer.from(ticket.signature, "base64url"),
      );
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) {
      return this.deny("invalid_signature", observedAt, metadata, "denied");
    }

    const issuedAtMs = Date.parse(ticket.payload.issuedAt);
    const expiresAtMs = Date.parse(ticket.payload.expiresAt);
    const ttl = expiresAtMs - issuedAtMs;
    if (ttl > this.maxTtlMs) {
      return this.deny("ttl_exceeded", observedAt, metadata, "denied");
    }
    if (issuedAtMs - observedAt.getTime() > this.maxClockSkewMs) {
      return this.deny("not_yet_valid", observedAt, metadata, "denied");
    }
    if (observedAt.getTime() >= expiresAtMs) {
      return this.deny("expired", observedAt, metadata, "denied");
    }

    const mismatch = firstBindingMismatch(ticket.payload, expected);
    if (mismatch !== undefined) {
      return this.deny("binding_mismatch", observedAt, metadata, "denied", mismatch);
    }

    const replayRecord = Object.freeze({
      replayKey: replayKey(ticket.payload.keyId, ticket.payload.nonce),
      ticketDigest: metadata.ticketDigest as string,
      expiresAtMs,
    });
    let consumed: unknown;
    try {
      consumed = await this.replayStore.consumeOnce(replayRecord);
    } catch {
      return this.deny("replay_store_error", observedAt, metadata, "error");
    }
    if (typeof consumed !== "boolean") {
      return this.deny("replay_store_error", observedAt, metadata, "error");
    }
    if (!consumed) {
      return this.deny("replayed", observedAt, metadata, "denied");
    }

    // If a durable store or remote trust lookup delayed this call beyond the
    // deadline, fail closed after consumption. Burning an expired ticket is safe.
    const completedAt = this.currentTime();
    if (completedAt.getTime() >= expiresAtMs) {
      return this.deny("expired", completedAt, metadata, "denied");
    }
    this.record({
      observedAt: completedAt.toISOString(),
      outcome: "accepted",
      code: "accepted",
      ...metadata,
    });
    return Object.freeze({
      ok: true,
      ticketDigest: metadata.ticketDigest as string,
      keyIdDigest: metadata.keyIdDigest as string,
      expiresAt: ticket.payload.expiresAt,
    });
  }

  /** Metadata commitments only: never arguments, resources, IDs, or nonce. */
  listEvents(): ApprovalTicketAuditEvent[] {
    return this.events.map((event) => Object.freeze({ ...event }));
  }

  private deny(
    code: ApprovalTicketFailureCode,
    observedAt: Date,
    metadata: AuditMetadata,
    outcome: "denied" | "error",
    binding?: ApprovalTicketBindingField,
  ): ApprovalTicketDenied {
    this.record({
      observedAt: observedAt.toISOString(),
      outcome,
      code,
      ...(binding ? { binding } : {}),
      ...metadata,
    });
    return Object.freeze({ ok: false, code, ...(binding ? { binding } : {}) });
  }

  private record(event: Omit<ApprovalTicketAuditEvent, "sequence">): void {
    this.events.push(Object.freeze({ sequence: ++this.nextSequence, ...event }));
    while (this.events.length > this.maxEvents) this.events.shift();
  }

  private currentTime(): Date {
    const observed = trustedNow(this.clock, "approval verifier clock").getTime();
    this.clockHighWatermarkMs = Math.max(this.clockHighWatermarkMs, observed);
    return new Date(this.clockHighWatermarkMs);
  }
}

interface NormalizedBinding {
  tenantId: string;
  userId: string;
  taskId: string;
  sessionId: string;
  traceId: string;
  tool: ApprovalTicketToolKey;
  descriptorDigest: string;
  argumentsDigest: string;
  effect: ApprovalTicketEffect;
  principal: ApprovalTicketPrincipal;
  policyDigest: string;
  contractDigest: string;
}

interface AuditMetadata {
  ticketDigest?: string;
  keyIdDigest?: string;
  nonceDigest?: string;
  taskDigest?: string;
  sessionDigest?: string;
  traceDigest?: string;
  toolKeyDigest?: string;
}

interface NormalizedIssuerOptions {
  keyId: string;
  privateKey: KeyObject;
  ttlMs: number;
  clock: () => Date;
  nonceFactory: () => string;
}

function normalizeBinding(raw: ApprovalTicketBinding): NormalizedBinding {
  const value = ownDataRecord(raw, "approval binding");
  assertOnlyKeys(
    value,
    [
      "tenantId", "userId", "taskId", "sessionId", "traceId", "tool",
      "descriptorDigest", "arguments", "effect", "principal", "policyDigest",
      "contractDigest",
    ],
    "approval binding",
  );
  return Object.freeze({
    tenantId: boundedIdentifier(value.tenantId, "tenantId"),
    userId: boundedIdentifier(value.userId, "userId"),
    taskId: boundedIdentifier(value.taskId, "taskId"),
    sessionId: boundedIdentifier(value.sessionId, "sessionId"),
    traceId: boundedIdentifier(value.traceId, "traceId"),
    tool: normalizeToolKey(value.tool),
    descriptorDigest: requiredDigest(value.descriptorDigest, "descriptorDigest"),
    argumentsDigest: digestApprovalArguments(value.arguments),
    effect: normalizeEffect(value.effect),
    principal: normalizePrincipal(value.principal),
    policyDigest: requiredDigest(value.policyDigest, "policyDigest"),
    contractDigest: requiredDigest(value.contractDigest, "contractDigest"),
  });
}

function normalizePayload(raw: unknown): ApprovalTicketPayload {
  const value = ownDataRecord(raw, "approval ticket payload");
  assertOnlyKeys(
    value,
    [
      "version", "algorithm", "keyId", "tenantId", "userId", "taskId",
      "sessionId", "traceId", "tool", "descriptorDigest", "argumentsDigest",
      "effect", "principal", "issuedAt", "expiresAt", "nonce", "policyDigest",
      "contractDigest",
    ],
    "approval ticket payload",
  );
  if (value.version !== APPROVAL_TICKET_VERSION) {
    throw validationError("unsupported approval ticket version");
  }
  if (value.algorithm !== APPROVAL_TICKET_ALGORITHM) {
    throw validationError("approval ticket algorithm must be Ed25519");
  }
  const issuedAt = canonicalTimestamp(value.issuedAt, "issuedAt");
  const expiresAt = canonicalTimestamp(value.expiresAt, "expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw validationError("approval ticket expiresAt must be after issuedAt");
  }
  return freezePayload({
    version: APPROVAL_TICKET_VERSION,
    algorithm: APPROVAL_TICKET_ALGORITHM,
    keyId: boundedIdentifier(value.keyId, "keyId", true),
    tenantId: boundedIdentifier(value.tenantId, "tenantId"),
    userId: boundedIdentifier(value.userId, "userId"),
    taskId: boundedIdentifier(value.taskId, "taskId"),
    sessionId: boundedIdentifier(value.sessionId, "sessionId"),
    traceId: boundedIdentifier(value.traceId, "traceId"),
    tool: normalizeToolKey(value.tool),
    descriptorDigest: requiredDigest(value.descriptorDigest, "descriptorDigest"),
    argumentsDigest: requiredDigest(value.argumentsDigest, "argumentsDigest"),
    effect: normalizeEffect(value.effect),
    principal: normalizePrincipal(value.principal),
    issuedAt,
    expiresAt,
    nonce: normalizeNonce(value.nonce),
    policyDigest: requiredDigest(value.policyDigest, "policyDigest"),
    contractDigest: requiredDigest(value.contractDigest, "contractDigest"),
  });
}

function freezePayload(payload: ApprovalTicketPayload): ApprovalTicketPayload {
  return Object.freeze({
    ...payload,
    tool: Object.freeze({ ...payload.tool }),
    effect: Object.freeze({ ...payload.effect }),
    principal: Object.freeze({ ...payload.principal }),
  });
}

function normalizeToolKey(raw: unknown): ApprovalTicketToolKey {
  const value = ownDataRecord(raw, "tool");
  assertOnlyKeys(value, ["providerId", "serverId", "toolName"], "tool");
  return Object.freeze({
    providerId: boundedIdentifier(value.providerId, "tool.providerId"),
    serverId: boundedIdentifier(value.serverId, "tool.serverId"),
    toolName: boundedIdentifier(value.toolName, "tool.toolName"),
  });
}

function normalizeEffect(raw: unknown): ApprovalTicketEffect {
  const value = ownDataRecord(raw, "effect");
  assertOnlyKeys(value, ["type", "resource", "destination"], "effect");
  if (value.destination !== null && typeof value.destination !== "string") {
    throw validationError("effect.destination must be a string or explicit null");
  }
  return Object.freeze({
    type: boundedIdentifier(value.type, "effect.type"),
    resource: boundedResource(value.resource, "effect.resource"),
    destination: value.destination === null
      ? null
      : boundedResource(value.destination, "effect.destination"),
  });
}

function normalizePrincipal(raw: unknown): ApprovalTicketPrincipal {
  const value = ownDataRecord(raw, "principal");
  assertOnlyKeys(value, ["type", "id"], "principal");
  return Object.freeze({
    type: boundedIdentifier(value.type, "principal.type"),
    id: boundedIdentifier(value.id, "principal.id"),
  });
}

function normalizeIssuerOptions(raw: ApprovalTicketIssuerOptions): NormalizedIssuerOptions {
  const value = ownDataRecord(raw, "approval issuer options");
  assertOnlyKeys(
    value,
    ["keyId", "privateKey", "ttlMs", "clock", "nonceFactory"],
    "approval issuer options",
  );
  const ttlMs = value.ttlMs === undefined
    ? APPROVAL_TICKET_LIMITS.defaultTtlMs
    : boundedPositiveInteger(value.ttlMs, "ttlMs", APPROVAL_TICKET_LIMITS.maxTtlMs);
  const nonceFactory = value.nonceFactory === undefined
    ? () => randomBytes(32).toString("base64url")
    : value.nonceFactory;
  if (typeof nonceFactory !== "function") throw validationError("nonceFactory must be a function");
  return {
    keyId: boundedIdentifier(value.keyId, "keyId", true),
    privateKey: requireEd25519Key(value.privateKey, "private", "approval private key"),
    ttlMs,
    clock: optionalClock(value.clock, "approval issuer clock"),
    nonceFactory: nonceFactory as () => string,
  };
}

function normalizeReplayRecord(raw: ApprovalTicketReplayRecord): ApprovalTicketReplayRecord {
  const value = ownDataRecord(raw, "approval replay record");
  assertOnlyKeys(value, ["replayKey", "ticketDigest", "expiresAtMs"], "approval replay record");
  const expiresAtMs = value.expiresAtMs;
  if (!Number.isSafeInteger(expiresAtMs) || (expiresAtMs as number) <= 0) {
    throw validationError("replay expiresAtMs must be a positive safe integer");
  }
  return Object.freeze({
    replayKey: requiredDigest(value.replayKey, "replayKey"),
    ticketDigest: requiredDigest(value.ticketDigest, "ticketDigest"),
    expiresAtMs: expiresAtMs as number,
  });
}

function firstBindingMismatch(
  payload: ApprovalTicketPayload,
  expected: NormalizedBinding,
): ApprovalTicketBindingField | undefined {
  if (!safeTextEqual(payload.tenantId, expected.tenantId)) return "tenant";
  if (!safeTextEqual(payload.userId, expected.userId)) return "user";
  if (!safeTextEqual(payload.taskId, expected.taskId)) return "task";
  if (!safeTextEqual(payload.sessionId, expected.sessionId)) return "session";
  if (!safeTextEqual(payload.traceId, expected.traceId)) return "trace";
  if (
    !safeTextEqual(payload.tool.providerId, expected.tool.providerId) ||
    !safeTextEqual(payload.tool.serverId, expected.tool.serverId) ||
    !safeTextEqual(payload.tool.toolName, expected.tool.toolName)
  ) return "tool";
  if (!safeTextEqual(payload.descriptorDigest, expected.descriptorDigest)) return "descriptor";
  if (!safeTextEqual(payload.argumentsDigest, expected.argumentsDigest)) return "arguments";
  if (
    !safeTextEqual(payload.effect.type, expected.effect.type) ||
    !safeTextEqual(payload.effect.resource, expected.effect.resource) ||
    !nullableTextEqual(payload.effect.destination, expected.effect.destination)
  ) return "effect";
  if (
    !safeTextEqual(payload.principal.type, expected.principal.type) ||
    !safeTextEqual(payload.principal.id, expected.principal.id)
  ) return "principal";
  if (!safeTextEqual(payload.policyDigest, expected.policyDigest)) return "policy";
  if (!safeTextEqual(payload.contractDigest, expected.contractDigest)) return "contract";
  return undefined;
}

function signatureInput(payload: ApprovalTicketPayload): Buffer {
  const canonical = canonicalJsonValue(
    payload,
    "approval payload",
    0,
    { nodes: 0, scalarBytes: 0, ancestors: new Set<object>() },
    APPROVAL_TICKET_LIMITS.maxJsonDepth,
    APPROVAL_TICKET_LIMITS.maxJsonNodes,
  );
  return Buffer.from(`${SIGNATURE_DOMAIN}${canonical}`, "utf8");
}

function auditMetadata(ticket: SignedApprovalTicket): AuditMetadata {
  const payload = ticket.payload;
  return Object.freeze({
    ticketDigest: sha256(serializeApprovalTicket(ticket)),
    keyIdDigest: sha256(payload.keyId),
    nonceDigest: sha256(payload.nonce),
    taskDigest: sha256(payload.taskId),
    sessionDigest: sha256(payload.sessionId),
    traceDigest: sha256(payload.traceId),
    toolKeyDigest: sha256(
      `${TOOL_KEY_DOMAIN}${payload.tool.providerId}\0${payload.tool.serverId}\0${payload.tool.toolName}`,
    ),
  });
}

function replayKey(keyId: string, nonce: string): string {
  return sha256(`${REPLAY_DOMAIN}${keyId}\0${nonce}`);
}

function normalizeSignature(value: unknown): string {
  if (typeof value !== "string" || value.length !== 86 || !BASE64URL.test(value)) {
    throw validationError("approval signature must be canonical unpadded base64url");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 64 || decoded.toString("base64url") !== value) {
    throw validationError("approval signature must encode exactly 64 bytes");
  }
  return value;
}

function normalizeNonce(value: unknown): string {
  if (typeof value !== "string" || value.length < 22 || value.length > 128 || !BASE64URL.test(value)) {
    throw validationError("approval nonce must be canonical base64url with at least 128 bits");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length < 16 || decoded.length > 96 || decoded.toString("base64url") !== value) {
    throw validationError("approval nonce must be canonical base64url with at least 128 bits");
  }
  return value;
}

function requireEd25519Key(
  value: unknown,
  type: "public" | "private",
  label: string,
): KeyObject {
  if (
    !(value instanceof KeyObject) || value.type !== type ||
    value.asymmetricKeyType !== "ed25519"
  ) {
    throw validationError(`${label} must be an Ed25519 ${type} KeyObject`);
  }
  return value as KeyObject;
}

function canonicalTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length !== 24) {
    throw validationError(`${label} must be a canonical ISO 8601 UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw validationError(`${label} must be a canonical ISO 8601 UTC timestamp`);
  }
  return value;
}

function boundedIdentifier(value: unknown, label: string, keyId = false): string {
  if (typeof value !== "string") throw validationError(`${label} must be a string`);
  const bytes = Buffer.byteLength(value, "utf8");
  if (
    bytes < 1 || bytes > APPROVAL_TICKET_LIMITS.maxIdentifierBytes ||
    !(keyId ? SAFE_KEY_ID : SAFE_IDENTIFIER).test(value)
  ) {
    throw validationError(`${label} must be a bounded safe identifier`);
  }
  return value;
}

function boundedResource(value: unknown, label: string): string {
  if (typeof value !== "string") throw validationError(`${label} must be a string`);
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes < 1 || bytes > APPROVAL_TICKET_LIMITS.maxResourceBytes || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw validationError(`${label} must be a bounded string without control characters`);
  }
  return value;
}

function requiredDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) {
    throw validationError(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function optionalClock(value: unknown, label: string): () => Date {
  if (value === undefined) return () => new Date();
  if (typeof value !== "function") throw validationError(`${label} must be a function`);
  return value as () => Date;
}

function trustedNow(clock: () => Date, label: string): Date {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw validationError(`${label} must return a valid Date`);
  }
  return new Date(value.getTime());
}

function boundedPositiveInteger(value: unknown, label: string, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > max) {
    throw new RangeError(`${label} must be an integer between 1 and ${max}`);
  }
  return value as number;
}

function boundedNonNegativeInteger(value: unknown, label: string, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > max) {
    throw new RangeError(`${label} must be an integer between 0 and ${max}`);
  }
  return value as number;
}

function nullableTextEqual(left: string | null, right: string | null): boolean {
  if (left === null || right === null) return left === right;
  return safeTextEqual(left, right);
}

function safeTextEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hasCallableMethod(value: unknown, method: string): boolean {
  if (typeof value !== "object" || value === null || utilTypes.isProxy(value)) return false;
  try {
    return typeof (value as Record<string, unknown>)[method] === "function";
  } catch {
    return false;
  }
}

function ownDataRecord(value: unknown, label: string): Record<string, unknown> {
  if (
    typeof value !== "object" || value === null || Array.isArray(value) ||
    utilTypes.isProxy(value)
  ) {
    throw validationError(`${label} must be a non-Proxy object`);
  }
  let prototype: object | null;
  let keys: Array<string | symbol>;
  try {
    prototype = Object.getPrototypeOf(value) as object | null;
    keys = Reflect.ownKeys(value);
  } catch {
    throw validationError(`${label} cannot be inspected safely`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw validationError(`${label} must be a plain object`);
  }
  const result = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    if (typeof key !== "string") throw validationError(`${label} must not contain symbol keys`);
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      throw validationError(`${label} cannot be inspected safely`);
    }
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw validationError(`${label} must contain only enumerable data properties`);
    }
    result[key] = descriptor.value;
  }
  return result;
}

function assertOnlyKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const accepted = new Set(allowed);
  if (Object.keys(record).some((key) => !accepted.has(key))) {
    throw validationError(`${label} contains unsupported field(s)`);
  }
}

function validationError(message: string): ApprovalTicketValidationError {
  return new ApprovalTicketValidationError(message);
}

interface CanonicalState {
  nodes: number;
  scalarBytes: number;
  ancestors: Set<object>;
}

function canonicalJsonValue(
  value: unknown,
  path: string,
  depth: number,
  state: CanonicalState,
  maxDepth: number,
  maxNodes: number,
): string {
  state.nodes += 1;
  if (state.nodes > maxNodes) throw new RangeError(`${path} exceeds maximum node count`);
  if (depth > maxDepth) throw new RangeError(`${path} exceeds maximum depth`);
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean": return value ? "true" : "false";
    case "string": {
      assertWellFormedUnicode(value, path);
      if (Buffer.byteLength(value, "utf8") > APPROVAL_TICKET_LIMITS.maxArgumentsBytes) {
        throw new RangeError(`${path} exceeds canonical JSON byte budget`);
      }
      const encoded = JSON.stringify(value);
      accountCanonicalScalar(state, Buffer.byteLength(encoded, "utf8"), path);
      return encoded;
    }
    case "number": {
      if (!Number.isFinite(value)) throw validationError(`${path} must contain finite JSON numbers`);
      if (Object.is(value, -0)) throw validationError(`${path} must not contain negative zero`);
      return JSON.stringify(value);
    }
    case "object": return canonicalJsonContainer(value, path, depth, state, maxDepth, maxNodes);
    default: throw validationError(`${path} must contain only JSON-compatible values`);
  }
}

function canonicalJsonContainer(
  value: object,
  path: string,
  depth: number,
  state: CanonicalState,
  maxDepth: number,
  maxNodes: number,
): string {
  if (utilTypes.isProxy(value)) throw validationError(`${path} must not contain Proxy objects`);
  if (state.ancestors.has(value)) throw validationError(`${path} contains a circular reference`);
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      for (const key of keys) {
        if (key === "length") continue;
        if (typeof key !== "string" || !isArrayIndex(key)) {
          throw validationError(`${path} must be a dense JSON array without extra properties`);
        }
      }
      if (value.length > maxNodes - state.nodes) {
        throw new RangeError(`${path} exceeds maximum node count`);
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const items: string[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
          throw validationError(`${path} must be a dense accessor-free JSON array`);
        }
        items.push(canonicalJsonValue(
          descriptor.value,
          `${path}[${index}]`,
          depth + 1,
          state,
          maxDepth,
          maxNodes,
        ));
      }
      return `[${items.join(",")}]`;
    }

    const record = ownDataRecord(value, path);
    const entries = Object.keys(record).sort().map((key) => {
      if (key === "__proto__" || key === "prototype" || key === "constructor") {
        throw validationError(`${path} contains a forbidden object key`);
      }
      if (Buffer.byteLength(key, "utf8") > APPROVAL_TICKET_LIMITS.maxArgumentsBytes) {
        throw new RangeError(`${path} exceeds canonical JSON byte budget`);
      }
      assertWellFormedUnicode(key, path);
      const encodedKey = JSON.stringify(key);
      accountCanonicalScalar(state, Buffer.byteLength(encodedKey, "utf8"), path);
      return `${encodedKey}:${canonicalJsonValue(
        record[key],
        `${path}.${key}`,
        depth + 1,
        state,
        maxDepth,
        maxNodes,
      )}`;
    });
    return `{${entries.join(",")}}`;
  } finally {
    state.ancestors.delete(value);
  }
}

function accountCanonicalScalar(state: CanonicalState, bytes: number, path: string): void {
  state.scalarBytes += bytes;
  if (state.scalarBytes > APPROVAL_TICKET_LIMITS.maxArgumentsBytes) {
    throw new RangeError(`${path} exceeds canonical JSON byte budget`);
  }
}

function isArrayIndex(value: string): boolean {
  if (!/^(0|[1-9]\d*)$/.test(value)) return false;
  const index = Number(value);
  return Number.isSafeInteger(index) && index >= 0 && index < 4_294_967_295;
}

function assertWellFormedUnicode(value: string, label: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw validationError(`${label} must not contain unpaired Unicode surrogates`);
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw validationError(`${label} must not contain unpaired Unicode surrogates`);
    }
  }
}

/** Minimal bounded JSON parser that preserves duplicate-key detection. */
class StrictJsonParser {
  private offset = 0;
  private nodes = 0;

  constructor(private readonly source: string) {}

  parse(): JsonValue {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.offset !== this.source.length) throw validationError("approval ticket has trailing JSON data");
    return value;
  }

  private parseValue(depth: number): JsonValue {
    this.nodes += 1;
    if (this.nodes > APPROVAL_TICKET_LIMITS.maxJsonNodes) {
      throw new RangeError("approval ticket JSON exceeds maximum node count");
    }
    if (depth > APPROVAL_TICKET_LIMITS.maxJsonDepth) {
      throw new RangeError("approval ticket JSON exceeds maximum depth");
    }
    const char = this.source[this.offset];
    if (char === "{") return this.parseObject(depth);
    if (char === "[") return this.parseArray(depth);
    if (char === '"') return this.parseString();
    if (char === "t") return this.parseLiteral("true", true);
    if (char === "f") return this.parseLiteral("false", false);
    if (char === "n") return this.parseLiteral("null", null);
    return this.parseNumber();
  }

  private parseObject(depth: number): { [key: string]: JsonValue } {
    this.offset += 1;
    this.skipWhitespace();
    const result = Object.create(null) as { [key: string]: JsonValue };
    const keys = new Set<string>();
    if (this.consume("}")) return result;
    while (true) {
      if (this.source[this.offset] !== '"') throw validationError("approval ticket JSON object key must be a string");
      const key = this.parseString();
      if (keys.has(key)) throw validationError("approval ticket JSON contains a duplicate object key");
      keys.add(key);
      this.skipWhitespace();
      if (!this.consume(":")) throw validationError("approval ticket JSON object is missing ':'");
      this.skipWhitespace();
      result[key] = this.parseValue(depth + 1);
      this.skipWhitespace();
      if (this.consume("}")) return result;
      if (!this.consume(",")) throw validationError("approval ticket JSON object is missing ','");
      this.skipWhitespace();
    }
  }

  private parseArray(depth: number): JsonValue[] {
    this.offset += 1;
    this.skipWhitespace();
    const result: JsonValue[] = [];
    if (this.consume("]")) return result;
    while (true) {
      result.push(this.parseValue(depth + 1));
      this.skipWhitespace();
      if (this.consume("]")) return result;
      if (!this.consume(",")) throw validationError("approval ticket JSON array is missing ','");
      this.skipWhitespace();
    }
  }

  private parseString(): string {
    const start = this.offset;
    this.offset += 1;
    while (this.offset < this.source.length) {
      const code = this.source.charCodeAt(this.offset);
      if (code === 0x22) {
        this.offset += 1;
        const token = this.source.slice(start, this.offset);
        let value: unknown;
        try {
          value = JSON.parse(token) as unknown;
        } catch {
          throw validationError("approval ticket contains an invalid JSON string");
        }
        if (typeof value !== "string") throw validationError("approval ticket contains an invalid JSON string");
        assertWellFormedUnicode(value, "approval ticket JSON string");
        return value;
      }
      if (code < 0x20) throw validationError("approval ticket JSON string contains a control character");
      if (code === 0x5c) {
        this.offset += 1;
        const escaped = this.source[this.offset];
        if (escaped === "u") {
          if (!/^[a-fA-F0-9]{4}$/.test(this.source.slice(this.offset + 1, this.offset + 5))) {
            throw validationError("approval ticket contains an invalid Unicode escape");
          }
          this.offset += 4;
        } else if (!escaped || !'"\\/bfnrt'.includes(escaped)) {
          throw validationError("approval ticket contains an invalid escape");
        }
      }
      this.offset += 1;
    }
    throw validationError("approval ticket contains an unterminated JSON string");
  }

  private parseNumber(): number {
    const remainder = this.source.slice(this.offset);
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(remainder);
    if (!match) throw validationError("approval ticket contains an invalid JSON value");
    this.offset += match[0].length;
    const value = Number(match[0]);
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw validationError("approval ticket contains a non-canonical JSON number");
    }
    return value;
  }

  private parseLiteral<T extends JsonPrimitive>(token: string, value: T): T {
    if (!this.source.startsWith(token, this.offset)) {
      throw validationError("approval ticket contains an invalid JSON literal");
    }
    this.offset += token.length;
    return value;
  }

  private consume(token: string): boolean {
    if (this.source[this.offset] !== token) return false;
    this.offset += 1;
    return true;
  }

  private skipWhitespace(): void {
    while (/\s/u.test(this.source[this.offset] ?? "")) {
      const char = this.source[this.offset];
      if (char !== " " && char !== "\t" && char !== "\r" && char !== "\n") {
        throw validationError("approval ticket contains non-JSON whitespace");
      }
      this.offset += 1;
    }
  }
}
