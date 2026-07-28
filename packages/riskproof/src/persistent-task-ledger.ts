// ============================================================================
// RiskProof — local, cross-process task/session security ledger
// ============================================================================
//
// This module is deliberately a local-filesystem coordination primitive, not a
// distributed consensus database. Processes on one host can share task budgets,
// reservations, and replay state through an append-only, hash-linked JSONL log.
// Every mutation is serialized by an atomic directory lock and durably fsynced.
// Scope identifiers, reservation capabilities, and nonces are committed with
// SHA-256; raw arguments, results, secrets, and raw scope IDs are never accepted
// as event fields.

import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { hostname } from "node:os";
import { dirname, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { parseRfc3339 } from "./timestamp.js";

const LEDGER_FORMAT = "riskproof.local-task-ledger.event.v1" as const;
const ZERO_HASH = "0".repeat(64);
const SHA256_DIGEST = /^[a-f0-9]{64}$/;
const TOOL_NAME = /^[A-Za-z0-9][A-Za-z0-9_.:/-]*$/;
const RESERVATION_TOKEN = /^plr_[A-Za-z0-9_-]{43}$/;
const NONCE = /^[A-Za-z0-9_-]+$/;
const OWNER_FILE = "owner.json";
const OWNER_FILE_MAX_BYTES = 4_096;
const MAX_EVENT_BYTES = 256 * 1024;
const DEFAULT_BASE_DIR = ".riskproof/ledger";
const NONCE_PURPOSES = new Set<PersistentLedgerNoncePurpose>([
  "approval_ticket",
  "delegation",
  "dispatch",
]);

export const PERSISTENT_TASK_LEDGER_LIMITS = Object.freeze({
  maxScopeComponentLength: 256,
  maxToolNameLength: 256,
  maxTools: 512,
  maxCalls: 1_000_000,
  maxNonceLength: 512,
  minNonceLength: 16,
  defaultReservationTtlMs: 5 * 60_000,
  maxReservationTtlMs: 7 * 24 * 60 * 60_000,
  defaultMaxPendingReservations: 10_000,
  maxPendingReservations: 100_000,
  defaultMaxEvents: 100_000,
  maxEvents: 1_000_000,
  defaultMaxFileBytes: 64 * 1024 * 1024,
  maxFileBytes: 1024 * 1024 * 1024,
  defaultLockTimeoutMs: 10_000,
  maxLockTimeoutMs: 60_000,
  defaultLockRetryMs: 10,
  defaultStaleLockMs: 30_000,
  maxStaleLockMs: 10 * 60_000,
});

export interface PersistentLedgerScope {
  tenantId: string;
  userId: string;
  taskId: string;
  sessionId: string;
}

export interface PersistentLedgerToolBudget {
  toolName: string;
  maxCalls: number;
}

export interface PersistentLedgerBudget {
  /** Successful plus currently pending calls across the whole task/session. */
  maxCalls?: number;
  /** Optional exact per-tool budgets. Tools not listed have no ledger-level per-tool cap. */
  toolBudgets?: readonly PersistentLedgerToolBudget[];
}

export interface PersistentTaskLedgerOptions {
  baseDir?: string;
  /** Trusted host clock; never source this from a model or MCP message. */
  clock?: () => Date;
  reservationTtlMs?: number;
  maxPendingReservations?: number;
  maxEvents?: number;
  maxFileBytes?: number;
  lockTimeoutMs?: number;
  lockRetryMs?: number;
  staleLockMs?: number;
}

export interface PersistentLedgerReserveRequest {
  toolName: string;
  /** Optional commitments only. Raw descriptor, arguments, and provenance are not accepted. */
  descriptorDigest?: string;
  requestDigest?: string;
  toolKeyDigest?: string;
}

export type PersistentLedgerBudgetViolation =
  | "task_budget_exhausted"
  | "tool_budget_exhausted"
  | "pending_reservation_limit";

export interface PersistentLedgerReservation {
  status: "reserved";
  /** Bearer capability returned only to the caller; only its digest is persisted. */
  reservationToken: string;
  reservationDigest: string;
  sequence: number;
  expiresAt: string;
}

export interface PersistentLedgerReservationDenied {
  status: "denied";
  violation: PersistentLedgerBudgetViolation;
  sequence: number;
}

export type PersistentLedgerReserveResult =
  | PersistentLedgerReservation
  | PersistentLedgerReservationDenied;

export type PersistentLedgerNoncePurpose =
  | "approval_ticket"
  | "delegation"
  | "dispatch";

export interface PersistentLedgerNonceRequest {
  /** Opaque bearer nonce. Only SHA-256(nonce) is persisted. */
  nonce: string;
  purpose: PersistentLedgerNoncePurpose;
  /** Optional commitment to ticket/task/arguments/effect. */
  bindingDigest?: string;
  /** If expired, the nonce is durably burned and cannot become valid after clock rollback. */
  expiresAt?: string;
}

export type PersistentLedgerNonceResult =
  | { status: "consumed"; nonceDigest: string; sequence: number }
  | { status: "expired"; nonceDigest: string; sequence: number }
  | {
    status: "replayed";
    nonceDigest: string;
    originalSequence: number;
    originalStatus: "consumed" | "expired";
  };

export interface PersistentLedgerRecoveryResult {
  recovered: number;
  sequences: number[];
}

interface LedgerInitializedData {
  policyDigest: string;
  taskMaxCalls: number | null;
  toolBudgets: PersistentLedgerToolBudget[];
  reservationTtlMs: number;
  maxPendingReservations: number;
}

interface ReservationPendingData {
  toolName: string;
  reservationDigest: string;
  expiresAt: string;
  descriptorDigest?: string;
  requestDigest?: string;
  toolKeyDigest?: string;
}

interface ReservationFinalizedData {
  toolName: string;
  reservationDigest: string;
}

interface BudgetDeniedData {
  toolName: string;
  violation: PersistentLedgerBudgetViolation;
}

interface NonceData {
  nonceDigest: string;
  purpose: PersistentLedgerNoncePurpose;
  bindingDigest?: string;
  expiresAt?: string;
}

interface PersistentLedgerEventBase {
  format: typeof LEDGER_FORMAT;
  sequence: number;
  timestamp: string;
  scopeDigest: string;
  previousHash: string;
  eventHash: string;
}

export type PersistentLedgerEvent =
  | (PersistentLedgerEventBase & {
    type: "ledger_initialized";
    data: LedgerInitializedData;
  })
  | (PersistentLedgerEventBase & {
    type: "reservation_pending";
    data: ReservationPendingData;
  })
  | (PersistentLedgerEventBase & {
    type: "reservation_completed" | "reservation_aborted" | "reservation_recovered";
    data: ReservationFinalizedData;
  })
  | (PersistentLedgerEventBase & {
    type: "budget_denied";
    data: BudgetDeniedData;
  })
  | (PersistentLedgerEventBase & {
    type: "nonce_consumed" | "nonce_rejected_expired";
    data: NonceData;
  });

export interface PersistentLedgerSnapshot {
  scopeDigest: string;
  policyDigest: string;
  sequence: number;
  lastEventHash: string;
  eventCount: number;
  fileBytes: number;
  completedCalls: number;
  pendingCalls: number;
  completedByTool: Record<string, number>;
  pendingByTool: Record<string, number>;
  usedNonces: number;
}

export class PersistentTaskLedgerCorruptionError extends Error {
  constructor(reason = "Persistent task ledger failed integrity validation") {
    super(reason);
    this.name = "PersistentTaskLedgerCorruptionError";
  }
}

export class PersistentTaskLedgerPolicyMismatchError extends Error {
  constructor() {
    super("Persistent task ledger policy does not match the existing scope ledger");
    this.name = "PersistentTaskLedgerPolicyMismatchError";
  }
}

export class PersistentTaskLedgerCapacityError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "PersistentTaskLedgerCapacityError";
  }
}

export class PersistentTaskLedgerLockError extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "PersistentTaskLedgerLockError";
  }
}

interface NormalizedPolicy {
  maxCalls?: number;
  toolBudgets: PersistentLedgerToolBudget[];
  reservationTtlMs: number;
  maxPendingReservations: number;
}

interface NormalizedOptions {
  baseDir: string;
  clock: () => Date;
  reservationTtlMs: number;
  maxPendingReservations: number;
  maxEvents: number;
  maxFileBytes: number;
  lockTimeoutMs: number;
  lockRetryMs: number;
  staleLockMs: number;
}

interface PendingReservation {
  toolName: string;
  expiresAtMs: number;
  terminalReserveBytes: number;
}

interface UsedNonce {
  sequence: number;
  status: "consumed" | "expired";
}

interface LedgerState {
  events: PersistentLedgerEvent[];
  lastHash: string;
  lastTimestampMs: number;
  fileBytes: number;
  device?: bigint;
  inode?: bigint;
  pending: Map<string, PendingReservation>;
  seenReservations: Set<string>;
  completedCalls: number;
  completedByTool: Map<string, number>;
  usedNonces: Map<string, UsedNonce>;
}

interface LockOwner {
  token: string;
  pid: number;
  hostname: string;
  createdAtMs: number;
}

type EventType = PersistentLedgerEvent["type"];
type EventData = PersistentLedgerEvent["data"];
type AppendMode =
  | { kind: "normal" }
  | { kind: "new_pending"; toolName: string; reservationDigest: string }
  | { kind: "finalize"; reservationDigest: string };

/**
 * Durable reference-monitor state shared by local proxy processes.
 *
 * Security boundary: the filesystem and OS account are trusted. The lock is
 * reliable for cooperating processes on one host. This class does not provide
 * quorum, replication, remote-host leases, Byzantine protection, or distributed
 * linearizability.
 */
export class PersistentTaskLedger {
  readonly baseDir: string;
  private readonly scopeDigest: string;
  private readonly policy: NormalizedPolicy;
  private readonly policyDigest: string;
  private readonly toolBudgets = new Map<string, number>();
  private readonly options: NormalizedOptions;
  private readonly scopesDir: string;
  private readonly locksDir: string;
  private readonly ledgerPath: string;
  private readonly lockPath: string;
  private readonly reapLockPath: string;

  constructor(
    rawScope: PersistentLedgerScope,
    rawBudget: PersistentLedgerBudget,
    rawOptions: PersistentTaskLedgerOptions = {},
  ) {
    const scope = normalizeScope(rawScope);
    this.options = normalizeOptions(rawOptions);
    this.baseDir = this.options.baseDir;
    this.scopeDigest = sha256(canonicalJson({
      format: "riskproof.local-task-scope.v1",
      tenantId: scope.tenantId,
      userId: scope.userId,
      taskId: scope.taskId,
      sessionId: scope.sessionId,
    }));
    this.policy = normalizePolicy(
      rawBudget,
      this.options.reservationTtlMs,
      this.options.maxPendingReservations,
    );
    for (const entry of this.policy.toolBudgets) {
      this.toolBudgets.set(entry.toolName, entry.maxCalls);
    }
    this.policyDigest = sha256(canonicalJson({
      format: "riskproof.local-task-ledger-policy.v1",
      scopeDigest: this.scopeDigest,
      maxCalls: this.policy.maxCalls ?? null,
      toolBudgets: this.policy.toolBudgets,
      reservationTtlMs: this.policy.reservationTtlMs,
      maxPendingReservations: this.policy.maxPendingReservations,
    }));

    ensurePrivateDirectory(this.baseDir);
    this.scopesDir = resolveChild(this.baseDir, "scopes");
    this.locksDir = resolveChild(this.baseDir, "locks");
    ensurePrivateDirectory(this.scopesDir);
    ensurePrivateDirectory(this.locksDir);
    this.ledgerPath = resolveChild(this.scopesDir, `${this.scopeDigest}.jsonl`);
    this.lockPath = resolveChild(this.locksDir, `${this.scopeDigest}.lock`);
    this.reapLockPath = resolveChild(this.locksDir, `${this.scopeDigest}.reap`);
  }

  getScopeDigest(): string {
    return this.scopeDigest;
  }

  getPolicyDigest(): string {
    return this.policyDigest;
  }

  /** Atomically check both budgets and persist an in-flight reservation. */
  async reserve(rawRequest: PersistentLedgerReserveRequest): Promise<PersistentLedgerReserveResult> {
    const request = normalizeReserveRequest(rawRequest);
    return this.withLock(() => {
      const state = this.loadOrInitialize();
      const violation = this.budgetViolation(state, request.toolName);
      if (violation !== undefined) {
        const event = this.appendEvent(state, "budget_denied", {
          toolName: request.toolName,
          violation,
        }, { kind: "normal" });
        return { status: "denied", violation, sequence: event.sequence };
      }

      let reservationToken = "";
      let reservationDigest = "";
      for (let attempt = 0; attempt < 8; attempt += 1) {
        reservationToken = `plr_${randomBytes(32).toString("base64url")}`;
        reservationDigest = sha256(reservationToken);
        if (!state.seenReservations.has(reservationDigest)) break;
      }
      if (!reservationToken || state.seenReservations.has(reservationDigest)) {
        throw new Error("Unable to allocate a unique reservation capability");
      }

      const nowMs = this.logicalNowMs(state);
      const expiresAt = safeIsoTimestamp(nowMs + this.policy.reservationTtlMs);
      const data: ReservationPendingData = {
        toolName: request.toolName,
        reservationDigest,
        expiresAt,
        ...(request.descriptorDigest ? { descriptorDigest: request.descriptorDigest } : {}),
        ...(request.requestDigest ? { requestDigest: request.requestDigest } : {}),
        ...(request.toolKeyDigest ? { toolKeyDigest: request.toolKeyDigest } : {}),
      };
      const event = this.appendEvent(state, "reservation_pending", data, {
        kind: "new_pending",
        toolName: request.toolName,
        reservationDigest,
      });
      return {
        status: "reserved",
        reservationToken,
        reservationDigest,
        sequence: event.sequence,
        expiresAt,
      };
    });
  }

  /** Durably consume one successful reservation. */
  async complete(reservationToken: string): Promise<boolean> {
    return this.finalizeReservation(reservationToken, "reservation_completed");
  }

  /** Durably release one failed, cancelled, or rejected reservation. */
  async abort(reservationToken: string): Promise<boolean> {
    return this.finalizeReservation(reservationToken, "reservation_aborted");
  }

  /**
   * Release expired in-flight reservations after a crash/restart decision.
   * Callers must ensure the old dispatcher can no longer produce the side
   * effect; time alone cannot fence a still-running remote operation.
   */
  async recoverStale(): Promise<PersistentLedgerRecoveryResult> {
    return this.withLock(() => {
      const state = this.loadOrInitialize();
      const nowMs = this.logicalNowMs(state);
      const stale = [...state.pending.entries()]
        .filter(([, pending]) => pending.expiresAtMs <= nowMs)
        .sort(([left], [right]) => left.localeCompare(right));
      const sequences: number[] = [];
      for (const [reservationDigest, pending] of stale) {
        const event = this.appendEvent(state, "reservation_recovered", {
          toolName: pending.toolName,
          reservationDigest,
        }, { kind: "finalize", reservationDigest });
        sequences.push(event.sequence);
      }
      return { recovered: sequences.length, sequences };
    });
  }

  /** Atomically burn a scoped nonce. Replays survive process restarts. */
  async consumeNonce(rawRequest: PersistentLedgerNonceRequest): Promise<PersistentLedgerNonceResult> {
    const request = normalizeNonceRequest(rawRequest);
    const nonceDigest = sha256(request.nonce);
    return this.withLock(() => {
      const state = this.loadOrInitialize();
      const prior = state.usedNonces.get(nonceDigest);
      if (prior !== undefined) {
        return {
          status: "replayed",
          nonceDigest,
          originalSequence: prior.sequence,
          originalStatus: prior.status,
        };
      }

      const nowMs = this.logicalNowMs(state);
      const expired = request.expiresAtMs !== undefined && nowMs >= request.expiresAtMs;
      const data: NonceData = {
        nonceDigest,
        purpose: request.purpose,
        ...(request.bindingDigest ? { bindingDigest: request.bindingDigest } : {}),
        ...(request.expiresAt ? { expiresAt: request.expiresAt } : {}),
      };
      const event = this.appendEvent(
        state,
        expired ? "nonce_rejected_expired" : "nonce_consumed",
        data,
        { kind: "normal" },
      );
      return {
        status: expired ? "expired" : "consumed",
        nonceDigest,
        sequence: event.sequence,
      };
    });
  }

  /** Verify and summarize the complete ledger without exposing bearer values. */
  async snapshot(): Promise<PersistentLedgerSnapshot> {
    return this.withLock(() => {
      const state = this.loadOrInitialize();
      return {
        scopeDigest: this.scopeDigest,
        policyDigest: this.policyDigest,
        sequence: state.events.at(-1)?.sequence ?? 0,
        lastEventHash: state.lastHash,
        eventCount: state.events.length,
        fileBytes: state.fileBytes,
        completedCalls: state.completedCalls,
        pendingCalls: state.pending.size,
        completedByTool: countRecord(state.completedByTool),
        pendingByTool: countRecordFromPending(state.pending),
        usedNonces: state.usedNonces.size,
      };
    });
  }

  /** Return a bounded newest-first slice of validated metadata-only events. */
  async listEvents(limit = 1_000): Promise<PersistentLedgerEvent[]> {
    assertIntegerInRange(limit, 1, 10_000, "PersistentTaskLedger event list limit");
    return this.withLock(() => {
      const state = this.loadOrInitialize();
      return state.events.slice(-limit).reverse().map(cloneEvent);
    });
  }

  private async finalizeReservation(
    reservationToken: string,
    type: "reservation_completed" | "reservation_aborted",
  ): Promise<boolean> {
    const token = normalizeReservationToken(reservationToken);
    const reservationDigest = sha256(token);
    return this.withLock(() => {
      const state = this.loadOrInitialize();
      const pending = state.pending.get(reservationDigest);
      if (pending === undefined) return false;
      this.appendEvent(state, type, {
        toolName: pending.toolName,
        reservationDigest,
      }, { kind: "finalize", reservationDigest });
      return true;
    });
  }

  private budgetViolation(
    state: LedgerState,
    toolName: string,
  ): PersistentLedgerBudgetViolation | undefined {
    if (
      this.policy.maxCalls !== undefined &&
      state.completedCalls + state.pending.size >= this.policy.maxCalls
    ) return "task_budget_exhausted";

    const toolBudget = this.toolBudgets.get(toolName);
    if (toolBudget !== undefined) {
      const completed = state.completedByTool.get(toolName) ?? 0;
      const pending = countPendingForTool(state.pending, toolName);
      if (completed + pending >= toolBudget) return "tool_budget_exhausted";
    }
    if (state.pending.size >= this.policy.maxPendingReservations) {
      return "pending_reservation_limit";
    }
    return undefined;
  }

  private loadOrInitialize(): LedgerState {
    let state = this.readLedger();
    if (state !== null) return state;
    state = emptyState();
    this.appendEvent(state, "ledger_initialized", {
      policyDigest: this.policyDigest,
      taskMaxCalls: this.policy.maxCalls ?? null,
      toolBudgets: this.policy.toolBudgets.map((entry) => ({ ...entry })),
      reservationTtlMs: this.policy.reservationTtlMs,
      maxPendingReservations: this.policy.maxPendingReservations,
    }, { kind: "normal" });
    return state;
  }

  private readLedger(): LedgerState | null {
    if (!existsSync(this.ledgerPath)) return null;
    const stat = safeRegularFileStat(this.ledgerPath);
    if (stat.size === 0) throw new PersistentTaskLedgerCorruptionError("Ledger file is empty");
    if (stat.size > this.options.maxFileBytes) {
      throw new PersistentTaskLedgerCorruptionError("Ledger file exceeds its configured byte bound");
    }
    chmodSync(this.ledgerPath, 0o600);

    const descriptor = openSync(
      this.ledgerPath,
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    let serialized: string;
    let openedStat;
    try {
      openedStat = fstatSync(descriptor, { bigint: true });
      if (!openedStat.isFile() || openedStat.nlink !== 1n) {
        throw new PersistentTaskLedgerCorruptionError("Ledger path is not a private regular file");
      }
      if (openedStat.size > BigInt(this.options.maxFileBytes)) {
        throw new PersistentTaskLedgerCorruptionError("Ledger file exceeds its configured byte bound");
      }
      serialized = readFileSync(descriptor, "utf8");
    } finally {
      closeSync(descriptor);
    }
    if (!serialized.endsWith("\n")) {
      throw new PersistentTaskLedgerCorruptionError("Ledger has a truncated final event");
    }
    const lines = serialized.slice(0, -1).split("\n");
    if (lines.length > this.options.maxEvents) {
      throw new PersistentTaskLedgerCorruptionError("Ledger exceeds its configured record bound");
    }

    const state = emptyState();
    state.fileBytes = Buffer.byteLength(serialized);
    state.device = openedStat.dev;
    state.inode = openedStat.ino;
    for (const line of lines) {
      if (Buffer.byteLength(line) > MAX_EVENT_BYTES) {
        throw new PersistentTaskLedgerCorruptionError("Ledger event exceeds its byte bound");
      }
      const event = parseEvent(line);
      this.applyEvent(state, event);
    }
    if (state.events.length === 0 || state.events[0]?.type !== "ledger_initialized") {
      throw new PersistentTaskLedgerCorruptionError("Ledger initialization event is missing");
    }
    return state;
  }

  private appendEvent(
    state: LedgerState,
    type: EventType,
    data: EventData,
    mode: AppendMode,
  ): PersistentLedgerEvent {
    const event = createEvent(
      this.scopeDigest,
      state.events.length + 1,
      safeIsoTimestamp(this.logicalNowMs(state)),
      state.lastHash,
      type,
      data,
    );
    const line = `${JSON.stringify(event)}\n`;
    const lineBytes = Buffer.byteLength(line);
    if (lineBytes > MAX_EVENT_BYTES) {
      throw new PersistentTaskLedgerCapacityError("Ledger event exceeds its byte bound");
    }
    this.assertAppendCapacity(state, lineBytes, mode);

    const creatingLedger = state.fileBytes === 0;
    const descriptor = openSync(
      this.ledgerPath,
      constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT |
        constants.O_NOFOLLOW,
      0o600,
    );
    let openedStat;
    try {
      openedStat = fstatSync(descriptor, { bigint: true });
      if (!openedStat.isFile() || openedStat.nlink !== 1n) {
        throw new PersistentTaskLedgerCorruptionError("Ledger path is not a private regular file");
      }
      if (
        openedStat.size !== BigInt(state.fileBytes) ||
        (state.device !== undefined && openedStat.dev !== state.device) ||
        (state.inode !== undefined && openedStat.ino !== state.inode)
      ) {
        throw new PersistentTaskLedgerCorruptionError("Ledger changed outside the held scope lock");
      }
      fchmodSync(descriptor, 0o600);
      const written = writeSync(descriptor, line, undefined, "utf8");
      if (written !== lineBytes) {
        throw new PersistentTaskLedgerCorruptionError("Ledger append was incomplete");
      }
      fsyncSync(descriptor);
    } finally {
      closeSync(descriptor);
    }
    if (creatingLedger) fsyncDirectory(this.scopesDir);

    state.fileBytes += lineBytes;
    state.device = openedStat.dev;
    state.inode = openedStat.ino;
    this.applyEvent(state, event);
    return event;
  }

  private assertAppendCapacity(state: LedgerState, lineBytes: number, mode: AppendMode): void {
    let reservedEvents = state.pending.size;
    let reservedBytes = [...state.pending.values()]
      .reduce((total, pending) => total + pending.terminalReserveBytes, 0);
    if (mode.kind === "new_pending") {
      reservedEvents += 1;
      reservedBytes += this.terminalReserveBytes(mode.toolName, mode.reservationDigest);
    } else if (mode.kind === "finalize") {
      const pending = state.pending.get(mode.reservationDigest);
      if (pending === undefined) {
        throw new PersistentTaskLedgerCorruptionError("Finalization references no pending reservation");
      }
      reservedEvents -= 1;
      reservedBytes -= pending.terminalReserveBytes;
    }
    if (state.events.length + 1 + reservedEvents > this.options.maxEvents) {
      throw new PersistentTaskLedgerCapacityError(
        "Ledger record bound would leave no durable finalization slot",
      );
    }
    if (state.fileBytes + lineBytes + reservedBytes > this.options.maxFileBytes) {
      throw new PersistentTaskLedgerCapacityError(
        "Ledger byte bound would leave no durable finalization space",
      );
    }
  }

  private terminalReserveBytes(toolName: string, reservationDigest: string): number {
    const data: ReservationFinalizedData = { toolName, reservationDigest };
    return Math.max(
      serializedEventBytes(createEvent(
        this.scopeDigest,
        this.options.maxEvents,
        "9999-12-31T23:59:59.999Z",
        ZERO_HASH,
        "reservation_completed",
        data,
      )),
      serializedEventBytes(createEvent(
        this.scopeDigest,
        this.options.maxEvents,
        "9999-12-31T23:59:59.999Z",
        ZERO_HASH,
        "reservation_aborted",
        data,
      )),
      serializedEventBytes(createEvent(
        this.scopeDigest,
        this.options.maxEvents,
        "9999-12-31T23:59:59.999Z",
        ZERO_HASH,
        "reservation_recovered",
        data,
      )),
    );
  }

  private applyEvent(state: LedgerState, event: PersistentLedgerEvent): void {
    const expectedSequence = state.events.length + 1;
    if (event.sequence !== expectedSequence) {
      throw new PersistentTaskLedgerCorruptionError("Ledger sequence is not contiguous");
    }
    if (event.scopeDigest !== this.scopeDigest) {
      throw new PersistentTaskLedgerCorruptionError("Ledger event belongs to another scope");
    }
    if (event.previousHash !== state.lastHash) {
      throw new PersistentTaskLedgerCorruptionError("Ledger hash chain is broken");
    }
    const expectedHash = hashEvent(event);
    if (event.eventHash !== expectedHash) {
      throw new PersistentTaskLedgerCorruptionError("Ledger event hash is invalid");
    }
    const timestampMs = parseEventTimestamp(event.timestamp);
    if (timestampMs < state.lastTimestampMs) {
      throw new PersistentTaskLedgerCorruptionError("Ledger timestamps moved backwards");
    }

    if (event.type === "ledger_initialized") {
      if (state.events.length !== 0) {
        throw new PersistentTaskLedgerCorruptionError("Ledger contains multiple initialization events");
      }
      if (event.data.policyDigest !== this.policyDigest) {
        throw new PersistentTaskLedgerPolicyMismatchError();
      }
      const expectedData: LedgerInitializedData = {
        policyDigest: this.policyDigest,
        taskMaxCalls: this.policy.maxCalls ?? null,
        toolBudgets: this.policy.toolBudgets,
        reservationTtlMs: this.policy.reservationTtlMs,
        maxPendingReservations: this.policy.maxPendingReservations,
      };
      if (canonicalJson(event.data) !== canonicalJson(expectedData)) {
        throw new PersistentTaskLedgerCorruptionError("Ledger policy metadata is inconsistent");
      }
    } else {
      if (state.events.length === 0) {
        throw new PersistentTaskLedgerCorruptionError("Ledger event precedes initialization");
      }
      this.applyStateTransition(state, event, timestampMs);
    }

    state.events.push(event);
    state.lastHash = event.eventHash;
    state.lastTimestampMs = timestampMs;
  }

  private applyStateTransition(
    state: LedgerState,
    event: Exclude<PersistentLedgerEvent, { type: "ledger_initialized" }>,
    timestampMs: number,
  ): void {
    switch (event.type) {
      case "reservation_pending": {
        const violation = this.budgetViolation(state, event.data.toolName);
        if (violation !== undefined) {
          throw new PersistentTaskLedgerCorruptionError("Reservation exceeds its persisted budget");
        }
        if (state.seenReservations.has(event.data.reservationDigest)) {
          throw new PersistentTaskLedgerCorruptionError("Reservation commitment was reused");
        }
        const expiresAtMs = parseEventTimestamp(event.data.expiresAt);
        if (expiresAtMs <= timestampMs) {
          throw new PersistentTaskLedgerCorruptionError("Reservation expiry is not after creation");
        }
        state.seenReservations.add(event.data.reservationDigest);
        state.pending.set(event.data.reservationDigest, {
          toolName: event.data.toolName,
          expiresAtMs,
          terminalReserveBytes: this.terminalReserveBytes(
            event.data.toolName,
            event.data.reservationDigest,
          ),
        });
        break;
      }
      case "reservation_completed": {
        const pending = this.requirePending(state, event.data);
        state.pending.delete(event.data.reservationDigest);
        state.completedCalls += 1;
        state.completedByTool.set(
          pending.toolName,
          (state.completedByTool.get(pending.toolName) ?? 0) + 1,
        );
        if (
          this.policy.maxCalls !== undefined &&
          state.completedCalls > this.policy.maxCalls
        ) {
          throw new PersistentTaskLedgerCorruptionError("Completed calls exceed task budget");
        }
        const toolBudget = this.toolBudgets.get(pending.toolName);
        if (
          toolBudget !== undefined &&
          (state.completedByTool.get(pending.toolName) ?? 0) > toolBudget
        ) {
          throw new PersistentTaskLedgerCorruptionError("Completed calls exceed tool budget");
        }
        break;
      }
      case "reservation_aborted": {
        this.requirePending(state, event.data);
        state.pending.delete(event.data.reservationDigest);
        break;
      }
      case "reservation_recovered": {
        const pending = this.requirePending(state, event.data);
        if (timestampMs < pending.expiresAtMs) {
          throw new PersistentTaskLedgerCorruptionError("Reservation was recovered before expiry");
        }
        state.pending.delete(event.data.reservationDigest);
        break;
      }
      case "budget_denied": {
        if (this.budgetViolation(state, event.data.toolName) !== event.data.violation) {
          throw new PersistentTaskLedgerCorruptionError("Budget denial is inconsistent with ledger state");
        }
        break;
      }
      case "nonce_consumed":
      case "nonce_rejected_expired": {
        if (state.usedNonces.has(event.data.nonceDigest)) {
          throw new PersistentTaskLedgerCorruptionError("Nonce commitment was reused");
        }
        const expiresAtMs = event.data.expiresAt === undefined
          ? undefined
          : parseEventTimestamp(event.data.expiresAt);
        if (event.type === "nonce_consumed" && expiresAtMs !== undefined && timestampMs >= expiresAtMs) {
          throw new PersistentTaskLedgerCorruptionError("Expired nonce was recorded as consumed");
        }
        if (
          event.type === "nonce_rejected_expired" &&
          (expiresAtMs === undefined || timestampMs < expiresAtMs)
        ) {
          throw new PersistentTaskLedgerCorruptionError("Unexpired nonce was recorded as expired");
        }
        state.usedNonces.set(event.data.nonceDigest, {
          sequence: event.sequence,
          status: event.type === "nonce_consumed" ? "consumed" : "expired",
        });
        break;
      }
    }
  }

  private requirePending(
    state: LedgerState,
    data: ReservationFinalizedData,
  ): PendingReservation {
    const pending = state.pending.get(data.reservationDigest);
    if (pending === undefined || pending.toolName !== data.toolName) {
      throw new PersistentTaskLedgerCorruptionError("Reservation finalization is inconsistent");
    }
    return pending;
  }

  private logicalNowMs(state: LedgerState): number {
    return Math.max(this.readClockMs(), state.lastTimestampMs);
  }

  private readClockMs(): number {
    const value = this.options.clock();
    if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
      throw new TypeError("PersistentTaskLedger clock must return a valid Date");
    }
    return value.getTime();
  }

  private async withLock<T>(operation: () => T): Promise<T> {
    const owner = await this.acquireLock();
    let operationError: unknown;
    try {
      return operation();
    } catch (error) {
      operationError = error;
      throw error;
    } finally {
      try {
        this.releaseLock(owner);
      } catch (releaseError) {
        if (operationError === undefined) throw releaseError;
      }
    }
  }

  private async acquireLock(): Promise<LockOwner> {
    const deadline = Date.now() + this.options.lockTimeoutMs;
    for (;;) {
      // A stale-lock reaper holds this short-lived gate while it rechecks and
      // renames the main lock. This prevents two reapers from acting on the
      // same stale observation and accidentally displacing a newly acquired
      // live lock.
      if (existsSync(this.reapLockPath)) {
        if (Date.now() >= deadline) {
          throw new PersistentTaskLedgerLockError("Timed out acquiring the local ledger scope lock");
        }
        await sleep(this.options.lockRetryMs);
        continue;
      }
      const owner: LockOwner = {
        token: randomUUID(),
        pid: process.pid,
        hostname: hostname(),
        // Lock leases use the host wall clock, not the injectable policy clock.
        // A test/business clock jump must never make a live mutex look stale.
        createdAtMs: Date.now(),
      };
      try {
        mkdirSync(this.lockPath, { mode: 0o700 });
        chmodSync(this.lockPath, 0o700);
        const ownerPath = resolveChild(this.lockPath, OWNER_FILE);
        try {
          writeFileSync(ownerPath, `${JSON.stringify(owner)}\n`, {
            encoding: "utf8",
            flag: "wx",
            mode: 0o600,
            flush: true,
          });
        } catch (error) {
          rmSync(this.lockPath, { recursive: true, force: true });
          throw error;
        }
        return owner;
      } catch (error) {
        if (errorCode(error) !== "EEXIST") throw error;
      }

      if (this.reapStaleLock()) continue;
      if (Date.now() >= deadline) {
        throw new PersistentTaskLedgerLockError("Timed out acquiring the local ledger scope lock");
      }
      await sleep(this.options.lockRetryMs);
    }
  }

  private reapStaleLock(): boolean {
    try {
      mkdirSync(this.reapLockPath, { mode: 0o700 });
    } catch (error) {
      if (errorCode(error) === "EEXIST") return false;
      throw error;
    }
    try {
      return this.reapStaleLockUnderGate();
    } finally {
      rmdirSync(this.reapLockPath);
    }
  }

  private reapStaleLockUnderGate(): boolean {
    let stat;
    try {
      stat = lstatSync(this.lockPath);
    } catch (error) {
      if (errorCode(error) === "ENOENT") return true;
      throw error;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new PersistentTaskLedgerLockError("Ledger lock path is not a private directory");
    }
    const owner = readLockOwner(resolveChild(this.lockPath, OWNER_FILE));
    const createdAtMs = owner?.createdAtMs ?? stat.mtimeMs;
    if (Date.now() - createdAtMs < this.options.staleLockMs) return false;
    if (owner !== null && owner.hostname === hostname() && processIsAlive(owner.pid)) return false;

    const quarantine = resolveChild(
      this.locksDir,
      `${this.scopeDigest}.stale-${randomUUID()}`,
    );
    try {
      renameSync(this.lockPath, quarantine);
    } catch (error) {
      if (errorCode(error) === "ENOENT") return true;
      throw error;
    }
    rmSync(quarantine, { recursive: true, force: true });
    return true;
  }

  private releaseLock(owner: LockOwner): void {
    const ownerPath = resolveChild(this.lockPath, OWNER_FILE);
    const current = readLockOwner(ownerPath);
    if (current === null || current.token !== owner.token) {
      throw new PersistentTaskLedgerLockError("Ledger lock ownership changed before release");
    }
    unlinkSync(ownerPath);
    rmdirSync(this.lockPath);
  }
}

function normalizeScope(raw: PersistentLedgerScope): PersistentLedgerScope {
  const record = strictRecord(raw, "PersistentLedgerScope");
  assertOnlyKeys(record, ["tenantId", "userId", "taskId", "sessionId"], "PersistentLedgerScope");
  return {
    tenantId: scopeComponent(record.tenantId, "tenantId"),
    userId: scopeComponent(record.userId, "userId"),
    taskId: scopeComponent(record.taskId, "taskId"),
    sessionId: scopeComponent(record.sessionId, "sessionId"),
  };
}

function normalizePolicy(
  raw: PersistentLedgerBudget,
  reservationTtlMs: number,
  maxPendingReservations: number,
): NormalizedPolicy {
  const record = strictRecord(raw, "PersistentLedgerBudget");
  assertOnlyKeys(record, ["maxCalls", "toolBudgets"], "PersistentLedgerBudget");
  const maxCalls = optionalInteger(
    record.maxCalls,
    1,
    PERSISTENT_TASK_LEDGER_LIMITS.maxCalls,
    "PersistentLedgerBudget.maxCalls",
  );
  if (record.toolBudgets !== undefined && !Array.isArray(record.toolBudgets)) {
    throw new TypeError("PersistentLedgerBudget.toolBudgets must be an array");
  }
  const rawTools = (record.toolBudgets ?? []) as unknown[];
  if (rawTools.length > PERSISTENT_TASK_LEDGER_LIMITS.maxTools) {
    throw new TypeError("PersistentLedgerBudget.toolBudgets exceeds the supported tool bound");
  }
  const seen = new Set<string>();
  const toolBudgets = rawTools.map((rawTool, index) => {
    const tool = strictRecord(rawTool, `toolBudgets[${index}]`);
    assertOnlyKeys(tool, ["toolName", "maxCalls"], `toolBudgets[${index}]`);
    const toolName = normalizeToolName(tool.toolName, `toolBudgets[${index}].toolName`);
    if (seen.has(toolName)) throw new TypeError("PersistentLedgerBudget contains duplicate tool budgets");
    seen.add(toolName);
    return {
      toolName,
      maxCalls: requiredInteger(
        tool.maxCalls,
        1,
        PERSISTENT_TASK_LEDGER_LIMITS.maxCalls,
        `toolBudgets[${index}].maxCalls`,
      ),
    };
  }).sort((left, right) => left.toolName.localeCompare(right.toolName));
  return {
    ...(maxCalls === undefined ? {} : { maxCalls }),
    toolBudgets,
    reservationTtlMs,
    maxPendingReservations,
  };
}

function normalizeOptions(raw: PersistentTaskLedgerOptions): NormalizedOptions {
  const record = strictRecord(raw, "PersistentTaskLedgerOptions");
  assertOnlyKeys(record, [
    "baseDir",
    "clock",
    "reservationTtlMs",
    "maxPendingReservations",
    "maxEvents",
    "maxFileBytes",
    "lockTimeoutMs",
    "lockRetryMs",
    "staleLockMs",
  ], "PersistentTaskLedgerOptions");
  if (record.baseDir !== undefined && (typeof record.baseDir !== "string" || record.baseDir.length === 0)) {
    throw new TypeError("PersistentTaskLedger baseDir must be a non-empty string");
  }
  if (record.clock !== undefined && typeof record.clock !== "function") {
    throw new TypeError("PersistentTaskLedger clock must be a function");
  }
  const reservationTtlMs = integerOption(
    record.reservationTtlMs,
    1,
    PERSISTENT_TASK_LEDGER_LIMITS.maxReservationTtlMs,
    PERSISTENT_TASK_LEDGER_LIMITS.defaultReservationTtlMs,
    "reservationTtlMs",
  );
  const maxPendingReservations = integerOption(
    record.maxPendingReservations,
    1,
    PERSISTENT_TASK_LEDGER_LIMITS.maxPendingReservations,
    PERSISTENT_TASK_LEDGER_LIMITS.defaultMaxPendingReservations,
    "maxPendingReservations",
  );
  const maxEvents = integerOption(
    record.maxEvents,
    2,
    PERSISTENT_TASK_LEDGER_LIMITS.maxEvents,
    PERSISTENT_TASK_LEDGER_LIMITS.defaultMaxEvents,
    "maxEvents",
  );
  const maxFileBytes = integerOption(
    record.maxFileBytes,
    1_024,
    PERSISTENT_TASK_LEDGER_LIMITS.maxFileBytes,
    PERSISTENT_TASK_LEDGER_LIMITS.defaultMaxFileBytes,
    "maxFileBytes",
  );
  const lockTimeoutMs = integerOption(
    record.lockTimeoutMs,
    1,
    PERSISTENT_TASK_LEDGER_LIMITS.maxLockTimeoutMs,
    PERSISTENT_TASK_LEDGER_LIMITS.defaultLockTimeoutMs,
    "lockTimeoutMs",
  );
  const lockRetryMs = integerOption(
    record.lockRetryMs,
    1,
    1_000,
    PERSISTENT_TASK_LEDGER_LIMITS.defaultLockRetryMs,
    "lockRetryMs",
  );
  const staleLockMs = integerOption(
    record.staleLockMs,
    1,
    PERSISTENT_TASK_LEDGER_LIMITS.maxStaleLockMs,
    PERSISTENT_TASK_LEDGER_LIMITS.defaultStaleLockMs,
    "staleLockMs",
  );
  return {
    baseDir: resolve((record.baseDir as string | undefined) ?? DEFAULT_BASE_DIR),
    clock: (record.clock as (() => Date) | undefined) ?? (() => new Date()),
    reservationTtlMs,
    maxPendingReservations,
    maxEvents,
    maxFileBytes,
    lockTimeoutMs,
    lockRetryMs,
    staleLockMs,
  };
}

function normalizeReserveRequest(raw: PersistentLedgerReserveRequest): PersistentLedgerReserveRequest {
  const record = strictRecord(raw, "PersistentLedgerReserveRequest");
  assertOnlyKeys(
    record,
    ["toolName", "descriptorDigest", "requestDigest", "toolKeyDigest"],
    "PersistentLedgerReserveRequest",
  );
  return {
    toolName: normalizeToolName(record.toolName, "PersistentLedgerReserveRequest.toolName"),
    ...optionalDigestField(record, "descriptorDigest"),
    ...optionalDigestField(record, "requestDigest"),
    ...optionalDigestField(record, "toolKeyDigest"),
  };
}

function normalizeNonceRequest(raw: PersistentLedgerNonceRequest): PersistentLedgerNonceRequest & {
  expiresAtMs?: number;
} {
  const record = strictRecord(raw, "PersistentLedgerNonceRequest");
  assertOnlyKeys(
    record,
    ["nonce", "purpose", "bindingDigest", "expiresAt"],
    "PersistentLedgerNonceRequest",
  );
  if (
    typeof record.nonce !== "string" ||
    record.nonce.length < PERSISTENT_TASK_LEDGER_LIMITS.minNonceLength ||
    record.nonce.length > PERSISTENT_TASK_LEDGER_LIMITS.maxNonceLength ||
    !NONCE.test(record.nonce)
  ) {
    throw new TypeError("Persistent ledger nonce must be a bounded base64url-compatible string");
  }
  if (!NONCE_PURPOSES.has(record.purpose as PersistentLedgerNoncePurpose)) {
    throw new TypeError("Persistent ledger nonce purpose is unsupported");
  }
  const binding = optionalDigestField(record, "bindingDigest");
  let expiresAt: string | undefined;
  let expiresAtMs: number | undefined;
  if (record.expiresAt !== undefined) {
    try {
      expiresAtMs = parseRfc3339(record.expiresAt, "PersistentLedgerNonceRequest.expiresAt");
    } catch {
      throw new TypeError("PersistentLedgerNonceRequest.expiresAt must be valid RFC 3339");
    }
    expiresAt = record.expiresAt as string;
  }
  return {
    nonce: record.nonce,
    purpose: record.purpose as PersistentLedgerNoncePurpose,
    ...binding,
    ...(expiresAt === undefined ? {} : { expiresAt, expiresAtMs }),
  };
}

function normalizeReservationToken(value: unknown): string {
  if (typeof value !== "string" || !RESERVATION_TOKEN.test(value)) {
    throw new TypeError("Persistent ledger reservation token is malformed");
  }
  return value;
}

function parseEvent(serialized: string): PersistentLedgerEvent {
  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch {
    throw new PersistentTaskLedgerCorruptionError("Ledger contains invalid JSON");
  }
  const record = corruptionRecord(raw, "event");
  corruptionOnlyKeys(
    record,
    ["format", "sequence", "timestamp", "scopeDigest", "previousHash", "eventHash", "type", "data"],
    "event",
  );
  if (record.format !== LEDGER_FORMAT) corrupt("Ledger event format is unsupported");
  const sequence = corruptionInteger(record.sequence, 1, PERSISTENT_TASK_LEDGER_LIMITS.maxEvents, "sequence");
  const timestamp = corruptionTimestamp(record.timestamp, "timestamp");
  const scopeDigest = corruptionDigest(record.scopeDigest, "scopeDigest");
  const previousHash = corruptionDigest(record.previousHash, "previousHash");
  const eventHash = corruptionDigest(record.eventHash, "eventHash");
  const type = record.type;
  if (typeof type !== "string" || !EVENT_TYPES.has(type as EventType)) {
    corrupt("Ledger event type is unsupported");
  }
  const data = parseEventData(type as EventType, record.data);
  return {
    format: LEDGER_FORMAT,
    sequence,
    timestamp,
    scopeDigest,
    previousHash,
    eventHash,
    type: type as EventType,
    data,
  } as PersistentLedgerEvent;
}

const EVENT_TYPES = new Set<EventType>([
  "ledger_initialized",
  "reservation_pending",
  "reservation_completed",
  "reservation_aborted",
  "reservation_recovered",
  "budget_denied",
  "nonce_consumed",
  "nonce_rejected_expired",
]);

function parseEventData(type: EventType, raw: unknown): EventData {
  const data = corruptionRecord(raw, "event.data");
  switch (type) {
    case "ledger_initialized": {
      corruptionOnlyKeys(data, [
        "policyDigest",
        "taskMaxCalls",
        "toolBudgets",
        "reservationTtlMs",
        "maxPendingReservations",
      ], "event.data");
      const taskMaxCalls = data.taskMaxCalls === null
        ? null
        : corruptionInteger(data.taskMaxCalls, 1, PERSISTENT_TASK_LEDGER_LIMITS.maxCalls, "taskMaxCalls");
      if (!Array.isArray(data.toolBudgets) || data.toolBudgets.length > PERSISTENT_TASK_LEDGER_LIMITS.maxTools) {
        corrupt("Ledger tool budget metadata is invalid");
      }
      const toolBudgets = (data.toolBudgets as unknown[]).map((rawTool) => {
        const tool = corruptionRecord(rawTool, "event.data.toolBudgets[]");
        corruptionOnlyKeys(tool, ["toolName", "maxCalls"], "event.data.toolBudgets[]");
        return {
          toolName: corruptionToolName(tool.toolName),
          maxCalls: corruptionInteger(tool.maxCalls, 1, PERSISTENT_TASK_LEDGER_LIMITS.maxCalls, "maxCalls"),
        };
      });
      return {
        policyDigest: corruptionDigest(data.policyDigest, "policyDigest"),
        taskMaxCalls,
        toolBudgets,
        reservationTtlMs: corruptionInteger(
          data.reservationTtlMs,
          1,
          PERSISTENT_TASK_LEDGER_LIMITS.maxReservationTtlMs,
          "reservationTtlMs",
        ),
        maxPendingReservations: corruptionInteger(
          data.maxPendingReservations,
          1,
          PERSISTENT_TASK_LEDGER_LIMITS.maxPendingReservations,
          "maxPendingReservations",
        ),
      };
    }
    case "reservation_pending": {
      corruptionOnlyKeys(data, [
        "toolName",
        "reservationDigest",
        "expiresAt",
        "descriptorDigest",
        "requestDigest",
        "toolKeyDigest",
      ], "event.data");
      return {
        toolName: corruptionToolName(data.toolName),
        reservationDigest: corruptionDigest(data.reservationDigest, "reservationDigest"),
        expiresAt: corruptionTimestamp(data.expiresAt, "expiresAt"),
        ...corruptionOptionalDigest(data, "descriptorDigest"),
        ...corruptionOptionalDigest(data, "requestDigest"),
        ...corruptionOptionalDigest(data, "toolKeyDigest"),
      };
    }
    case "reservation_completed":
    case "reservation_aborted":
    case "reservation_recovered": {
      corruptionOnlyKeys(data, ["toolName", "reservationDigest"], "event.data");
      return {
        toolName: corruptionToolName(data.toolName),
        reservationDigest: corruptionDigest(data.reservationDigest, "reservationDigest"),
      };
    }
    case "budget_denied": {
      corruptionOnlyKeys(data, ["toolName", "violation"], "event.data");
      if (!BUDGET_VIOLATIONS.has(data.violation as PersistentLedgerBudgetViolation)) {
        corrupt("Ledger budget violation is unsupported");
      }
      return {
        toolName: corruptionToolName(data.toolName),
        violation: data.violation as PersistentLedgerBudgetViolation,
      };
    }
    case "nonce_consumed":
    case "nonce_rejected_expired": {
      corruptionOnlyKeys(data, ["nonceDigest", "purpose", "bindingDigest", "expiresAt"], "event.data");
      if (!NONCE_PURPOSES.has(data.purpose as PersistentLedgerNoncePurpose)) {
        corrupt("Ledger nonce purpose is unsupported");
      }
      return {
        nonceDigest: corruptionDigest(data.nonceDigest, "nonceDigest"),
        purpose: data.purpose as PersistentLedgerNoncePurpose,
        ...corruptionOptionalDigest(data, "bindingDigest"),
        ...(data.expiresAt === undefined
          ? {}
          : { expiresAt: corruptionTimestamp(data.expiresAt, "expiresAt") }),
      };
    }
  }
}

const BUDGET_VIOLATIONS = new Set<PersistentLedgerBudgetViolation>([
  "task_budget_exhausted",
  "tool_budget_exhausted",
  "pending_reservation_limit",
]);

function createEvent(
  scopeDigest: string,
  sequence: number,
  timestamp: string,
  previousHash: string,
  type: EventType,
  data: EventData,
): PersistentLedgerEvent {
  const unsigned = {
    format: LEDGER_FORMAT,
    sequence,
    timestamp,
    scopeDigest,
    previousHash,
    type,
    data,
  };
  return {
    ...unsigned,
    eventHash: sha256(canonicalJson(unsigned)),
  } as PersistentLedgerEvent;
}

function hashEvent(event: PersistentLedgerEvent): string {
  return sha256(canonicalJson({
    format: event.format,
    sequence: event.sequence,
    timestamp: event.timestamp,
    scopeDigest: event.scopeDigest,
    previousHash: event.previousHash,
    type: event.type,
    data: event.data,
  }));
}

function serializedEventBytes(event: PersistentLedgerEvent): number {
  return Buffer.byteLength(`${JSON.stringify(event)}\n`);
}

function parseEventTimestamp(value: string): number {
  try {
    return parseRfc3339(value, "ledger timestamp");
  } catch {
    throw new PersistentTaskLedgerCorruptionError("Ledger timestamp is invalid");
  }
}

function safeIsoTimestamp(timestampMs: number): string {
  if (!Number.isFinite(timestampMs)) throw new TypeError("Persistent ledger timestamp is invalid");
  try {
    return new Date(timestampMs).toISOString();
  } catch {
    throw new TypeError("Persistent ledger timestamp is outside the supported range");
  }
}

function emptyState(): LedgerState {
  return {
    events: [],
    lastHash: ZERO_HASH,
    lastTimestampMs: Number.NEGATIVE_INFINITY,
    fileBytes: 0,
    pending: new Map(),
    seenReservations: new Set(),
    completedCalls: 0,
    completedByTool: new Map(),
    usedNonces: new Map(),
  };
}

function cloneEvent(event: PersistentLedgerEvent): PersistentLedgerEvent {
  return JSON.parse(JSON.stringify(event)) as PersistentLedgerEvent;
}

function countPendingForTool(pending: Map<string, PendingReservation>, toolName: string): number {
  let count = 0;
  for (const entry of pending.values()) if (entry.toolName === toolName) count += 1;
  return count;
}

function countRecord(values: Map<string, number>): Record<string, number> {
  return Object.fromEntries([...values.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function countRecordFromPending(values: Map<string, PendingReservation>): Record<string, number> {
  const counts = new Map<string, number>();
  for (const { toolName } of values.values()) {
    counts.set(toolName, (counts.get(toolName) ?? 0) + 1);
  }
  return countRecord(counts);
}

function scopeComponent(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > PERSISTENT_TASK_LEDGER_LIMITS.maxScopeComponentLength
  ) {
    throw new TypeError(`${label} must be a non-empty bounded string`);
  }
  return value;
}

function normalizeToolName(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length > PERSISTENT_TASK_LEDGER_LIMITS.maxToolNameLength ||
    !TOOL_NAME.test(value)
  ) {
    throw new TypeError(`${label} must be a bounded MCP tool metadata name`);
  }
  return value;
}

function optionalDigestField<K extends string>(
  record: Record<string, unknown>,
  key: K,
): Partial<Record<K, string>> {
  const value = record[key];
  if (value === undefined) return {};
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) {
    throw new TypeError(`${key} must be a lowercase SHA-256 digest`);
  }
  return { [key]: value } as Partial<Record<K, string>>;
}

function strictRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain data object`);
  }
  if (Reflect.ownKeys(value).some((key) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor?.get !== undefined || descriptor?.set !== undefined;
  })) {
    throw new TypeError(`${label} must not contain accessors`);
  }
  return value as Record<string, unknown>;
}

function assertOnlyKeys(record: Record<string, unknown>, allowed: string[], label: string): void {
  const allowedSet = new Set(allowed);
  if (Reflect.ownKeys(record).some((key) => typeof key !== "string" || !allowedSet.has(key))) {
    throw new TypeError(`${label} contains unsupported fields`);
  }
}

function integerOption(
  value: unknown,
  minimum: number,
  maximum: number,
  fallback: number,
  label: string,
): number {
  return value === undefined ? fallback : requiredInteger(value, minimum, maximum, label);
}

function optionalInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): number | undefined {
  return value === undefined ? undefined : requiredInteger(value, minimum, maximum, label);
}

function requiredInteger(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new TypeError(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function assertIntegerInRange(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): asserts value is number {
  requiredInteger(value, minimum, maximum, label);
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("Persistent ledger canonical data is unsupported");
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function resolveChild(parent: string, child: string): string {
  const resolved = resolve(parent, child);
  if (dirname(resolved) !== resolve(parent)) {
    throw new TypeError("Persistent ledger path escaped its private parent directory");
  }
  return resolved;
}

function ensurePrivateDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new TypeError("Persistent ledger directory must not be a symlink");
  }
  chmodSync(path, 0o700);
}

function fsyncDirectory(path: string): void {
  const descriptor = openSync(path, constants.O_RDONLY);
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function safeRegularFileStat(path: string) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
    throw new PersistentTaskLedgerCorruptionError("Ledger path is not a private regular file");
  }
  return stat;
}

function readLockOwner(path: string): LockOwner | null {
  if (!existsSync(path)) return null;
  let stat;
  try {
    stat = safeLockOwnerStat(path);
  } catch (error) {
    // The current owner may release between existsSync() and lstatSync(). The
    // caller will recheck the lock directory under the reaper gate.
    if (errorCode(error) === "ENOENT") return null;
    throw error;
  }
  if (stat.size > OWNER_FILE_MAX_BYTES) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  if (
    Object.keys(record).some((key) => !["token", "pid", "hostname", "createdAtMs"].includes(key)) ||
    typeof record.token !== "string" ||
    typeof record.hostname !== "string" ||
    !Number.isSafeInteger(record.pid) ||
    (record.pid as number) <= 0 ||
    !Number.isFinite(record.createdAtMs)
  ) return null;
  return {
    token: record.token,
    pid: record.pid as number,
    hostname: record.hostname,
    createdAtMs: record.createdAtMs as number,
  };
}

function safeLockOwnerStat(path: string) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) {
    throw new PersistentTaskLedgerLockError("Ledger lock owner metadata is not a private file");
  }
  return stat;
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) === "EPERM";
  }
}

function errorCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code?: unknown }).code)
    : undefined;
}

function corruptionRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    corrupt(`Ledger ${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function corruptionOnlyKeys(record: Record<string, unknown>, allowed: string[], label: string): void {
  const set = new Set(allowed);
  if (Object.keys(record).some((key) => !set.has(key))) {
    corrupt(`Ledger ${label} contains unsupported fields`);
  }
}

function corruptionInteger(
  value: unknown,
  minimum: number,
  maximum: number,
  label: string,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    corrupt(`Ledger ${label} is outside its integer bound`);
  }
  return value as number;
}

function corruptionDigest(value: unknown, label: string): string {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) {
    corrupt(`Ledger ${label} is not a SHA-256 digest`);
  }
  return value;
}

function corruptionOptionalDigest<K extends string>(
  record: Record<string, unknown>,
  key: K,
): Partial<Record<K, string>> {
  return record[key] === undefined ? {} : { [key]: corruptionDigest(record[key], key) } as Partial<Record<K, string>>;
}

function corruptionTimestamp(value: unknown, label: string): string {
  if (typeof value !== "string") corrupt(`Ledger ${label} is not a timestamp`);
  try {
    parseRfc3339(value, label);
  } catch {
    corrupt(`Ledger ${label} is not valid RFC 3339`);
  }
  return value;
}

function corruptionToolName(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > PERSISTENT_TASK_LEDGER_LIMITS.maxToolNameLength ||
    !TOOL_NAME.test(value)
  ) corrupt("Ledger tool name is invalid");
  return value;
}

function corrupt(reason: string): never {
  throw new PersistentTaskLedgerCorruptionError(reason);
}
