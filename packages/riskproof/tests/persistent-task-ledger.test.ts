import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { hostname, tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import { afterEach, describe, expect, it } from "vitest";
import {
  PersistentTaskLedger,
  PersistentTaskLedgerCapacityError,
  PersistentTaskLedgerCorruptionError,
  PersistentTaskLedgerLockError,
  PersistentTaskLedgerPolicyMismatchError,
  type PersistentLedgerBudget,
  type PersistentLedgerReserveResult,
  type PersistentLedgerScope,
  type PersistentTaskLedgerOptions,
} from "../src/persistent-task-ledger.js";

const tempDirs: string[] = [];
const FIXED_TIME = Date.parse("2026-07-27T00:00:00.000Z");
const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);

function tempDir(): string {
  const dir = mkdtempSync(resolve(tmpdir(), "riskproof-ledger-test-"));
  tempDirs.push(dir);
  return dir;
}

function scope(overrides: Partial<PersistentLedgerScope> = {}): PersistentLedgerScope {
  return {
    tenantId: "tenant-secret-acme",
    userId: "user-secret-alice",
    taskId: "task-secret-export",
    sessionId: "session-secret-42",
    ...overrides,
  };
}

function budget(): PersistentLedgerBudget {
  return {
    maxCalls: 3,
    toolBudgets: [
      { toolName: "read_file", maxCalls: 1 },
      { toolName: "send_email", maxCalls: 2 },
    ],
  };
}

function options(baseDir: string, extra: PersistentTaskLedgerOptions = {}): PersistentTaskLedgerOptions {
  return {
    baseDir,
    clock: () => new Date(FIXED_TIME),
    reservationTtlMs: 60_000,
    ...extra,
  };
}

function ledgerFile(baseDir: string, ledger: PersistentTaskLedger): string {
  return resolve(baseDir, "scopes", `${ledger.getScopeDigest()}.jsonl`);
}

function lockDir(baseDir: string, ledger: PersistentTaskLedger): string {
  return resolve(baseDir, "locks", `${ledger.getScopeDigest()}.lock`);
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("PersistentTaskLedger", () => {
  it("persists reserve/complete/abort budgets with private metadata-only files", async () => {
    const baseDir = tempDir();
    const monitor = new PersistentTaskLedger(scope(), budget(), options(baseDir));
    const first = await monitor.reserve({
      toolName: "read_file",
      descriptorDigest: DIGEST_A,
      requestDigest: DIGEST_B,
    });
    expect(first).toMatchObject({ status: "reserved", sequence: 2 });
    if (first.status !== "reserved") throw new Error("expected reservation");
    expect(await monitor.complete(first.reservationToken)).toBe(true);
    expect(await monitor.complete(first.reservationToken)).toBe(false);

    expect(await monitor.reserve({ toolName: "read_file" })).toMatchObject({
      status: "denied",
      violation: "tool_budget_exhausted",
    });
    const aborted = await monitor.reserve({ toolName: "send_email" });
    if (aborted.status !== "reserved") throw new Error("expected reservation");
    expect(await monitor.abort(aborted.reservationToken)).toBe(true);
    expect(await monitor.abort(aborted.reservationToken)).toBe(false);
    expect(await monitor.reserve({ toolName: "send_email" })).toMatchObject({ status: "reserved" });

    const snapshot = await monitor.snapshot();
    expect(snapshot).toMatchObject({
      completedCalls: 1,
      pendingCalls: 1,
      completedByTool: { read_file: 1 },
      pendingByTool: { send_email: 1 },
    });

    const events = (await monitor.listEvents()).reverse();
    expect(events.map(({ sequence }) => sequence)).toEqual(
      Array.from({ length: events.length }, (_, index) => index + 1),
    );
    expect(events[0]?.previousHash).toBe("0".repeat(64));
    for (let index = 1; index < events.length; index += 1) {
      expect(events[index]?.previousHash).toBe(events[index - 1]?.eventHash);
    }

    const file = ledgerFile(baseDir, monitor);
    const serialized = readFileSync(file, "utf8");
    for (const secret of Object.values(scope())) expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain(first.reservationToken);
    expect(serialized).toContain(first.reservationDigest);
    expect(serialized).toContain(DIGEST_A);
    expect(serialized).toContain(DIGEST_B);
    expect(statSync(baseDir).mode & 0o777).toBe(0o700);
    expect(statSync(resolve(baseDir, "scopes")).mode & 0o777).toBe(0o700);
    expect(statSync(resolve(baseDir, "locks")).mode & 0o777).toBe(0o700);
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it("serializes many in-process contenders so task and per-tool budgets cannot overrun", async () => {
    const baseDir = tempDir();
    const sharedScope = scope();
    const sharedBudget = { maxCalls: 2, toolBudgets: [{ toolName: "send_email", maxCalls: 1 }] };
    const monitors = Array.from(
      { length: 20 },
      () => new PersistentTaskLedger(sharedScope, sharedBudget, options(baseDir)),
    );
    const results = await Promise.all(
      monitors.map((monitor) => monitor.reserve({ toolName: "send_email" })),
    );
    expect(results.filter(({ status }) => status === "reserved")).toHaveLength(1);
    expect(results.filter(({ status }) => status === "denied")).toHaveLength(19);
    expect(results.filter((result) =>
      result.status === "denied" && result.violation === "tool_budget_exhausted"))
      .toHaveLength(19);

    const winner = results.find((result) => result.status === "reserved");
    if (winner?.status !== "reserved") throw new Error("missing winner");
    expect(await monitors[0]!.complete(winner.reservationToken)).toBe(true);
    expect(await monitors[1]!.snapshot()).toMatchObject({
      completedCalls: 1,
      pendingCalls: 0,
    });
  });

  it("coordinates independent Node processes and preserves the winning reservation after restart", async () => {
    const baseDir = tempDir();
    const moduleUrl = pathToFileURL(resolve(
      dirname(fileURLToPath(import.meta.url)),
      "../src/persistent-task-ledger.ts",
    )).href;
    const childCode = `
      import { PersistentTaskLedger } from ${JSON.stringify(moduleUrl)};
      const ledger = new PersistentTaskLedger(
        ${JSON.stringify(scope())},
        { maxCalls: 1, toolBudgets: [{ toolName: "send_email", maxCalls: 1 }] },
        { baseDir: ${JSON.stringify(baseDir)}, reservationTtlMs: 60000 }
      );
      const result = await ledger.reserve({ toolName: "send_email" });
      process.stdout.write(JSON.stringify(result));
    `;
    const outputs = await Promise.all(
      Array.from({ length: 8 }, () => runChild(childCode)),
    );
    const results = outputs.map((output) => JSON.parse(output) as PersistentLedgerReserveResult);
    expect(results.filter(({ status }) => status === "reserved")).toHaveLength(1);
    expect(results.filter(({ status }) => status === "denied")).toHaveLength(7);

    const winner = results.find((result) => result.status === "reserved");
    if (winner?.status !== "reserved") throw new Error("missing cross-process winner");
    const restarted = new PersistentTaskLedger(
      scope(),
      { maxCalls: 1, toolBudgets: [{ toolName: "send_email", maxCalls: 1 }] },
      { baseDir, reservationTtlMs: 60_000 },
    );
    expect(await restarted.snapshot()).toMatchObject({ pendingCalls: 1, completedCalls: 0 });
    expect(await restarted.complete(winner.reservationToken)).toBe(true);
    expect(await restarted.reserve({ toolName: "send_email" })).toMatchObject({
      status: "denied",
      violation: "task_budget_exhausted",
    });
  }, 30_000);

  it("recovers expired reservations after restart without treating recovery as completion", async () => {
    const baseDir = tempDir();
    let now = FIXED_TIME;
    const mutableOptions = (): PersistentTaskLedgerOptions => ({
      baseDir,
      clock: () => new Date(now),
      reservationTtlMs: 100,
    });
    const firstProcess = new PersistentTaskLedger(scope(), { maxCalls: 1 }, mutableOptions());
    const pending = await firstProcess.reserve({ toolName: "send_email" });
    if (pending.status !== "reserved") throw new Error("expected reservation");

    now += 101;
    const restarted = new PersistentTaskLedger(scope(), { maxCalls: 1 }, mutableOptions());
    expect(await restarted.recoverStale()).toEqual({ recovered: 1, sequences: [3] });
    expect(await restarted.complete(pending.reservationToken)).toBe(false);
    expect(await restarted.snapshot()).toMatchObject({ completedCalls: 0, pendingCalls: 0 });
    expect(await restarted.reserve({ toolName: "send_email" })).toMatchObject({ status: "reserved" });
    expect((await restarted.listEvents()).map(({ type }) => type))
      .toContain("reservation_recovered");
  });

  it("atomically consumes nonces, survives restart, and durably burns expired nonces", async () => {
    const baseDir = tempDir();
    let now = FIXED_TIME;
    const sharedOptions = (): PersistentTaskLedgerOptions => ({
      baseDir,
      clock: () => new Date(now),
      reservationTtlMs: 60_000,
    });
    const left = new PersistentTaskLedger(scope(), {}, sharedOptions());
    const right = new PersistentTaskLedger(scope(), {}, sharedOptions());
    const nonce = "approval_nonce_secret_1234567890";
    const concurrent = await Promise.all([
      left.consumeNonce({
        nonce,
        purpose: "approval_ticket",
        bindingDigest: DIGEST_A,
        expiresAt: "2026-07-27T00:01:00.000Z",
      }),
      right.consumeNonce({
        nonce,
        purpose: "approval_ticket",
        bindingDigest: DIGEST_A,
        expiresAt: "2026-07-27T00:01:00.000Z",
      }),
    ]);
    expect(concurrent.filter(({ status }) => status === "consumed")).toHaveLength(1);
    expect(concurrent.filter(({ status }) => status === "replayed")).toHaveLength(1);

    const restarted = new PersistentTaskLedger(scope(), {}, sharedOptions());
    expect(await restarted.consumeNonce({ nonce, purpose: "approval_ticket" }))
      .toMatchObject({ status: "replayed", originalStatus: "consumed" });

    const expiredNonce = "expired_nonce_secret_1234567890";
    expect(await restarted.consumeNonce({
      nonce: expiredNonce,
      purpose: "delegation",
      expiresAt: "2026-07-26T23:59:59.999Z",
    })).toMatchObject({ status: "expired" });
    now -= 60_000;
    const rolledBackClock = new PersistentTaskLedger(scope(), {}, sharedOptions());
    expect(await rolledBackClock.consumeNonce({ nonce: expiredNonce, purpose: "delegation" }))
      .toMatchObject({ status: "replayed", originalStatus: "expired" });

    const serialized = readFileSync(ledgerFile(baseDir, restarted), "utf8");
    expect(serialized).not.toContain(nonce);
    expect(serialized).not.toContain(expiredNonce);
    expect(await restarted.snapshot()).toMatchObject({ usedNonces: 2 });
  });

  it("binds one scope ledger to one exact policy while canonicalizing tool order", async () => {
    const baseDir = tempDir();
    const first = new PersistentTaskLedger(scope(), budget(), options(baseDir));
    await first.snapshot();

    const reordered = new PersistentTaskLedger(scope(), {
      maxCalls: 3,
      toolBudgets: [
        { toolName: "send_email", maxCalls: 2 },
        { toolName: "read_file", maxCalls: 1 },
      ],
    }, options(baseDir));
    expect(reordered.getPolicyDigest()).toBe(first.getPolicyDigest());
    await expect(reordered.snapshot()).resolves.toMatchObject({ eventCount: 1 });

    const expanded = new PersistentTaskLedger(scope(), { maxCalls: 99 }, options(baseDir));
    await expect(expanded.snapshot()).rejects.toBeInstanceOf(
      PersistentTaskLedgerPolicyMismatchError,
    );

    const anotherSession = new PersistentTaskLedger(
      scope({ sessionId: "another-session" }),
      { maxCalls: 99 },
      options(baseDir),
    );
    expect(anotherSession.getScopeDigest()).not.toBe(first.getScopeDigest());
    await expect(anotherSession.snapshot()).resolves.toMatchObject({ eventCount: 1 });
  });

  it("hashes traversal-shaped scope IDs and never uses them as filesystem components", async () => {
    const baseDir = tempDir();
    const traversalScope = scope({
      tenantId: "../../outside-tenant",
      userId: "/tmp/outside-user",
      taskId: "..\\..\\outside-task",
      sessionId: "nested/../../../outside-session",
    });
    const monitor = new PersistentTaskLedger(traversalScope, {}, options(baseDir));
    await monitor.snapshot();
    const files = readdirSync(resolve(baseDir, "scopes"));
    expect(files).toEqual([`${monitor.getScopeDigest()}.jsonl`]);
    expect(dirname(ledgerFile(baseDir, monitor))).toBe(resolve(baseDir, "scopes"));
    expect(readFileSync(ledgerFile(baseDir, monitor), "utf8")).not.toContain("outside-");
  });

  it("fails closed for hash tampering, truncation, oversized files, and policy-safe retries", async () => {
    const tamperedDir = tempDir();
    const tampered = new PersistentTaskLedger(scope(), budget(), options(tamperedDir));
    await tampered.snapshot();
    const tamperedFile = ledgerFile(tamperedDir, tampered);
    const original = readFileSync(tamperedFile, "utf8");
    const parsed = JSON.parse(original.trim()) as { eventHash: string };
    const replacement = parsed.eventHash.startsWith("0") ? "1" : "0";
    writeFileSync(
      tamperedFile,
      original.replace(parsed.eventHash, `${replacement}${parsed.eventHash.slice(1)}`),
    );
    const afterTamper = readFileSync(tamperedFile, "utf8");
    await expect(tampered.reserve({ toolName: "read_file" }))
      .rejects.toBeInstanceOf(PersistentTaskLedgerCorruptionError);
    expect(readFileSync(tamperedFile, "utf8")).toBe(afterTamper);

    const truncatedDir = tempDir();
    const truncated = new PersistentTaskLedger(scope(), {}, options(truncatedDir));
    await truncated.snapshot();
    const truncatedFile = ledgerFile(truncatedDir, truncated);
    const complete = readFileSync(truncatedFile, "utf8");
    writeFileSync(truncatedFile, complete.slice(0, -1));
    await expect(truncated.snapshot()).rejects.toThrow(/truncated/);

    const oversizedDir = tempDir();
    const oversized = new PersistentTaskLedger(scope(), {}, options(oversizedDir, {
      maxFileBytes: 2_048,
    }));
    await oversized.snapshot();
    const oversizedFile = ledgerFile(oversizedDir, oversized);
    truncateSync(oversizedFile, 2_049);
    await expect(oversized.snapshot()).rejects.toThrow(/byte bound/);
  });

  it("reserves finalization capacity before dispatch and enforces record/pending bounds", async () => {
    const boundedDir = tempDir();
    const bounded = new PersistentTaskLedger(scope(), { maxCalls: 10 }, options(boundedDir, {
      maxEvents: 3,
    }));
    const reservation = await bounded.reserve({ toolName: "send_email" });
    if (reservation.status !== "reserved") throw new Error("expected reservation");
    await expect(bounded.consumeNonce({
      nonce: "bounded_nonce_1234567890",
      purpose: "approval_ticket",
    })).rejects.toBeInstanceOf(PersistentTaskLedgerCapacityError);
    await expect(bounded.complete(reservation.reservationToken)).resolves.toBe(true);
    await expect(bounded.reserve({ toolName: "send_email" }))
      .rejects.toBeInstanceOf(PersistentTaskLedgerCapacityError);
    expect(await bounded.snapshot()).toMatchObject({ completedCalls: 1, pendingCalls: 0 });

    const pendingDir = tempDir();
    const pendingBound = new PersistentTaskLedger(scope(), { maxCalls: 10 }, options(pendingDir, {
      maxPendingReservations: 1,
    }));
    expect(await pendingBound.reserve({ toolName: "read_file" })).toMatchObject({ status: "reserved" });
    expect(await pendingBound.reserve({ toolName: "send_email" })).toMatchObject({
      status: "denied",
      violation: "pending_reservation_limit",
    });
  });

  it("reaps a dead stale process lock but never steals a live process lock", async () => {
    const baseDir = tempDir();
    const lockNow = Date.now();
    const monitor = new PersistentTaskLedger(scope(), {}, options(baseDir, {
      staleLockMs: 10,
      lockTimeoutMs: 20,
      lockRetryMs: 1,
    }));
    await monitor.snapshot();

    const stalePath = lockDir(baseDir, monitor);
    mkdirSync(stalePath, { mode: 0o700 });
    writeFileSync(resolve(stalePath, "owner.json"), JSON.stringify({
      token: "crashed-process-lock",
      pid: 2_147_483_647,
      hostname: hostname(),
      createdAtMs: lockNow - 11,
    }), { mode: 0o600 });
    await expect(monitor.snapshot()).resolves.toMatchObject({ eventCount: 1 });

    mkdirSync(stalePath, { mode: 0o700 });
    writeFileSync(resolve(stalePath, "owner.json"), JSON.stringify({
      token: "live-process-lock",
      pid: process.pid,
      hostname: hostname(),
      createdAtMs: lockNow - 1_000,
    }), { mode: 0o600 });
    await expect(monitor.snapshot()).rejects.toBeInstanceOf(PersistentTaskLedgerLockError);
  });

  it("keeps event time monotonic under trusted clock rollback", async () => {
    const baseDir = tempDir();
    let now = FIXED_TIME;
    const monitor = new PersistentTaskLedger(scope(), {}, {
      baseDir,
      clock: () => new Date(now),
      reservationTtlMs: 60_000,
    });
    const reservation = await monitor.reserve({ toolName: "read_file" });
    if (reservation.status !== "reserved") throw new Error("expected reservation");
    now -= 5 * 60_000;
    await monitor.abort(reservation.reservationToken);
    const timestamps = (await monitor.listEvents()).reverse().map(({ timestamp }) => timestamp);
    expect(timestamps).toEqual([...timestamps].sort());
  });

  it("rejects malformed inputs, ambiguous policies, accessors, and secret-shaped metadata fields", async () => {
    const baseDir = tempDir();
    expect(() => new PersistentTaskLedger(
      scope(),
      { toolBudgets: [{ toolName: "read_file", maxCalls: 1 }, { toolName: "read_file", maxCalls: 2 }] },
      options(baseDir),
    )).toThrow(/duplicate/);
    expect(() => new PersistentTaskLedger(
      scope(),
      { maxCalls: 0 },
      options(baseDir),
    )).toThrow(/integer/);
    expect(() => new PersistentTaskLedger(
      scope(),
      {},
      options(baseDir, { maxEvents: 1 }),
    )).toThrow(/integer/);

    const accessor: Record<string, unknown> = {
      tenantId: "tenant",
      userId: "user",
      taskId: "task",
    };
    Object.defineProperty(accessor, "sessionId", {
      enumerable: true,
      get: () => "session",
    });
    expect(() => new PersistentTaskLedger(
      accessor as unknown as PersistentLedgerScope,
      {},
      options(baseDir),
    )).toThrow(/accessors/);

    const monitor = new PersistentTaskLedger(scope(), {}, options(baseDir));
    await expect(monitor.reserve({ toolName: "../../secret tool" })).rejects.toThrow(/tool/);
    await expect(monitor.reserve({ toolName: "read_file", requestDigest: "secret" }))
      .rejects.toThrow(/SHA-256/);
    await expect(monitor.reserve({
      toolName: "read_file",
      args: { apiKey: "must-never-reach-disk" },
    } as never)).rejects.toThrow(/unsupported fields/);
    await expect(monitor.consumeNonce({ nonce: "short", purpose: "approval_ticket" }))
      .rejects.toThrow(/nonce/);
    await expect(monitor.consumeNonce({
      nonce: "valid_nonce_1234567890",
      purpose: "free_form_secret" as "approval_ticket",
    })).rejects.toThrow(/purpose/);
  });

  it("restores private permissions if an operator accidentally broadens the ledger file", async () => {
    const baseDir = tempDir();
    const monitor = new PersistentTaskLedger(scope(), {}, options(baseDir));
    await monitor.snapshot();
    const file = ledgerFile(baseDir, monitor);
    chmodSync(file, 0o666);
    await monitor.snapshot();
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });
});

function runChild(code: string): Promise<string> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx/esm", "--input-type=module", "--eval", code],
      { cwd: process.cwd(), stdio: ["ignore", "pipe", "pipe"] },
    );
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    child.once("error", rejectPromise);
    child.once("close", (codeValue) => {
      if (codeValue === 0) resolvePromise(stdout);
      else rejectPromise(new Error(`ledger child exited ${String(codeValue)}: ${stderr}`));
    });
  });
}
