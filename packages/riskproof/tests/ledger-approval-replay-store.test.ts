import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { PersistentLedgerApprovalReplayStore } from "../src/ledger-approval-replay-store.js";
import { PersistentTaskLedger } from "../src/persistent-task-ledger.js";

const roots: string[] = [];

function ledger(baseDir: string, clock: () => Date): PersistentTaskLedger {
  return new PersistentTaskLedger(
    { tenantId: "tenant", userId: "user", taskId: "task", sessionId: "session" },
    { maxCalls: 2 },
    { baseDir, clock },
  );
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("PersistentLedgerApprovalReplayStore", () => {
  it("atomically rejects replay across adapter and ledger instances", async () => {
    const root = mkdtempSync(resolve(tmpdir(), "riskproof-approval-ledger-"));
    roots.push(root);
    const clock = () => new Date("2026-07-27T00:00:00.000Z");
    const record = {
      replayKey: "a".repeat(64),
      ticketDigest: "b".repeat(64),
      expiresAtMs: Date.parse("2026-07-27T00:05:00.000Z"),
    };
    const first = new PersistentLedgerApprovalReplayStore(ledger(root, clock));
    const second = new PersistentLedgerApprovalReplayStore(ledger(root, clock));

    expect(await first.consumeOnce(record)).toBe(true);
    expect(await second.consumeOnce(record)).toBe(false);
    const snapshot = await ledger(root, clock).snapshot();
    expect(snapshot.usedNonces).toBe(1);
  });

  it("burns expired records instead of making them valid after clock rollback", async () => {
    const root = mkdtempSync(resolve(tmpdir(), "riskproof-approval-ledger-"));
    roots.push(root);
    let now = new Date("2026-07-27T00:06:00.000Z");
    const store = new PersistentLedgerApprovalReplayStore(ledger(root, () => now));
    const record = {
      replayKey: "c".repeat(64),
      ticketDigest: "d".repeat(64),
      expiresAtMs: Date.parse("2026-07-27T00:05:00.000Z"),
    };

    expect(await store.consumeOnce(record)).toBe(false);
    now = new Date("2026-07-27T00:00:00.000Z");
    expect(await store.consumeOnce(record)).toBe(false);
  });
});
