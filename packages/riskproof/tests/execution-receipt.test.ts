import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  digestCanonicalValue,
  ExecutionReceiptStore,
} from "../src/execution-receipt.js";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const roots: string[] = [];

function temporaryRoot(): string {
  const root = mkdtempSync(resolve(tmpdir(), "riskproof-receipt-"));
  roots.push(root);
  return root;
}

function startInput(secret = "synthetic-secret-value") {
  return {
    scope: { tenantId: "tenant-1", taskId: "task-1", sessionId: "session-1" },
    toolKeyDigest: DIGEST_A,
    descriptorDigest: DIGEST_B,
    args: { path: "/tmp/input", payload: secret },
    proofId: "proof-1",
    decision: "allow" as const,
    riskLevel: "low" as const,
    matchedRuleIds: ["task_contract_matched"],
  };
}

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("ExecutionReceiptStore", () => {
  it("records a metadata-only decision, dispatch, result, and effect chain", () => {
    const root = temporaryRoot();
    const store = new ExecutionReceiptStore({
      baseDir: root,
      clock: () => new Date("2026-07-27T00:00:00.000Z"),
    });
    const secret = "sk-test-receipt-must-not-persist";
    const started = store.start({
      ...startInput(secret),
      toolManifestDigest: "c".repeat(64),
      selectionPolicyDigest: "d".repeat(64),
      ledgerPolicyDigest: "e".repeat(64),
    });
    expect(started.state).toBe("decided");
    expect(started.events[0]).toMatchObject({
      data: {
        toolManifestDigest: "c".repeat(64),
        selectionPolicyDigest: "d".repeat(64),
        ledgerPolicyDigest: "e".repeat(64),
      },
    });

    const dispatched = store.markDispatched(started.receiptId, {
      request: { method: "tools/call", params: { name: "read_file", arguments: { payload: secret } } },
    });
    expect(dispatched.state).toBe("dispatched");

    const settled = store.settle(started.receiptId, {
      outcome: "success",
      result: { content: [{ type: "text", text: secret }] },
      effectEvidence: [{ kind: "sandbox", status: "confirmed", digest: DIGEST_A }],
    });
    expect(settled.state).toBe("settled");
    expect(settled.events).toHaveLength(3);
    expect(settled.events[1].previousHash).toBe(settled.events[0].eventHash);
    expect(settled.events[2].previousHash).toBe(settled.events[1].eventHash);
    expect((settled.events[2] as { data: { effectEvidence: unknown[] } }).data.effectEvidence).toHaveLength(1);

    const serialized = readdirSync(resolve(root, started.receiptId))
      .map((name) => readFileSync(resolve(root, started.receiptId, name), "utf-8"))
      .join("\n");
    expect(serialized).not.toContain(secret);
    expect(store.load(started.receiptId)).toEqual(settled);
  });

  it("records policy blocks as terminal non-dispatch receipts", () => {
    const store = new ExecutionReceiptStore({ baseDir: temporaryRoot() });
    const started = store.start({ ...startInput(), decision: "deny", riskLevel: "critical" });
    const terminal = store.recordNotDispatched(started.receiptId, { reason: "policy_block" });
    expect(terminal.state).toBe("not_dispatched");
    expect(terminal.events.map(({ stage }) => stage)).toEqual(["decision", "not_dispatched"]);
    expect(() => store.markDispatched(started.receiptId, { request: {} })).toThrow(/cannot dispatch/);
  });

  it("preserves incomplete receipts so a crash is visible", () => {
    const store = new ExecutionReceiptStore({ baseDir: temporaryRoot() });
    const started = store.start(startInput());
    expect(store.load(started.receiptId).state).toBe("decided");
    store.markDispatched(started.receiptId, { request: { method: "tools/call" } });
    expect(store.load(started.receiptId).state).toBe("dispatched");
    expect(store.listDiagnostics()).toEqual([
      expect.objectContaining({ receiptId: started.receiptId, state: "dispatched", eventCount: 2 }),
    ]);
  });

  it("detects event tampering and invalid transitions", () => {
    const root = temporaryRoot();
    const store = new ExecutionReceiptStore({ baseDir: root });
    const started = store.start(startInput());
    const eventPath = resolve(root, started.receiptId, "01-decision.json");
    const raw = JSON.parse(readFileSync(eventPath, "utf-8"));
    raw.data.riskLevel = "critical";
    writeFileSync(eventPath, JSON.stringify(raw));
    expect(() => store.load(started.receiptId)).toThrow(/hash mismatch/);
    expect(store.listDiagnostics()).toEqual([
      { receiptId: started.receiptId, state: "corrupt", eventCount: 0 },
    ]);
  });

  it("signs every event with Ed25519 and rejects the wrong trust root", () => {
    const root = temporaryRoot();
    const pair = generateKeyPairSync("ed25519");
    const wrong = generateKeyPairSync("ed25519");
    const writer = new ExecutionReceiptStore({
      baseDir: root,
      signing: { keyId: "operator-2026", privateKey: pair.privateKey },
      requireSignature: true,
    });
    const started = writer.start(startInput());
    writer.recordNotDispatched(started.receiptId, { reason: "approval_rejected" });
    expect(writer.load(started.receiptId).signed).toBe(true);

    const reader = new ExecutionReceiptStore({
      baseDir: root,
      verificationKeys: { "operator-2026": pair.publicKey },
      requireSignature: true,
    });
    expect(reader.load(started.receiptId).state).toBe("not_dispatched");
    const untrusted = new ExecutionReceiptStore({
      baseDir: root,
      verificationKeys: { "operator-2026": wrong.publicKey },
      requireSignature: true,
    });
    expect(() => untrusted.load(started.receiptId)).toThrow(/verification failed/);
  });

  it("rejects replayed transitions, unknown fields, accessors, proxies, and non-JSON values", () => {
    const store = new ExecutionReceiptStore({ baseDir: temporaryRoot() });
    const started = store.start(startInput());
    store.markDispatched(started.receiptId, { request: {} });
    expect(() => store.markDispatched(started.receiptId, { request: {} })).toThrow(/cannot dispatch/);
    expect(() => store.start({ ...startInput(), extra: true } as never)).toThrow(/unsupported/);
    expect(() => store.start({ ...startInput(), args: new Proxy({}, {}) })).toThrow(/Proxy/);
    expect(() => store.start({
      ...startInput(),
      args: Object.defineProperty({}, "secret", { enumerable: true, get: () => "value" }),
    })).toThrow(/accessors/);
    expect(() => store.start({ ...startInput(), args: { bad: Number.NaN } })).toThrow(/non-finite/);
  });

  it("canonicalizes object keys while preserving array order and Unicode", () => {
    expect(digestCanonicalValue({ b: 2, a: 1 })).toBe(digestCanonicalValue({ a: 1, b: 2 }));
    expect(digestCanonicalValue({ values: [1, 2] })).not.toBe(digestCanonicalValue({ values: [2, 1] }));
    expect(digestCanonicalValue({ text: "visible" })).not.toBe(digestCanonicalValue({ text: "visi\u200bble" }));
  });
});
