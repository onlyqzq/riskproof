import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import {
  APPROVAL_TICKET_LIMITS,
  ApprovalTicketVerifier,
  InMemoryApprovalTicketReplayStore,
  StaticApprovalTicketTrustStore,
  canonicalizeApprovalArguments,
  digestApprovalArguments,
  issueApprovalTicket,
  parseApprovalTicket,
  serializeApprovalTicket,
  type ApprovalTicketBinding,
  type ApprovalTicketReplayRecord,
  type ApprovalTicketReplayStore,
  type SignedApprovalTicket,
} from "../src/approval-ticket.js";

const NOW = new Date("2026-07-27T08:00:00.000Z");
const KEY_ID = "approval-key-2026-07";
const NONCE = Buffer.alloc(32, 7).toString("base64url");
const DESCRIPTOR_DIGEST = "a".repeat(64);
const POLICY_DIGEST = "b".repeat(64);
const CONTRACT_DIGEST = "c".repeat(64);

const primaryKeys = generateKeyPairSync("ed25519");
const secondaryKeys = generateKeyPairSync("ed25519");

type DeepMutable<T> = {
  -readonly [Key in keyof T]: T[Key] extends object ? DeepMutable<T[Key]> : T[Key];
};

function binding(): ApprovalTicketBinding {
  return {
    tenantId: "tenant-acme",
    userId: "user-42",
    taskId: "task-quarterly-report",
    sessionId: "session-007",
    traceId: "trace-abc-123",
    tool: {
      providerId: "provider.internal",
      serverId: "finance-mcp-v2",
      toolName: "send_email",
    },
    descriptorDigest: DESCRIPTOR_DIGEST,
    arguments: {
      subject: "Quarterly review",
      to: "board@example.test",
      attachment: { path: "/reports/q2.pdf", confidential: true },
    },
    effect: {
      type: "external_disclosure",
      resource: "file:/reports/q2.pdf",
      destination: "mailto:board@example.test",
    },
    principal: { type: "workload", id: "agent-finance-prod" },
    policyDigest: POLICY_DIGEST,
    contractDigest: CONTRACT_DIGEST,
  };
}

function issue(
  request: ApprovalTicketBinding = binding(),
  options: { now?: Date; ttlMs?: number; keyId?: string; nonce?: string } = {},
): SignedApprovalTicket {
  return issueApprovalTicket(request, {
    keyId: options.keyId ?? KEY_ID,
    privateKey: primaryKeys.privateKey,
    ttlMs: options.ttlMs ?? 60_000,
    clock: () => new Date((options.now ?? NOW).getTime()),
    nonceFactory: () => options.nonce ?? NONCE,
  });
}

function verifier(
  options: {
    now?: Date;
    replayStore?: ApprovalTicketReplayStore;
    maxTtlMs?: number;
    maxEvents?: number;
  } = {},
): ApprovalTicketVerifier {
  const clock = () => new Date((options.now ?? NOW).getTime());
  return new ApprovalTicketVerifier({
    trustStore: new StaticApprovalTicketTrustStore({
      [KEY_ID]: primaryKeys.publicKey,
      "secondary-key": secondaryKeys.publicKey,
    }),
    replayStore: options.replayStore ?? new InMemoryApprovalTicketReplayStore({ clock }),
    clock,
    ...(options.maxTtlMs === undefined ? {} : { maxTtlMs: options.maxTtlMs }),
    ...(options.maxEvents === undefined ? {} : { maxEvents: options.maxEvents }),
  });
}

function cloneBinding(): DeepMutable<ApprovalTicketBinding> {
  return structuredClone(binding()) as DeepMutable<ApprovalTicketBinding>;
}

function mutableTicket(ticket: SignedApprovalTicket): {
  payload: Record<string, unknown>;
  signature: string;
} {
  return JSON.parse(JSON.stringify(ticket)) as {
    payload: Record<string, unknown>;
    signature: string;
  };
}

describe("approval ticket issuance and verification", () => {
  it("issues an Ed25519 ticket bound to the complete call and consumes it once", async () => {
    const ticket = issue();
    expect(ticket.payload).toMatchObject({
      version: "riskproof-approval-v1",
      algorithm: "Ed25519",
      keyId: KEY_ID,
      descriptorDigest: DESCRIPTOR_DIGEST,
      policyDigest: POLICY_DIGEST,
      contractDigest: CONTRACT_DIGEST,
      issuedAt: NOW.toISOString(),
      expiresAt: new Date(NOW.getTime() + 60_000).toISOString(),
      nonce: NONCE,
    });
    expect(ticket.payload.argumentsDigest).toBe(digestApprovalArguments(binding().arguments));
    expect(JSON.stringify(ticket)).not.toContain("Quarterly review");
    expect(ticket.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);

    const serialized = serializeApprovalTicket(ticket);
    expect(parseApprovalTicket(serialized)).toEqual(ticket);

    const monitor = verifier();
    await expect(monitor.verifyAndConsume(serialized, binding())).resolves.toMatchObject({
      ok: true,
      ticketDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      keyIdDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      expiresAt: ticket.payload.expiresAt,
    });
    await expect(monitor.verifyAndConsume(ticket, binding())).resolves.toEqual({
      ok: false,
      code: "replayed",
    });

    const audit = JSON.stringify(monitor.listEvents());
    expect(monitor.listEvents().map(({ code }) => code)).toEqual(["accepted", "replayed"]);
    for (const secretOrIdentifier of [
      ticket.payload.nonce,
      KEY_ID,
      "tenant-acme",
      "user-42",
      "task-quarterly-report",
      "session-007",
      "trace-abc-123",
      "board@example.test",
      "/reports/q2.pdf",
    ]) {
      expect(audit).not.toContain(secretOrIdentifier);
    }
  });

  it("accepts semantically identical object key order but rejects changed arguments", async () => {
    const request = cloneBinding();
    request.arguments = {
      z: [3, 2, 1],
      a: { second: false, first: "same" },
    };
    const equivalent = cloneBinding();
    equivalent.arguments = {
      a: { first: "same", second: false },
      z: [3, 2, 1],
    };
    const ticket = issue(request);
    expect(digestApprovalArguments(request.arguments)).toBe(digestApprovalArguments(equivalent.arguments));
    await expect(verifier().verifyAndConsume(ticket, equivalent)).resolves.toMatchObject({ ok: true });

    const changed = structuredClone(equivalent);
    changed.arguments = { a: { first: "changed", second: false }, z: [3, 2, 1] };
    await expect(verifier().verifyAndConsume(ticket, changed)).resolves.toEqual({
      ok: false,
      code: "binding_mismatch",
      binding: "arguments",
    });
  });

  it("fails closed when any authority-bearing binding changes", async () => {
    const ticket = issue();
    const cases: Array<[string, (value: DeepMutable<ApprovalTicketBinding>) => void]> = [
      ["tenant", (value) => { value.tenantId = "tenant-other"; }],
      ["user", (value) => { value.userId = "user-99"; }],
      ["task", (value) => { value.taskId = "task-other"; }],
      ["session", (value) => { value.sessionId = "session-other"; }],
      ["trace", (value) => { value.traceId = "trace-other"; }],
      ["tool", (value) => { value.tool.toolName = "delete_file"; }],
      ["descriptor", (value) => { value.descriptorDigest = "d".repeat(64); }],
      ["arguments", (value) => { value.arguments = { to: "attacker@example.test" }; }],
      ["effect", (value) => { value.effect.destination = "mailto:other@example.test"; }],
      ["principal", (value) => { value.principal.id = "agent-untrusted"; }],
      ["policy", (value) => { value.policyDigest = "e".repeat(64); }],
      ["contract", (value) => { value.contractDigest = "f".repeat(64); }],
    ];
    const monitor = verifier();
    for (const [field, mutate] of cases) {
      const changed = cloneBinding();
      mutate(changed);
      await expect(monitor.verifyAndConsume(ticket, changed)).resolves.toEqual({
        ok: false,
        code: "binding_mismatch",
        binding: field,
      });
    }
    // Binding failures do not consume the ticket; the exact call still can.
    await expect(monitor.verifyAndConsume(ticket, binding())).resolves.toMatchObject({ ok: true });
  });

  it("rejects payload and signature tampering before replay consumption", async () => {
    const replayStore = { consumeOnce: vi.fn(() => true) };
    const monitor = verifier({ replayStore });
    const payloadTamper = mutableTicket(issue());
    payloadTamper.payload.userId = "user-attacker";
    const matchingTamperedContext = cloneBinding();
    matchingTamperedContext.userId = "user-attacker";
    await expect(monitor.verifyAndConsume(
      payloadTamper as unknown as SignedApprovalTicket,
      matchingTamperedContext,
    )).resolves.toEqual({ ok: false, code: "invalid_signature" });

    const signatureTamper = mutableTicket(issue());
    signatureTamper.signature = `${signatureTamper.signature[0] === "A" ? "B" : "A"}${signatureTamper.signature.slice(1)}`;
    await expect(monitor.verifyAndConsume(
      signatureTamper as unknown as SignedApprovalTicket,
      binding(),
    )).resolves.toEqual({ ok: false, code: "invalid_signature" });
    expect(replayStore.consumeOnce).not.toHaveBeenCalled();
  });

  it("uses signed keyId lookup and fails closed for unknown or invalid trust keys", async () => {
    const unknownKeyTicket = issue(binding(), { keyId: "not-in-trust-store" });
    await expect(verifier().verifyAndConsume(unknownKeyTicket, binding())).resolves.toEqual({
      ok: false,
      code: "unknown_key",
    });

    const invalidTrust = new ApprovalTicketVerifier({
      trustStore: { getPublicKey: () => secondaryKeys.privateKey },
      replayStore: new InMemoryApprovalTicketReplayStore({ clock: () => NOW }),
      clock: () => NOW,
    });
    await expect(invalidTrust.verifyAndConsume(issue(), binding())).resolves.toEqual({
      ok: false,
      code: "trust_store_error",
    });
  });

  it("enforces issuance, expiry, future-skew, and verifier TTL bounds", async () => {
    expect(() => issueApprovalTicket(binding(), {
      keyId: KEY_ID,
      privateKey: primaryKeys.privateKey,
      ttlMs: APPROVAL_TICKET_LIMITS.maxTtlMs + 1,
      clock: () => NOW,
    })).toThrow(/ttlMs/);

    const expired = issue();
    await expect(verifier({
      now: new Date(expired.payload.expiresAt),
    }).verifyAndConsume(expired, binding())).resolves.toEqual({ ok: false, code: "expired" });

    const future = issue(binding(), { now: new Date(NOW.getTime() + 31_000) });
    await expect(verifier().verifyAndConsume(future, binding())).resolves.toEqual({
      ok: false,
      code: "not_yet_valid",
    });

    const longLived = issue(binding(), { ttlMs: 120_000 });
    await expect(verifier({ maxTtlMs: 60_000 }).verifyAndConsume(
      longLived,
      binding(),
    )).resolves.toEqual({ ok: false, code: "ttl_exceeded" });
  });

  it("allows only one winner when the same ticket is verified concurrently", async () => {
    const monitor = verifier();
    const ticket = issue();
    const outcomes = await Promise.all(
      Array.from({ length: 32 }, () => monitor.verifyAndConsume(ticket, binding())),
    );
    expect(outcomes.filter(({ ok }) => ok)).toHaveLength(1);
    expect(outcomes.filter((result) => !result.ok && result.code === "replayed")).toHaveLength(31);
  });

  it("fails closed on replay-store uncertainty or capacity instead of evicting live nonces", async () => {
    const throwingStore: ApprovalTicketReplayStore = {
      consumeOnce: () => { throw new Error("database unavailable"); },
    };
    await expect(verifier({ replayStore: throwingStore }).verifyAndConsume(
      issue(),
      binding(),
    )).resolves.toEqual({ ok: false, code: "replay_store_error" });

    const store = new InMemoryApprovalTicketReplayStore({ clock: () => NOW, maxEntries: 1 });
    const firstMonitor = verifier({ replayStore: store });
    await expect(firstMonitor.verifyAndConsume(issue(), binding())).resolves.toMatchObject({ ok: true });
    const secondTicket = issue(binding(), { nonce: Buffer.alloc(32, 8).toString("base64url") });
    await expect(firstMonitor.verifyAndConsume(secondTicket, binding())).resolves.toEqual({
      ok: false,
      code: "replay_store_error",
    });
    expect(store.size()).toBe(1);

    await expect(verifier({
      replayStore: { consumeOnce: (() => "yes") as unknown as ApprovalTicketReplayStore["consumeOnce"] },
    }).verifyAndConsume(issue(), binding())).resolves.toEqual({
      ok: false,
      code: "replay_store_error",
    });
  });

  it("uses clock high-watermarks so wall-clock rollback cannot reopen an expired ticket", async () => {
    let now = new Date(NOW);
    const monitor = new ApprovalTicketVerifier({
      trustStore: new StaticApprovalTicketTrustStore({ [KEY_ID]: primaryKeys.publicKey }),
      replayStore: new InMemoryApprovalTicketReplayStore({ clock: () => now }),
      clock: () => now,
    });
    const ticket = issue();
    now = new Date(NOW.getTime() + 60_001);
    await expect(monitor.verifyAndConsume(ticket, binding())).resolves.toEqual({
      ok: false,
      code: "expired",
    });
    now = new Date(NOW);
    await expect(monitor.verifyAndConsume(ticket, binding())).resolves.toEqual({
      ok: false,
      code: "expired",
    });

    let storeNow = new Date(NOW);
    const store = new InMemoryApprovalTicketReplayStore({ clock: () => storeNow });
    const record = {
      replayKey: "1".repeat(64),
      ticketDigest: "2".repeat(64),
      expiresAtMs: NOW.getTime() + 60_000,
    };
    expect(store.consumeOnce(record)).toBe(true);
    storeNow = new Date(NOW.getTime() + 60_001);
    expect(store.size()).toBe(0);
    storeNow = new Date(NOW);
    expect(() => store.consumeOnce(record)).toThrow(/already-expired/);
  });

  it("passes only digest metadata to a persistent replay-store implementation", async () => {
    const consumeOnce = vi.fn(async (_record: ApprovalTicketReplayRecord) => true);
    const monitor = verifier({ replayStore: { consumeOnce } });
    await expect(monitor.verifyAndConsume(issue(), binding())).resolves.toMatchObject({ ok: true });
    expect(consumeOnce).toHaveBeenCalledTimes(1);
    expect(consumeOnce.mock.calls[0]?.[0]).toEqual({
      replayKey: expect.stringMatching(/^[a-f0-9]{64}$/),
      ticketDigest: expect.stringMatching(/^[a-f0-9]{64}$/),
      expiresAtMs: NOW.getTime() + 60_000,
    });
    expect(JSON.stringify(consumeOnce.mock.calls[0]?.[0])).not.toContain(NONCE);
  });
});

describe("approval ticket strict parsing and bounded canonical JSON", () => {
  it("detects duplicate JSON keys at every object level", () => {
    const ticket = issue();
    const payloadJson = JSON.stringify(ticket.payload);
    const duplicateEnvelope = `{"payload":${payloadJson},"signature":"${ticket.signature}","signature":"${ticket.signature}"}`;
    expect(() => parseApprovalTicket(duplicateEnvelope)).toThrow(/duplicate object key/);

    const duplicatePayload = payloadJson.replace(
      "{",
      `{"version":"riskproof-approval-v1",`,
    );
    expect(() => parseApprovalTicket(
      `{"payload":${duplicatePayload},"signature":"${ticket.signature}"}`,
    )).toThrow(/duplicate object key/);
  });

  it("rejects unknown fields, accessors, Proxies, and non-enumerable ambiguity", () => {
    const extraEnvelope = { ...issue(), adminOverride: true };
    expect(() => parseApprovalTicket(extraEnvelope)).toThrow(/unsupported field/);

    const extraPayload = mutableTicket(issue());
    extraPayload.payload.futureAuthority = true;
    expect(() => parseApprovalTicket(extraPayload)).toThrow(/unsupported field/);

    let getterRan = false;
    const accessor: Record<string, unknown> = { payload: issue().payload };
    Object.defineProperty(accessor, "signature", {
      enumerable: true,
      get: () => {
        getterRan = true;
        return issue().signature;
      },
    });
    expect(() => parseApprovalTicket(accessor)).toThrow(/enumerable data properties/);
    expect(getterRan).toBe(false);

    expect(() => parseApprovalTicket(new Proxy(issue(), {}))).toThrow(/non-Proxy/);

    const nonEnumerable = { ...issue() };
    Object.defineProperty(nonEnumerable, "hidden", { value: true, enumerable: false });
    expect(() => parseApprovalTicket(nonEnumerable)).toThrow(/enumerable data properties/);
  });

  it("rejects unsafe, ambiguous, or unbounded argument objects", () => {
    expect(() => digestApprovalArguments({ amount: Number.NaN })).toThrow(/finite JSON/);
    expect(() => digestApprovalArguments({ amount: Number.POSITIVE_INFINITY })).toThrow(/finite JSON/);
    expect(() => digestApprovalArguments({ amount: -0 })).toThrow(/negative zero/);
    expect(() => digestApprovalArguments({ text: "\ud800" })).toThrow(/unpaired Unicode/);
    expect(() => digestApprovalArguments(new Proxy({ safe: true }, {}))).toThrow(/Proxy/);

    let getterRan = false;
    const accessor: Record<string, unknown> = {};
    Object.defineProperty(accessor, "secret", {
      enumerable: true,
      get: () => {
        getterRan = true;
        return "credential";
      },
    });
    expect(() => digestApprovalArguments(accessor)).toThrow(/enumerable data properties/);
    expect(getterRan).toBe(false);

    const sparse = new Array(2);
    sparse[1] = "present";
    expect(() => digestApprovalArguments(sparse)).toThrow(/dense/);
    const hugeSparse = new Array(APPROVAL_TICKET_LIMITS.maxArgumentNodes + 1);
    expect(() => digestApprovalArguments(hugeSparse)).toThrow(/node count/);

    class NonJsonValue {
      safe = true;
    }
    expect(() => digestApprovalArguments(new NonJsonValue())).toThrow(/plain object/);

    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => digestApprovalArguments(circular)).toThrow(/circular/);

    expect(() => canonicalizeApprovalArguments({
      huge: "x".repeat(APPROVAL_TICKET_LIMITS.maxArgumentsBytes + 1),
    })).toThrow(/byte budget/);
  });

  it("rejects malformed signatures, timestamps, identifiers, nonce, and oversized transport", () => {
    const malformedSignature = mutableTicket(issue());
    malformedSignature.signature = `${malformedSignature.signature}=`;
    expect(() => parseApprovalTicket(malformedSignature)).toThrow(/signature/);

    const malformedTimestamp = mutableTicket(issue());
    malformedTimestamp.payload.issuedAt = "2026-07-27T08:00:00Z";
    expect(() => parseApprovalTicket(malformedTimestamp)).toThrow(/canonical ISO/);

    const malformedId = mutableTicket(issue());
    malformedId.payload.taskId = "task with spaces";
    expect(() => parseApprovalTicket(malformedId)).toThrow(/safe identifier/);

    const malformedNonce = mutableTicket(issue());
    malformedNonce.payload.nonce = "predictable";
    expect(() => parseApprovalTicket(malformedNonce)).toThrow(/nonce/);

    expect(() => parseApprovalTicket(" ".repeat(APPROVAL_TICKET_LIMITS.maxTicketBytes + 1)))
      .toThrow(/byte limit/);
  });

  it("requires real Ed25519 KeyObjects and keeps audit history bounded", async () => {
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(() => issueApprovalTicket(binding(), {
      keyId: KEY_ID,
      privateKey: rsa.privateKey,
      clock: () => NOW,
    })).toThrow(/Ed25519 private/);
    expect(() => new StaticApprovalTicketTrustStore({ [KEY_ID]: rsa.publicKey }))
      .toThrow(/Ed25519 public/);
    expect(() => new StaticApprovalTicketTrustStore({ [KEY_ID]: primaryKeys.privateKey }))
      .toThrow(/Ed25519 public/);

    const monitor = verifier({ maxEvents: 2 });
    const ticket = issue();
    const bad = cloneBinding();
    bad.taskId = "task-other";
    await monitor.verifyAndConsume(ticket, bad);
    await monitor.verifyAndConsume(ticket, bad);
    await monitor.verifyAndConsume(ticket, bad);
    expect(monitor.listEvents()).toHaveLength(2);
    expect(monitor.listEvents().map(({ sequence }) => sequence)).toEqual([2, 3]);
  });
});
