// ============================================================================
// dsh-riskproof — bounded, privacy-preserving proof store
// ============================================================================
// Records security decisions for audit. Proofs never contain raw tool
// arguments, results, prompts, or credentials — only hashes, types, taint
// labels, source ids, tool/destination summaries, policy ids, risk, and
// decision (see docs/security-model.md).
//
// Proofs live in a bounded in-memory ring. Optional JSONL persistence is
// append-only and off by default; raw provenance content is never persisted.
// ============================================================================

import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import type { SecurityProof } from "../core/types.js";
import { redactProof } from "./redaction.js";

export interface ProofStoreOptions {
  maxRecords?: number;
  /** Optional append-only JSONL file. Off by default. */
  file?: string;
}

export const DEFAULT_MAX_PROOF_RECORDS = 1_000;
export const MAX_PROOF_RECORDS = 10_000;

export interface ProofStoreStats {
  retained: number;
  decisions: Record<SecurityProof["decision"], number>;
  risks: Record<SecurityProof["riskLevel"], number>;
  rules: Record<string, number>;
}

export class ProofStore {
  private readonly maxRecords: number;
  private readonly file?: string;
  private readonly records: SecurityProof[] = [];

  constructor(options: ProofStoreOptions = {}) {
    if (typeof options !== "object" || options === null || Array.isArray(options)) {
      throw new TypeError("ProofStore options must be an object");
    }
    const maxRecords = options.maxRecords ?? DEFAULT_MAX_PROOF_RECORDS;
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > MAX_PROOF_RECORDS) {
      throw new RangeError(`ProofStore maxRecords must be between 1 and ${MAX_PROOF_RECORDS}`);
    }
    this.maxRecords = maxRecords;
    if (options.file !== undefined) {
      if (typeof options.file !== "string" || options.file.trim().length === 0) {
        throw new TypeError("ProofStore file must be a non-empty path");
      }
      this.file = resolve(options.file);
    }
  }

  /** Record a privacy-preserving proof and return its id. */
  save(proof: SecurityProof): string {
    const sanitized = redactProof(structuredClone(proof));
    this.records.push(sanitized);
    while (this.records.length > this.maxRecords) this.records.shift();
    if (this.file) {
      appendFileSync(this.file, JSON.stringify(sanitized) + "\n", {
        encoding: "utf-8",
        mode: 0o600,
        flag: "a",
      });
    }
    return sanitized.proofId;
  }

  list(): SecurityProof[] {
    return this.records.map(cloneProof);
  }

  /** The most recent proofs, newest last. */
  recent(limit = 100): SecurityProof[] {
    if (!Number.isSafeInteger(limit) || limit < 0) {
      throw new RangeError("ProofStore recent limit must be a non-negative integer");
    }
    const bounded = Math.max(0, Math.min(limit, this.records.length));
    return this.records.slice(this.records.length - bounded).map(cloneProof);
  }

  stats(): ProofStoreStats {
    const stats: ProofStoreStats = {
      retained: this.records.length,
      decisions: { allow: 0, require_approval: 0, deny: 0 },
      risks: { low: 0, medium: 0, high: 0, critical: 0 },
      rules: {},
    };
    for (const proof of this.records) {
      stats.decisions[proof.decision] += 1;
      stats.risks[proof.riskLevel] += 1;
      for (const rule of proof.matchedRules) {
        stats.rules[rule.id] = (stats.rules[rule.id] ?? 0) + 1;
      }
    }
    return stats;
  }

  clear(): void {
    this.records.length = 0;
  }
}

/** Generate a unique, opaque proof id. */
export function newProofId(tool: string, decision: string, timestamp: string): string {
  const stamp = timestamp.replace(/\D/g, "");
  const safeTool = tool.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 40) || "tool";
  return `rp_${safeTool}_${decision}_${stamp.slice(0, 14)}_${randomUUID().slice(0, 8)}`;
}

function cloneProof(proof: SecurityProof): SecurityProof {
  return structuredClone(proof);
}
