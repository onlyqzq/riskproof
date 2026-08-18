// ============================================================================
// dsh-riskproof — bounded, privacy-preserving proof store
// ============================================================================
// Records security decisions for audit. Proofs never contain raw tool
// arguments, results, prompts, or credentials — only hashes, types, taint
// labels, source ids, tool/destination summaries, policy ids, risk, and
// decision (see docs/security-model.md).
//
// v0.1 stores proofs in a bounded in-memory ring. Optional JSONL persistence
// is append-only and off by default; persistent provenance is P1.
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
      if (typeof options.file !== "string" || options.file.length === 0) {
        throw new TypeError("ProofStore file must be a non-empty path");
      }
      this.file = resolve(options.file);
    }
  }

  /** Record a privacy-preserving proof and return its id. */
  save(proof: SecurityProof): string {
    const sanitized = redactProof(proof);
    this.records.push(sanitized);
    while (this.records.length > this.maxRecords) this.records.shift();
    if (this.file) {
      appendFileSync(this.file, JSON.stringify(sanitized) + "\n", { encoding: "utf-8" });
    }
    return sanitized.proofId;
  }

  list(): SecurityProof[] {
    return this.records.map((proof) => ({ ...proof }));
  }

  /** The most recent proofs, newest last. */
  recent(limit = 100): SecurityProof[] {
    const bounded = Math.max(0, Math.min(limit, this.records.length));
    return this.records.slice(this.records.length - bounded).map((proof) => ({ ...proof }));
  }

  clear(): void {
    this.records.length = 0;
  }
}

/** Generate a unique, opaque proof id. */
export function newProofId(tool: string, decision: string, timestamp: string): string {
  const stamp = timestamp.replace(/\D/g, "");
  return `rp_${tool.slice(0, 40)}_${decision}_${stamp.slice(0, 14)}_${randomUUID().slice(0, 8)}`;
}
