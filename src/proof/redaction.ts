// ============================================================================
// dsh-riskproof — sensitive value redaction
// ============================================================================
// Proofs never store raw arguments or results by construction. This module
// applies a defense-in-depth text scrub to reason/evidence strings so a value
// that leaks into a generated message (e.g. a pasted secret) cannot be
// persisted verbatim.
// ============================================================================

import type { SecurityProof } from "../core/types.js";

/** Best-effort scrub for API keys, bearer tokens, and key=value secrets. */
export function redactLogText(value: string): string {
  return value
    .replace(/\bsk-[a-zA-Z0-9_-]{8,}\b/g, "[REDACTED_API_KEY]")
    .replace(/\b(Bearer\s+)[a-zA-Z0-9._-]+/gi, "$1[REDACTED]")
    .replace(
      /\b(api[_-]?key|secret|token|password)(\s*[=:]\s*)[^\s,;]+/gi,
      "$1$2[REDACTED]",
    );
}

/** Sanitize a proof's free-text fields (reason + matched-rule evidence). */
export function redactProof(proof: SecurityProof): SecurityProof {
  return {
    ...proof,
    reason: redactLogText(proof.reason),
    matchedRules: proof.matchedRules.map((rule) => ({
      ...rule,
      evidence: rule.evidence.map(redactLogText),
    })),
  };
}
