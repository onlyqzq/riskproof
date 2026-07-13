// ============================================================================
// RiskProof — Sensitive Value Redaction
// ============================================================================
// Engine callers retain the original in-memory result for compatibility.
// Anything persisted, logged, or returned by the HTTP boundary uses a redacted
// copy so detected credentials and personal data are not duplicated.
// ============================================================================

import type { ArgumentEvidence, EngineOutput, TaintLabel } from "./types.js";

const SENSITIVE_TAINTS = new Set<TaintLabel>([
  "CUSTOMER_DATA",
  "PII",
  "SECRET",
  "API_KEY",
  "SOURCE_CODE",
  "FINANCIAL_DATA",
  "PATIENT_DATA",
]);

export function sensitiveTaints(argument: ArgumentEvidence): TaintLabel[] {
  return argument.taints.filter((taint) => SENSITIVE_TAINTS.has(taint));
}

export function redactedValue(argument: ArgumentEvidence): unknown {
  const labels = sensitiveTaints(argument);
  return labels.length > 0 ? `[REDACTED:${labels.join(",")}]` : argument.value;
}

export function redactEngineOutput(output: EngineOutput): EngineOutput {
  return {
    ...output,
    arguments: Object.fromEntries(
      Object.entries(output.arguments).map(([name, argument]) => [
        name,
        {
          ...argument,
          value: redactedValue(argument),
          source: argument.source.map(redactLogText),
          ...(argument.risk === undefined ? {} : { risk: redactLogText(argument.risk) }),
        },
      ]),
    ),
    proof: {
      ...output.proof,
      matchedRules: output.proof.matchedRules.map(redactPolicy),
      evidence: output.proof.evidence.map(redactLogText),
      reason: redactLogText(output.proof.reason),
    },
    matchedPolicies: output.matchedPolicies.map(redactPolicy),
  };
}

function redactPolicy<T extends {
  triggeredArgs: string[];
  evidence: string[];
  reason?: string;
}>(rule: T): T {
  return {
    ...rule,
    triggeredArgs: rule.triggeredArgs.map(redactLogText),
    evidence: rule.evidence.map(redactLogText),
    ...(rule.reason === undefined ? {} : { reason: redactLogText(rule.reason) }),
  };
}

/** Best-effort defense for third-party stderr where structured taints are unavailable. */
export function redactLogText(value: string): string {
  return value
    .replace(/\bsk-[a-zA-Z0-9_-]{8,}\b/g, "[REDACTED_API_KEY]")
    .replace(/\b(Bearer\s+)[a-zA-Z0-9._-]+/gi, "$1[REDACTED]")
    .replace(
      /\b(api[_-]?key|secret|token|password)(\s*[=:]\s*)[^\s,;]+/gi,
      "$1$2[REDACTED]",
    );
}
