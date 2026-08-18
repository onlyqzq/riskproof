// ============================================================================
// dsh-riskproof — decision mapping and monotonic merge
// ============================================================================
// RiskProof uses internal decisions allow / require_approval / deny and maps
// them onto the DSH PreToolDecision vocabulary allow / ask / deny. Merging
// with a downstream decision is strictly monotonic:
//
//   allow < ask < deny
//
// RiskProof can never turn another plugin's deny into an allow.
// ============================================================================

import type { PreToolDecision } from "@deepseek-ai/dsh-tools";
import type { Decision } from "../core/types.js";
import type { ConfigDecision } from "../config.js";

/** Map a config-level decision (allow/ask/deny) to the internal decision. */
export function configDecisionToInternal(value: ConfigDecision): Decision {
  switch (value) {
    case "allow": return "allow";
    case "ask": return "require_approval";
    case "deny": return "deny";
  }
}

/** Map an internal decision to the DSH PreToolDecision vocabulary. */
export function decisionToPreToolDecision(decision: Decision, reason: string): PreToolDecision {
  switch (decision) {
    case "allow":
      return { kind: "allow" };
    case "require_approval":
      return { kind: "ask", reason };
    case "deny":
      return { kind: "deny", reason };
  }
}

function severity(decision: PreToolDecision): number {
  if (decision.kind === "allow") return 0;
  if (decision.kind === "ask") return 1;
  return 2; // deny
}

/** Pick the strictly more restrictive of two DSH pre-tool decisions. */
export function mergePreToolDecisions(
  mine: PreToolDecision,
  downstream: PreToolDecision,
): PreToolDecision {
  return severity(mine) >= severity(downstream) ? mine : downstream;
}
