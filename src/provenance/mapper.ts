// ============================================================================
// dsh-riskproof — provenance mapper
// ============================================================================
// Maps argument values back to previously-tracked tool results using exact and
// bounded substring matching. When the agent copies part of one tool's result
// into a later tool's arguments, this recovers the source id and its taints.
// ============================================================================

import type { TaintLabel } from "../core/types.js";
import type { ContextTracker } from "./context-tracker.js";

export interface ProvenanceMapping {
  provenance: Record<string, string[]>;
  taints: Record<string, TaintLabel[]>;
}

export class ProvenanceMapper {
  constructor(private readonly tracker: ContextTracker) {}

  mapArguments(args: Record<string, unknown>): ProvenanceMapping {
    const provenance: Record<string, string[]> = {};
    const taints: Record<string, TaintLabel[]> = {};
    for (const [name, value] of Object.entries(args)) {
      const matches = this.tracker.match(value);
      if (matches.length === 0) {
        provenance[name] = ["agent_generated"];
        taints[name] = [];
        continue;
      }
      provenance[name] = [...new Set(matches.map(({ entry }) => entry.id))];
      taints[name] = [...new Set(matches.flatMap(({ entry }) => entry.taints))];
    }
    return { provenance, taints };
  }
}
