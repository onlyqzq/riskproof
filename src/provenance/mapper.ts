// ============================================================================
// dsh-riskproof — provenance mapper
// ============================================================================
// Maps argument values back to previously-tracked tool results using exact and
// bounded substring matching. When the agent copies part of one tool's result
// into a later tool's arguments, this recovers the source id and its taints.
// ============================================================================

import type { TaintLabel } from "../core/types.js";
import type { ContextTracker } from "./context-tracker.js";
import { argumentLeaves } from "../core/arguments.js";

export interface ProvenanceMapping {
  provenance: Record<string, string[]>;
  taints: Record<string, TaintLabel[]>;
}

export class ProvenanceMapper {
  constructor(private readonly tracker: ContextTracker) {}

  mapArguments(args: Record<string, unknown>): ProvenanceMapping {
    const provenance: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
    const taints: Record<string, TaintLabel[]> = Object.create(null) as Record<string, TaintLabel[]>;
    for (const leaf of argumentLeaves(args)) {
      const matches = this.tracker.match(leaf.value);
      if (matches.length === 0) {
        provenance[leaf.path] = ["agent_generated"];
        taints[leaf.path] = [];
        continue;
      }
      provenance[leaf.path] = [...new Set(matches.map(({ entry }) => entry.id))];
      taints[leaf.path] = [...new Set(matches.flatMap(({ entry }) => entry.taints))];
    }
    return { provenance, taints };
  }
}
