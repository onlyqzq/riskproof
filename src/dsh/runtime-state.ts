// ============================================================================
// dsh-riskproof — per-session runtime state
// ============================================================================
// RiskProof state (provenance tracker, provenance mapper, toolchain guard) is
// isolated per agent/session so one session's data flow never contaminates
// another's toolchain. The global bucket is used only for agent-less calls.
// ============================================================================

import type { RiskProofConfig } from "../config.js";
import { ContextTracker } from "../provenance/context-tracker.js";
import { ProvenanceMapper } from "../provenance/mapper.js";
import { ToolchainGuard } from "../toolchain/guard.js";

export interface SessionState {
  tracker: ContextTracker;
  mapper: ProvenanceMapper;
  guard: ToolchainGuard;
}

const GLOBAL_SCOPE = "__riskproof_global__";

/** Upper bound on concurrently tracked sessions (safety net on top of disposal). */
const MAX_SESSIONS = 256;

export class RuntimeState {
  private readonly sessions = new Map<string, SessionState>();

  constructor(private readonly config: RiskProofConfig) {}

  get(agentId: string | undefined): SessionState {
    const key = agentId ?? GLOBAL_SCOPE;
    const existing = this.sessions.get(key);
    if (existing) return existing;

    // Bound concurrent sessions: evict the oldest so memory stays bounded even
    // if disposal notifications are ever missed.
    if (this.sessions.size >= MAX_SESSIONS) {
      const oldest = this.sessions.keys().next().value as string | undefined;
      if (oldest !== undefined) {
        const evicted = this.sessions.get(oldest);
        if (evicted) {
          evicted.tracker.clear();
          evicted.guard.clear();
        }
        this.sessions.delete(oldest);
      }
    }

    const tracker = new ContextTracker({
      maxEntries: this.config.provenance.maxEntries,
      maxEntryBytes: this.config.provenance.maxEntryBytes,
      maxTotalBytes: this.config.provenance.maxTotalBytes,
      minMatchLength: this.config.provenance.minMatchLength,
    });
    const session: SessionState = {
      tracker,
      mapper: new ProvenanceMapper(tracker),
      guard: new ToolchainGuard({
        maxEvents: this.config.toolchain.maxEvents,
        chainWindow: this.config.toolchain.chainWindow,
      }),
    };
    this.sessions.set(key, session);
    return session;
  }

  /** Remove a disposed session's state so memory does not grow unbounded. */
  dispose(agentId: string | undefined): void {
    const key = agentId ?? GLOBAL_SCOPE;
    const session = this.sessions.get(key);
    if (session) {
      session.tracker.clear();
      session.guard.clear();
      this.sessions.delete(key);
    }
  }

  clear(): void {
    for (const session of this.sessions.values()) {
      session.tracker.clear();
      session.guard.clear();
    }
    this.sessions.clear();
  }
}
