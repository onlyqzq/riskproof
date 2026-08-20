// ============================================================================
// dsh-riskproof — DeepSeek Harness native security plugin
// ============================================================================
// Provenance-aware execution security. Tracks where tool inputs came from,
// follows sensitive data across tool calls, and stops risky cross-tool side
// effects before they execute.
//
// Primary integration points:
//   tools/pre-execute  — allow / ask / deny before dispatch (monotonic)
//   tools/result       — update provenance + toolchain state on success
//   tools/change       — invalidate the capability classifier cache
//   agent/disposed     — release per-session state
// ============================================================================

import type { Context } from "@deepseek-ai/cordis";

import {
  Config,
  POLICY_DEFAULTS,
  POLICY_PRESETS,
  type PolicyPreset,
  type RiskProofConfig,
} from "./config.js";
import { RiskProofRuntime } from "./dsh/runtime.js";

/** Cordis plugin name (used by loader diagnostics). */
export const name = "riskproof";

/** Hard dependency: RiskProof is meaningless without the tool runtime. */
export const inject = ["tools"];

export { Config, POLICY_DEFAULTS, POLICY_PRESETS };
export type { PolicyPreset, RiskProofConfig };

/**
 * Wire RiskProof into the DSH tool pipeline. Every listener, guard, and cache
 * is fiber-owned: HMR or config reload disposes the previous instance before
 * activating the replacement, so no duplicate listener or tracker survives.
 */
export function apply(ctx: Context, config: RiskProofConfig): void {
  const runtime = new RiskProofRuntime(ctx, config);

  ctx.on("tools/pre-execute", (exec, next) => runtime.preExecute(exec, next));
  ctx.on("tools/result", (exec, result) => runtime.onResult(exec, result));
  ctx.on("tools/change", () => runtime.onToolsChange());
  ctx.on("agent/disposed", (payload) => runtime.disposeAgent(payload.agent.id));
}

// Re-export the runtime for programmatic embedding and local demos.
export { RiskProofRuntime } from "./dsh/runtime.js";

// Re-export the pure, deterministic core for advanced consumers and tests.
export {
  evaluate,
  DEFAULT_POLICY,
  type EnginePolicy,
} from "./core/engine.js";
export {
  argumentLeaves,
  argumentsAsRecord,
  flattenArguments,
  ARGUMENT_TRAVERSAL_LIMITS,
  type ArgumentLeaf,
} from "./core/arguments.js";
export {
  analyzeCommandRisks,
  type CommandRiskFinding,
  type CommandRiskKind,
} from "./core/command-risk.js";
export {
  findSensitivePaths,
  matchesPathPattern,
  normalizePathForPolicy,
  type SensitivePathFinding,
} from "./core/path-policy.js";
export {
  classifyTool,
  type ToolMetadata,
} from "./classification/classifier.js";
export {
  ContextTracker,
  CONTEXT_TRACKER_LIMITS,
  type ContextEntry,
  type ContextTrackerOptions,
} from "./provenance/context-tracker.js";
export { ProvenanceMapper, type ProvenanceMapping } from "./provenance/mapper.js";
export { ToolchainGuard, TOOLCHAIN_GUARD_LIMITS, type ToolchainEvent } from "./toolchain/guard.js";
export { ProofStore, newProofId, type ProofStoreStats } from "./proof/proof-store.js";
export * from "./core/types.js";
