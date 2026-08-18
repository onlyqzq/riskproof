// ============================================================================
// dsh-riskproof — DSH runtime glue
// ============================================================================
// Translates DSH ToolExecution / ToolExecutionResult into the core security
// model, evaluates it, and maps the decision back to the DSH PreToolDecision
// vocabulary. Never imports MCP/HTTP/Python concerns; this is the only place
// that touches DSH types.
// ============================================================================

import type { Context } from "@deepseek-ai/cordis";
import type {
  PreToolDecision,
  ToolExecution,
  ToolExecutionResult,
} from "@deepseek-ai/dsh-tools";
import type { Agent } from "@deepseek-ai/dsh-agent";

import type { RiskProofConfig } from "../config.js";
import type {
  SecurityCapability,
  SecurityDecision,
  SecurityProof,
  TaintLabel,
  ToolSecurityContext,
} from "../core/types.js";
import { EMPTY_TOOLCHAIN_STATE } from "../core/types.js";
import { evaluate, type EnginePolicy } from "../core/engine.js";
import { detectValueTaints, enrichArgumentTaints, inferKindFromTool } from "../core/taint.js";
import { classifyTool } from "../classification/classifier.js";
import { normalizeOverrides, type CapabilityOverrides } from "../classification/overrides.js";
import { ProofStore, newProofId } from "../proof/proof-store.js";
import { RuntimeState } from "./runtime-state.js";
import {
  configDecisionToInternal,
  decisionToPreToolDecision,
  mergePreToolDecisions,
} from "./decisions.js";

/** Cached capability resolution, invalidated on `tools/change`. */
class CapabilityResolver {
  private readonly cache = new Map<string, SecurityCapability[]>();

  constructor(
    private readonly ctx: Context,
    private readonly overrides: CapabilityOverrides,
  ) {}

  resolve(name: string, agent?: Agent): SecurityCapability[] {
    const override = this.overrides[name];
    if (override) return [...override];
    const cached = this.cache.get(name);
    if (cached) return [...cached];

    let definition = this.ctx.tools.get(name);
    if (agent) definition = this.ctx.tools.get(name, agent) ?? definition;

    const capabilities = classifyTool({
      name,
      description: definition?.description,
      inputSchema: definition?.parameters,
    });
    this.cache.set(name, capabilities);
    return [...capabilities];
  }

  invalidate(): void {
    this.cache.clear();
  }
}

function buildEnginePolicy(config: RiskProofConfig["policy"]): EnginePolicy {
  return {
    sensitiveExternalAction: configDecisionToInternal(config.sensitiveExternalAction),
    untrustedPrivateAccess: configDecisionToInternal(config.untrustedPrivateAccess),
    untrustedCodeExecution: configDecisionToInternal(config.untrustedCodeExecution),
    unknownTool: configDecisionToInternal(config.unknownTool),
    internalDomains: [...config.internalDomains],
  };
}

function argsAsRecord(args: unknown): Record<string, unknown> {
  if (typeof args === "object" && args !== null && !Array.isArray(args)) {
    return args as Record<string, unknown>;
  }
  return {};
}

export class RiskProofRuntime {
  private readonly state: RuntimeState;
  private readonly proofStore: ProofStore;
  private readonly resolver: CapabilityResolver;
  private readonly enginePolicy: EnginePolicy;
  private readonly logger: ReturnType<Context["logger"]>;

  constructor(
    ctx: Context,
    private readonly config: RiskProofConfig,
  ) {
    this.state = new RuntimeState(config);
    this.proofStore = new ProofStore({ maxRecords: config.proof.maxRecords });
    this.resolver = new CapabilityResolver(ctx, normalizeOverrides(config.classification.overrides));
    this.enginePolicy = buildEnginePolicy(config.policy);
    this.logger = ctx.logger("riskproof");
  }

  /** `tools/pre-execute` waterfall listener body. */
  async preExecute(exec: ToolExecution, next: () => Promise<PreToolDecision>): Promise<PreToolDecision> {
    const decision = this.evaluate(exec);
    const mine = decisionToPreToolDecision(decision.decision, decision.reason);

    this.recordProof(exec, decision);
    if (this.config.mode === "observe" && mine.kind !== "allow") {
      this.logger.warn(
        `[observe] would ${mine.kind === "deny" ? "deny" : "ask"} tool '${exec.name}': ${decision.reason}`,
      );
    }

    if (this.config.mode === "observe") {
      return next();
    }

    // Monotonic coexistence: allow delegates, deny vetoes, ask merges.
    if (mine.kind === "allow") return next();
    if (mine.kind === "deny") return mine;
    const downstream = await next();
    return mergePreToolDecisions(mine, downstream);
  }

  /** `tools/result` observer body. */
  onResult(exec: ToolExecution, result: ToolExecutionResult): undefined {
    // Only authoritative success may record "data obtained". Failures never do.
    if (result.isError) return undefined;

    const session = this.state.get(exec.agent?.id);
    const capabilities = this.resolver.resolve(exec.name, exec.agent);
    const kind = inferKindFromTool(exec.name, capabilities);
    const entry = session.tracker.record(kind, result.value, exec.name, detectValueTaints(result.value));

    if (this.config.toolchain.enabled && entry) {
      session.guard.recordEvent(exec.name, capabilities, [entry.id]);
    }
    return undefined;
  }

  /** Invalidate the classifier cache when the registered tool set changes. */
  onToolsChange(): void {
    this.resolver.invalidate();
  }

  /** Remove a disposed agent's session state. */
  disposeAgent(agentId: string): void {
    this.state.dispose(agentId);
  }

  /** Proofs recorded by this plugin instance (for diagnostics / tests). */
  listProofs(): SecurityProof[] {
    return this.proofStore.list();
  }

  private evaluate(exec: ToolExecution): SecurityDecision {
    const capabilities = this.resolver.resolve(exec.name, exec.agent);
    const session = this.state.get(exec.agent?.id);
    const args = argsAsRecord(exec.arguments);

    let provenance: Record<string, string[]> = {};
    let taints: Record<string, TaintLabel[]> = {};
    if (this.config.provenance.enabled || this.config.taint.enabled) {
      const mapping = session.mapper.mapArguments(args);
      provenance = mapping.provenance;
      taints = this.config.taint.enabled
        ? enrichArgumentTaints(args, mapping.provenance, mapping.taints)
        : mapping.taints;
    }

    const toolchainState = this.config.toolchain.enabled
      ? session.guard.snapshot()
      : EMPTY_TOOLCHAIN_STATE;

    const context: ToolSecurityContext = {
      tool: { name: exec.name, capabilities },
      args,
      provenance,
      taints,
      toolchain: toolchainState,
      execution: {
        callId: String(exec.callId),
        nested: exec.parent !== undefined,
      },
      internalDomains: this.config.policy.internalDomains,
    };

    return evaluate(context, this.enginePolicy);
  }

  private recordProof(exec: ToolExecution, decision: SecurityDecision): void {
    if (!this.config.proof.enabled) return;
    const proof: SecurityProof = {
      proofId: newProofId(exec.name, decision.decision, decision.timestamp),
      tool: exec.name,
      capabilities: this.resolver.resolve(exec.name, exec.agent),
      callId: String(exec.callId),
      nested: exec.parent !== undefined,
      decision: decision.decision,
      riskLevel: decision.riskLevel,
      matchedRules: decision.matchedRules.map((rule) => ({
        id: rule.id,
        triggeredArgs: [...rule.triggeredArgs],
        evidence: [...rule.evidence],
      })),
      provenanceSummary: decision.provenance,
      taintSummary: decision.taints,
      toolchain: decision.toolchain,
      reason: decision.reason,
      timestamp: decision.timestamp,
    };
    this.proofStore.save(proof);
  }
}
