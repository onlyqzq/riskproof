// ============================================================================
// RiskProof — Core Types (v2 simplified)
// ============================================================================
// Single-source-of-truth type definitions for the entire pipeline.
// Eliminates the old ToolCall/PolicyInput/ApprovalProof/PolicyProof duality.

export type ToolName = "send_email" | "http_request" | "shell_exec";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type Decision = "allow" | "require_approval" | "deny";

export type TaintLabel =
  | "UNTRUSTED_WEB"
  | "UNTRUSTED_EMAIL"
  | "UNTRUSTED_TOOL_SCHEMA"
  | "INTERNAL_DOC"
  | "CUSTOMER_DATA"
  | "PII"
  | "SECRET"
  | "API_KEY"
  | "SOURCE_CODE"
  | "FINANCIAL_DATA"
  | "PATIENT_DATA";

// ─── Provenance ────────────────────────────────────────────────────────────────

export interface ProvenanceSource {
  id: string;
  kind: string;
  label?: string;
}

export interface ProvenanceEdge {
  from: string;
  to: string;
  via?: string;
}

export interface ProvenanceGraph {
  nodes: ProvenanceSource[];
  edges: ProvenanceEdge[];
}

// ─── Core Input / Output ───────────────────────────────────────────────────────

/** Single clean input type — what callers provide to the engine */
export interface EngineInput {
  tool: ToolName;
  args: Record<string, unknown>;
  /** Per-argument provenance declarations */
  provenance?: Record<string, string[]>;
  /** Per-argument taint declarations */
  taints?: Record<string, TaintLabel[]>;
  /** Agent capability binding */
  capability?: Capability;
  /** Safety invariants (always enforced) */
  invariants?: SafetyInvariant[];
  /** Trace context for audit linking */
  trace?: TraceContext;
  /** Engine options */
  options?: EngineOptions;
}

export interface EngineOptions {
  internalDomains?: string[];
  referenceTime?: string;
}

/** Single clean output type — what callers receive from the engine */
export interface EngineOutput {
  /** Executable action for the caller */
  action: "allow" | "ask_approval" | "block";
  /** System decision */
  decision: Decision;
  /** Aggregated risk level */
  riskLevel: RiskLevel;
  /** Matched policies with evidence */
  matchedPolicies: MatchedPolicy[];
  /** Enhanced per-argument evidence */
  arguments: Record<string, ArgumentEvidence>;
  /** Audit proof object */
  proof: AuditProof;
}

// ─── Argument Evidence ─────────────────────────────────────────────────────────

export interface ArgumentEvidence {
  value: unknown;
  source: string[];
  taints: TaintLabel[];
  isSink?: boolean;
  risk?: string;
}

// ─── Policy Types ──────────────────────────────────────────────────────────────

export interface MatchedPolicy {
  id: string;
  triggeredArgs: string[];
  evidence: string[];
  reason?: string;
}

export interface Capability {
  tool: ToolName;
  allowedRecipientDomains?: string[];
  forbiddenTaints?: TaintLabel[];
  allowedProvenance?: string[];
  expiresAt?: string;
  description?: string;
}

export interface SafetyInvariant {
  name: string;
  description?: string;
  forbiddenTools?: ToolName[];
  protectedTaints?: TaintLabel[];
  maxValues?: Record<string, number>;
  minValues?: Record<string, number>;
}

// ─── Proof Object ──────────────────────────────────────────────────────────────

export interface AuditProof {
  proofId: string;
  tool: ToolName;
  traceId?: string;
  stepId?: string;
  decision: Decision;
  riskLevel: RiskLevel;
  matchedRules: MatchedPolicy[];
  evidence: string[];
  reason: string;
  timestamp: string;
}

// ─── Trace ─────────────────────────────────────────────────────────────────────

export interface TraceContext {
  traceId?: string;
  stepId?: string;
  agentId?: string;
  taskId?: string;
  userId?: string;
  parentStepId?: string;
}

// ─── User Action ───────────────────────────────────────────────────────────────

export type UserAction =
  | "approve"
  | "reject"
  | "approve_with_redaction"
  | "edit_parameters"
  | "ask_agent_to_justify"
  | "escalate"
  | "run_in_sandbox";
