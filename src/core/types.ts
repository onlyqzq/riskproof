// ============================================================================
// dsh-riskproof — core security types
// ============================================================================
// Provenance-aware execution security for DeepSeek Harness.
//
// The core model is deliberately independent of the DSH runtime. The DSH
// adapter (src/dsh/) translates ToolExecution / ToolExecutionResult into these
// types, evaluates them, and maps the decision back to PreToolDecision.
// ============================================================================

/** Security capability class assigned to a tool (see docs/toolchain.md). */
export type SecurityCapability =
  | "EXTERNAL_INGESTION" // EIT — reads content from outside the trust boundary
  | "PRIVATE_ACCESS" //     PAT — reads data inside the trust boundary
  | "EXTERNAL_ACTION" //    NAT — sends data outside the trust boundary
  | "LOCAL_MUTATION" //     writes/mutates local state
  | "CODE_EXECUTION" //     executes code / a shell / a program
  | "CREDENTIAL_ACCESS"; // reads credentials, secrets, or key material

/** Security attribute assigned to data (see docs/provenance.md). */
export type TaintLabel =
  | "UNTRUSTED_WEB"
  | "UNTRUSTED_EMAIL"
  | "UNTRUSTED_TOOL"
  | "PII"
  | "CUSTOMER_DATA"
  | "SECRET"
  | "API_KEY"
  | "SOURCE_CODE"
  | "FINANCIAL_DATA"
  | "PATIENT_DATA"
  | "INTERNAL_DATA";

/** Internal decision. The DSH adapter maps this to allow/ask/deny. */
export type Decision = "allow" | "require_approval" | "deny";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export const ALL_CAPABILITIES: readonly SecurityCapability[] = [
  "EXTERNAL_INGESTION",
  "PRIVATE_ACCESS",
  "EXTERNAL_ACTION",
  "LOCAL_MUTATION",
  "CODE_EXECUTION",
  "CREDENTIAL_ACCESS",
];

export const ALL_TAINTS: readonly TaintLabel[] = [
  "UNTRUSTED_WEB",
  "UNTRUSTED_EMAIL",
  "UNTRUSTED_TOOL",
  "PII",
  "CUSTOMER_DATA",
  "SECRET",
  "API_KEY",
  "SOURCE_CODE",
  "FINANCIAL_DATA",
  "PATIENT_DATA",
  "INTERNAL_DATA",
];

/** Untrusted-source taints (external ingestion produces these). */
export const UNTRUSTED_TAINTS: readonly TaintLabel[] = [
  "UNTRUSTED_WEB",
  "UNTRUSTED_EMAIL",
  "UNTRUSTED_TOOL",
];

/** Sensitive-data taints whose exfiltration is protected. */
export const SENSITIVE_TAINTS: readonly TaintLabel[] = [
  "PII",
  "CUSTOMER_DATA",
  "SECRET",
  "API_KEY",
  "SOURCE_CODE",
  "FINANCIAL_DATA",
  "PATIENT_DATA",
  "INTERNAL_DATA",
];

/** Toolchain state summary observed across the session so far. */
export interface ToolchainState {
  /** Whether an EXTERNAL_INGESTION capability was observed. */
  sawIngestion: boolean;
  /** Whether a PRIVATE_ACCESS capability was observed. */
  sawPrivateAccess: boolean;
  /** Whether an EXTERNAL_ACTION capability was observed. */
  sawExternalAction: boolean;
  /** Recent capability path (bounded, labels only) for diagnostics. */
  path: string[];
}

export const EMPTY_TOOLCHAIN_STATE: ToolchainState = Object.freeze({
  sawIngestion: false,
  sawPrivateAccess: false,
  sawExternalAction: false,
  path: [],
});

/** Tool description used by the engine (never carries the execute body). */
export interface ToolSecurityDescriptor {
  name: string;
  capabilities: SecurityCapability[];
  schemaDigest?: string;
}

/** Execution identity (opaque call correlation only). */
export interface ExecutionIdentity {
  /** RiskProof-owned call correlation. Never the raw DSH token. */
  callId: string;
  /** Whether this call is a nested sub-dispatch (e.g. Code Mode binding). */
  nested: boolean;
}

/** The complete, deterministic input the engine evaluates. */
export interface ToolSecurityContext {
  tool: ToolSecurityDescriptor;
  /** Lossless JSON arguments (already parsed and validated by the tool registry). */
  args: Record<string, unknown>;
  /** Per-argument provenance: argument name -> source ids. */
  provenance: Record<string, string[]>;
  /** Per-argument taints: argument name -> security labels. */
  taints: Record<string, TaintLabel[]>;
  /** Cross-tool state observed before this call. */
  toolchain: ToolchainState;
  /** Execution correlation. */
  execution: ExecutionIdentity;
  /** Internal domains for external-destination detection. */
  internalDomains?: string[];
}

/** A matched policy rule with evidence. */
export interface MatchedRule {
  id: string;
  triggeredArgs: string[];
  evidence: string[];
  reason?: string;
}

/** The engine's deterministic decision. */
export interface SecurityDecision {
  decision: Decision;
  riskLevel: RiskLevel;
  matchedRules: MatchedRule[];
  reason: string;
  evidence: string[];
  /** Redacted provenance summary (source ids only). */
  provenance: Record<string, string[]>;
  /** Taint summary (labels only). */
  taints: Record<string, TaintLabel[]>;
  toolchain: ToolchainState;
  timestamp: string;
}

/** Privacy-preserving durable proof (never raw args/results/credentials). */
export interface SecurityProof {
  proofId: string;
  tool: string;
  capabilities: SecurityCapability[];
  callId?: string;
  nested?: boolean;
  decision: Decision;
  riskLevel: RiskLevel;
  matchedRules: Array<{ id: string; triggeredArgs: string[]; evidence: string[] }>;
  provenanceSummary: Record<string, string[]>;
  taintSummary: Record<string, TaintLabel[]>;
  toolchain: ToolchainState;
  reason: string;
  timestamp: string;
}

/** Strictest-decision ordering helpers. */
export const DECISION_ORDER: Record<Decision, number> = {
  allow: 1,
  require_approval: 2,
  deny: 3,
};

export const RISK_ORDER: Record<RiskLevel, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Monotonically pick the stricter of two decisions. */
export function stricterDecision(a: Decision, b: Decision): Decision {
  return DECISION_ORDER[a] >= DECISION_ORDER[b] ? a : b;
}

/** Monotonically pick the higher of two risk levels. */
export function higherRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_ORDER[a] >= RISK_ORDER[b] ? a : b;
}
