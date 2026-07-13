// ============================================================================
// RiskProof — Public API
// ============================================================================

// Types
export { VERSION } from "./version.js";
export type {
  ToolName, RiskLevel, Decision, TaintLabel,
  EngineInput, EngineOutput, EngineOptions,
  ArgumentEvidence, MatchedPolicy,
  Capability, SafetyInvariant,
  AuditProof, TraceContext, UserAction,
  ProvenanceSource, ProvenanceEdge, ProvenanceGraph,
} from "./types.js";

// Config
export type { RiskProofConfig, CustomRule, ConfigOptions } from "./config.js";
export { CONFIG_COMPLEXITY_LIMITS, loadConfig, validateConfig } from "./config.js";

// Runtime validation for JSON-facing integrations
export {
  parseEngineInput,
  InputValidationError,
  SUPPORTED_TOOLS,
  TAINT_LABELS,
  ENGINE_INPUT_COMPLEXITY_LIMITS,
} from "./validation.js";
export { redactEngineOutput, redactedValue, sensitiveTaints, redactLogText } from "./redaction.js";

// Engine
export { evaluate, hasTaint, hasAnyTaint, getTaints } from "./engine.js";

// Explainer
export { formatCard, formatCompact, sanitizeTerminal, RULE_DB } from "./explainer.js";

// Proof Store
export {
  ProofStore,
  DEFAULT_PROOF_LIST_LIMIT,
  MAX_PROOF_LIST_LIMIT,
  MAX_CORRUPT_DIAGNOSTICS,
  MAX_USER_NOTE_LENGTH,
  MAX_PROOF_FILE_BYTES,
} from "./proof-store.js";
export type {
  ProofRecord,
  ProofFilter,
  ProofListResult,
  CorruptProofDiagnostic,
  CorruptProofKind,
} from "./proof-store.js";

// Proxy Server
export {
  McpProxyServer,
  MCP_MAX_LINE_BYTES,
  MCP_SHUTDOWN_GRACE_MS,
  MCP_MAX_PENDING_REQUESTS,
  MCP_MAX_OUTPUT_QUEUE_BYTES,
  MCP_BACKPRESSURE_TIMEOUT_MS,
} from "./proxy-server.js";
export type { ProxyOptions } from "./proxy-server.js";

// HTTP Server
export { startHttpServer } from "./http-server.js";
export type { HttpServerOptions } from "./http-server.js";

// Fixtures
export { ALL_FIXTURES, ATTACK_FIXTURES, BENIGN_FIXTURES } from "./fixtures.js";
export type { Fixture, MCPToolDef } from "./fixtures.js";
