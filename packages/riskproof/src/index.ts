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
  ProvenanceFlow,
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
export {
  evaluate,
  hasTaint,
  hasAnyTaint,
  getTaints,
} from "./engine.js";

// OPA/Rego policy-as-code
export { OpaPolicyEngine, evaluateWithOpa, OPA_MAX_WASM_BYTES } from "./opa-policy.js";
export type { OpaPolicyOptions, OpaPolicyMatch } from "./opa-policy.js";

// Automatic MCP context provenance
export {
  ContextTracker,
  ProvenanceMapper,
  CONTEXT_TRACKER_LIMITS,
} from "./provenance.js";
export type {
  ContextEntry,
  ContextEntryKind,
  ContextTrackerOptions,
  ProvenanceMapping,
} from "./provenance.js";

// Cross-tool MCP capability composition and sequence enforcement
export {
  ToolchainGuard,
  TOOLCHAIN_GUARD_LIMITS,
  classifyToolchainCapabilities,
  applyToolchainGuard,
} from "./toolchain-guard.js";
export type {
  ToolchainCapability,
  ToolchainGuardOptions,
  ToolchainEvent,
  McpToolDescriptor,
} from "./toolchain-guard.js";

// MCP tool identity continuity and pinned-manifest enforcement
export {
  ToolIdentityGuard,
  TOOL_IDENTITY_LIMITS,
  canonicalizeToolDescriptor,
  digestToolDescriptor,
} from "./tool-identity-guard.js";
export type {
  ToolIdentityMode,
  ToolIdentityViolation,
  ToolIdentityGuardOptions,
  ToolIdentityObservation,
  McpToolIdentityDescriptor,
} from "./tool-identity-guard.js";

// Host-held task authorization, descriptor binding, and call-budget enforcement
export {
  TaskAuthorizationGuard,
  TASK_AUTHORIZATION_LIMITS,
  applyTaskAuthorizationGuard,
} from "./task-authorization-guard.js";
export type {
  TaskToolAuthorization,
  TaskAuthorizationContract,
  TaskAuthorizationRequest,
  TaskAuthorizationViolation,
  TaskAuthorizationReservation,
  TaskAuthorizationRejection,
  TaskAuthorizationResult,
  TaskAuthorizationEvent,
  TaskAuthorizationGuardOptions,
} from "./task-authorization-guard.js";

// Provider-scoped ToolKey and signed pinned manifests
export {
  TOOL_MANIFEST_VERSION,
  TOOL_MANIFEST_ENVELOPE_VERSION,
  TOOL_KEY_CANONICAL_PREFIX,
  TOOL_MANIFEST_LIMITS,
  parseToolKey,
  canonicalizeToolKey,
  parseCanonicalToolKey,
  digestToolKey,
  parsePinnedToolManifest,
  canonicalizePinnedToolManifest,
  digestPinnedToolManifest,
  parseSignedPinnedToolManifestEnvelope,
  serializeSignedPinnedToolManifestEnvelope,
  signPinnedToolManifest,
  PinnedToolManifestVerifier,
  VerifiedPinnedToolManifest,
  verifySignedPinnedToolManifest,
} from "./tool-manifest.js";
export type {
  ToolKey,
  ToolPackageMetadata,
  ToolContainerMetadata,
  ToolPublisherMetadata,
  PinnedToolManifestEntryV1,
  PinnedToolManifestV1,
  ToolManifestSignatureAlgorithm,
  SignedPinnedToolManifestEnvelopeV1,
  Ed25519KeyMaterial,
  HmacKeyMaterial,
  Ed25519ManifestTrustAnchor,
  HmacManifestTrustAnchor,
  ManifestTrustAnchor,
  Ed25519ManifestSigner,
  HmacManifestSigner,
  ManifestSigner,
  ManifestTrustSemantics,
  ManifestVerificationCode,
  ManifestVerificationDiagnostic,
  ToolBindingVerificationCode,
  ToolBindingVerificationResult,
  VerifiedPinnedToolManifestSummary,
  SignedManifestVerificationResult,
  PinnedToolManifestVerifierOptions,
} from "./tool-manifest.js";

// Candidate-set and model tool-selection integrity
export { ToolSelectionGuard, TOOL_SELECTION_LIMITS } from "./tool-selection-guard.js";
export type {
  SelectionReason,
  ToolSelectionViolation,
  ToolSelectionCandidatePolicy,
  ToolSelectionPolicy,
  ObservedSelectionCandidate,
  ToolSelectionRequest,
  ToolSelectionAdmission,
  ToolSelectionEvent,
  ToolSelectionGuardOptions,
} from "./tool-selection-guard.js";

// Exact, expiring, signed, and single-use approval tickets
export {
  APPROVAL_TICKET_VERSION,
  APPROVAL_TICKET_ALGORITHM,
  APPROVAL_TICKET_LIMITS,
  ApprovalTicketValidationError,
  StaticApprovalTicketTrustStore,
  InMemoryApprovalTicketReplayStore,
  ApprovalTicketVerifier,
  canonicalizeApprovalArguments,
  digestApprovalArguments,
  issueApprovalTicket,
  parseApprovalTicket,
  serializeApprovalTicket,
} from "./approval-ticket.js";
export type {
  ApprovalTicketToolKey,
  ApprovalTicketEffect,
  ApprovalTicketPrincipal,
  ApprovalTicketBinding,
  ApprovalTicketPayload,
  SignedApprovalTicket,
  ApprovalTicketIssuerOptions,
  ApprovalTicketTrustStore,
  ApprovalTicketReplayRecord,
  ApprovalTicketReplayStore,
  ApprovalTicketBindingField,
  ApprovalTicketFailureCode,
  ApprovalTicketAccepted,
  ApprovalTicketDenied,
  ApprovalTicketVerificationResult,
  ApprovalTicketAuditEvent,
  ApprovalTicketVerifierOptions,
  InMemoryApprovalTicketReplayStoreOptions,
} from "./approval-ticket.js";

// Cross-process task/session budgets and durable replay protection
export {
  PERSISTENT_TASK_LEDGER_LIMITS,
  PersistentTaskLedger,
  PersistentTaskLedgerCorruptionError,
  PersistentTaskLedgerPolicyMismatchError,
  PersistentTaskLedgerCapacityError,
  PersistentTaskLedgerLockError,
} from "./persistent-task-ledger.js";
export type {
  PersistentLedgerScope,
  PersistentLedgerToolBudget,
  PersistentLedgerBudget,
  PersistentTaskLedgerOptions,
  PersistentLedgerReserveRequest,
  PersistentLedgerBudgetViolation,
  PersistentLedgerReservation,
  PersistentLedgerReservationDenied,
  PersistentLedgerReserveResult,
  PersistentLedgerNoncePurpose,
  PersistentLedgerNonceRequest,
  PersistentLedgerNonceResult,
  PersistentLedgerRecoveryResult,
  PersistentLedgerEvent,
  PersistentLedgerSnapshot,
} from "./persistent-task-ledger.js";
export { PersistentLedgerApprovalReplayStore } from "./ledger-approval-replay-store.js";

// Signed decision -> dispatch -> result/effect execution receipts
export {
  ExecutionReceiptStore,
  EXECUTION_RECEIPT_LIMITS,
  digestCanonicalValue,
} from "./execution-receipt.js";
export type {
  ExecutionOutcome,
  NoDispatchReason,
  EffectEvidenceKind,
  EffectEvidenceStatus,
  EffectEvidence,
  ExecutionScope,
  StartExecutionReceiptInput,
  DispatchReceiptInput,
  SettleExecutionReceiptInput,
  NoDispatchReceiptInput,
  ReceiptSignature,
  DecisionReceiptEvent,
  DispatchReceiptEvent,
  ResultReceiptEvent,
  NoDispatchReceiptEvent,
  ExecutionReceiptEvent,
  ExecutionReceipt,
  ExecutionReceiptDiagnostic,
  ExecutionReceiptStoreOptions,
} from "./execution-receipt.js";

// Explainer
export {
  formatCard,
  formatCompact,
  buildRiskExplanation,
  formatPolishedCard,
  sanitizeTerminal,
  RULE_DB,
  RULE_DB_EN,
} from "./explainer.js";
export type {
  ExplainerLocale,
  FormatMetadata,
  ExplanationPolisher,
  PolishedExplanationOptions,
  RiskExplanation,
  RiskPathStep,
  RiskPathKind,
  RiskFinding,
  AuthorizationEvidence,
  RiskConsequence,
  EvidenceCoverage,
  EvidenceCoverageLevel,
  ExplanationRecommendationAction,
} from "./explainer.js";

// Proof Store
export {
  ProofStore,
  DEFAULT_PROOF_LIST_LIMIT,
  MAX_PROOF_LIST_LIMIT,
  MAX_CORRUPT_DIAGNOSTICS,
  MAX_USER_NOTE_LENGTH,
  MAX_PROOF_FILE_BYTES,
  parseProofKey,
} from "./proof-store.js";
export type {
  ProofRecord,
  ProofFilter,
  ProofListResult,
  CorruptProofDiagnostic,
  CorruptProofKind,
  ProofKeyInput,
  ProofStoreOptions,
  ProofRetentionPolicy,
  ProofPruneResult,
} from "./proof-store.js";

// Proxy Server
export {
  McpProxyServer,
  MCP_MAX_LINE_BYTES,
  MCP_SHUTDOWN_GRACE_MS,
  MCP_MAX_PENDING_REQUESTS,
  MCP_MAX_OUTPUT_QUEUE_BYTES,
  MCP_BACKPRESSURE_TIMEOUT_MS,
  MCP_MAX_TOOL_LIST_PAGES,
  MCP_MAX_AGGREGATED_TOOLS,
  digestDecisionPolicy,
} from "./proxy-server.js";
export type {
  ProxyOptions,
  ProxyToolNamespace,
  ProxyApprovalBindingContext,
  ProxySelectionContext,
  ProxyEffectEvidenceContext,
} from "./proxy-server.js";

// HTTP Server
export { startHttpServer } from "./http-server.js";
export type { HttpServerOptions } from "./http-server.js";

// Fixtures
export { ALL_FIXTURES, ATTACK_FIXTURES, BENIGN_FIXTURES } from "./fixtures.js";
export type { Fixture, MCPToolDef } from "./fixtures.js";
