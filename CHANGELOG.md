# Changelog

All notable changes are documented here following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Runtime validation for CLI, HTTP, MCP, and the public `evaluate()` boundary.
- The `sensitive_data_external_http`, `dangerous_database_query`,
  `untrusted_mutative_tool`, `cloud_metadata_link_local_http`, and
  `protected_system_path_write` policies, bringing the per-call engine to 21
  built-in match rules plus the configurable default-deny fallback.
- Bounded MCP `ContextTracker` and `ProvenanceMapper` support for semantic,
  exact-substring provenance across resources, prompts, and tool results, with
  explicit `agent_generated` fallback and additive transformation `flows`.
- A bounded, metadata-only `ToolchainGuard` with deterministic EIT/PAT/NAT
  classification, cross-tool transition review, and confirmed parasitic
  exfiltration blocking. A UI-neutral redacted causal explanation model exposes
  risk paths, evidence coverage, impact, and safer alternatives.
- Complete canonical MCP tool-descriptor commitments with process-local TOFU
  and operator-pinned modes. Name collisions, manifest mismatches, late
  additions, and descriptor rug pulls enter sticky quarantine before planning
  or direct invocation.
- A host-held `TaskAuthorizationGuard` and `--task-contract` CLI path that bind
  calls to exact tool names, optional descriptor digests, provenance IDs,
  expiry, and global/per-tool budgets. Pending calls reserve budget before
  dispatch; failed results release it and successful results consume it.
- A bidirectional MCP method firewall that rejects unknown client requests,
  locally terminates or rejects server requests, narrows initialize
  capabilities, drops unmatched responses, and normalizes correlated replies.
- A five-part `npm run demo:research` conformance demonstration covering tool
  identity, task authority, parasitic chains, dangerous sinks, and protocol
  boundaries without real network, secret, or dangerous-tool side effects.
- OPA/Rego policy-as-code through the official OPA WASM runtime, with
  monotonic multi-module aggregation and fail-closed result validation.
- `file_read`, `file_write`, `database_query`, and `browser_action` engine tool
  classes in addition to email, HTTP, and shell tools.
- Consistent Chinese/English explanations and a vendor-neutral, redacted,
  timeout-bounded optional LLM explanation-polisher interface.
- AES-256-GCM proof envelopes, HMAC-SHA-256 integrity, read keyrings for key
  rotation, strict protected-record modes, and age/count retention policies.
- JSON Schema for version 1 configuration and schema/runtime consistency tests.
- HTTP `/ready`, exact-origin opt-in CORS, security headers, 1 MiB body limits,
  content-type validation, and request/header/keep-alive timeouts.
- Side-effect-free MCP `riskproof/evaluate` preflight for two-phase Agent
  approval and non-replaying LangGraph execution.
- TypeScript security, configuration, HTTP, proof-store, scenario, CLI, MCP,
  package-install, and benchmark coverage; Python callback, client, Agent,
  package-build, and clean-install coverage.
- Reproducible `npm run benchmark` microbenchmark for engine, proof writes, and
  local HTTP evaluation.
- Reproducible `npm run test:opa` and `npm run test:docker` release smokes for
  real Rego-to-WASM execution and hardened container runtime behavior.

### Changed

- Node.js support is now `>=22`; Node 18 and 20 are end-of-life and no longer
  part of the supported release matrix.
- Python runtime dependencies moved to patched LangGraph/LangChain 1.x ranges.
- MCP tools no longer receive capabilities based on read-like name substrings;
  unclassified calls require approval.
- Upstream MCP processes now inherit a minimal launch-variable allowlist rather
  than the complete parent environment. Example MCP configuration exposes only
  the RiskProof wrapper, not a parallel raw-server bypass.
- Poisoned tools are hidden from model-visible `tools/list` while retained in a
  quarantine cache for direct-call blocking.
- `tools/list` now preserves request parameters and commits complete raw
  descriptors before legacy scanner/cache reduction. Programmatic hosts may
  preload authenticated `trusted_user` context in a host-owned tracker.
- LangGraph tool execution now preflights every call, batches all approval
  decisions, then executes each allowed/approved tool at most once.
- CI uses the root lockfile, Node 22/24 and Python 3.10–3.13; release actions are
  commit-pinned and the prepared publish chain uses npm/PyPI OIDC plus GHCR
  provenance/SBOM generation.
- Proof persistence uses a fully written temporary file and atomic no-overwrite
  hard-link commit, including for multiple processes sharing a volume.
- TypeScript compilation now rejects unused locals and parameters.
- Custom policy expressions now run on the linear-time `re2js` engine;
  backtracking-only JavaScript lookaround/backreference syntax is no longer
  accepted.
- Proof storage remains backward-readable by default, while newly configured
  stores can write authenticated encrypted envelopes and enforce strict reads.
- The Docker base image is digest-pinned and the CI/release container smoke now
  checks non-root/read-only execution, HTTP limits, protected proofs,
  persistence, and graceful `SIGTERM` handling.

### Fixed

- Propagated JSON/YAML configuration through CLI check, HTTP serve, MCP proxy,
  and the public API; unknown fields, tools, duplicate/reserved IDs, invalid
  risks, and invalid/oversized regular expressions now fail closed.
- Prevented caller-controlled time rollback, proof-path escape, proof ID
  overwrites, incorrect proof tool fields, and world-readable proof files.
- Redacted detected secret, API-key, PII, customer, source-code, financial, and
  patient values from responses, stored proofs, approval output, and logs.
- Closed nested-secret, lowercase Bearer, multiple-recipient/CC/BCC, external
  HTTP sensitive-data, `curl|shell`, `wget|shell`, and recursive-rm bypasses.
- Fixed sink selection, per-field provenance, capability allowlist fail-closed
  behavior, YAML loading under ESM, HTTP internal-error disclosure, and stale
  test harness paths.
- Python callback decisions, subprocess credential isolation, EOF/close
  handling, request synchronization, DeepSeek endpoint selection, and import
  side effects now fail closed.
- Demo failures now produce a non-zero process exit status.
- Fixed the production image omitting `@open-policy-agent/opa-wasm` and its
  runtime dependencies after OPA policy support was added.

### Security

- Unsigned `_meta.riskproof_user_decision` is disabled by default and is
  documented only as an explicitly trusted local MVP compatibility mode.
- HTTP no longer enables wildcard CORS or accepts caller-supplied security
  context by default.
- npm and Python dependency audits currently report no known third-party
  vulnerabilities in the resolved release candidate.
- MCP response context is bounded and memory-only; metadata inspection never
  returns the indexed raw content. Proof envelope verification uses constant-
  time signature comparison, and unreadable evidence is never auto-pruned.
- Upstream MCP processes inherit a minimal parent environment, known metadata
  SSRF and persistence sinks deny even with a matching capability, tool
  identity quarantine is monotonic, and task call budgets count in-flight work
  to prevent parallel overrun.

### Compatibility

- Upgrading from the original dependency set requires Node 22+ and patched
  LangGraph/LangChain 1.x. Public RiskProof decision JSON remains compatible.
  File proofs require no forced migration: legacy JSON remains readable unless
  an operator explicitly enables strict encryption/signature requirements.

## [0.1.0] — 2026-07-09

### Added

- Initial deterministic policy engine for `send_email`, `http_request`, and
  `shell_exec` with provenance, taints, capabilities, invariants, explanations,
  JSON proof storage, CLI, HTTP and MCP adapters.
- Initial Python Agent SDK, LangChain callback, LangGraph approval demo, attack
  fixtures, scenario harness, Docker files, and project documentation.

### Security

- Initial schema-poisoning scan and protocol-level approval prototype. The
  unsigned approval field is not a production security token and must only be
  used across a trusted local process boundary.
