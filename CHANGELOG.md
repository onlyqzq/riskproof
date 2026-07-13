# Changelog

All notable changes are documented here following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Runtime validation for CLI, HTTP, MCP, and the public `evaluate()` boundary.
- The `sensitive_data_external_http` policy, bringing the engine to 17 built-in
  match rules plus the configurable default-deny fallback.
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

### Changed

- Node.js support is now `>=22`; Node 18 and 20 are end-of-life and no longer
  part of the supported release matrix.
- Python runtime dependencies moved to patched LangGraph/LangChain 1.x ranges.
- MCP tools no longer receive capabilities based on read-like name substrings;
  unclassified calls require approval.
- Poisoned tools are hidden from model-visible `tools/list` while retained in a
  quarantine cache for direct-call blocking.
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

### Security

- Unsigned `_meta.riskproof_user_decision` is disabled by default and is
  documented only as an explicitly trusted local MVP compatibility mode.
- HTTP no longer enables wildcard CORS or accepts caller-supplied security
  context by default.
- npm and Python dependency audits currently report no known third-party
  vulnerabilities in the resolved release candidate.

### Compatibility

- Upgrading from the original dependency set requires Node 22+ and patched
  LangGraph/LangChain 1.x. Public RiskProof decision and proof JSON remain on
  version `0.1.0`; no database migration exists because storage is file-based.

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
