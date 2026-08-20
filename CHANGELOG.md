# Changelog

All notable changes to RiskProof are documented here.

The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-08-20

### Added

- Optional append-only, redacted JSONL proof persistence and retained-proof statistics.
- Nested object/array argument analysis with stable leaf paths.
- Common Chinese capability-classification vocabulary.
- Node.js 22.19 and 24 compatibility CI with enforced coverage thresholds.
- Repeatable Awesome DSH Plugin metadata checks and direct Git-source install coverage.
- `permissive`, `balanced`, and `strict` policy presets with per-rule overrides.
- Sensitive-path read/write protection with built-in credential-file patterns and operator extensions.
- Deterministic command-risk checks for catastrophic operations, destructive commands, and download-and-execute pipelines.
- Egress domain denylist and optional allowlist handling for recognized tool destinations.
- Credential-bearing network-command, credential-after-ingestion, and untrusted-local-mutation rules.
- Actionable remediation guidance and per-rule proof statistics.
- A security-plugin benchmark documenting adopted patterns, rejected scope, and remaining limitations.

### Fixed

- Preserve the real EIT/PAT event order instead of treating `PAT → EIT` as an exfiltration chain.
- Apply internal-domain policy to URL and bare-host destinations.
- Isolate cached classifications for same-name tools in different agent scopes.
- Record successful capability events even when the result has no searchable content.
- Recover provenance when later arguments wrap a sufficiently long tracked result.
- Reject inconsistent or unreasonably large configuration values at plugin load.
- Point package metadata, installation docs, and security reporting at the canonical repository.
- Declare all official `@deepseek-ai/*` runtime packages as peer dependencies.
- Build automatically during Git-source installation and require release tags to match the package version.

## [0.1.0] — 2026-08-18

First DeepSeek Harness-native release. RiskProof is re-founded as a DSH security plugin; the prior MCP Proxy / HTTP Sidecar / Python SDK product is retired (see [docs/migration-from-riskproof.md](docs/migration-from-riskproof.md)).

### Added

- Native Cordis plugin (`dsh-riskproof`) with Schemastery configuration.
- `tools/pre-execute` allow / ask / deny gate, monotonic with other plugins.
- `tools/result` observer for provenance and toolchain state.
- Deterministic tool capability classifier (`EXTERNAL_INGESTION`, `PRIVATE_ACCESS`, `EXTERNAL_ACTION`, `LOCAL_MUTATION`, `CODE_EXECUTION`, `CREDENTIAL_ACCESS`) with configurable overrides.
- Per-session provenance tracking (bounded substring matching) and additive taint analysis.
- Cross-tool `EIT → PAT → NAT` attack-chain detection.
- Privacy-preserving proof records (no raw arguments/results/credentials).
- `enforce` and `observe` modes.
- Code Mode support (nested dispatches are protected without double-counting).
- Unit, integration, and security-regression test suites.

### Removed

- MCP Proxy runtime, HTTP evaluation server, Python SDK, LangGraph adapter, and standalone CLI.

### Security

- Deterministic, explainable decisions only. No LLM in the security boundary.
- Per-session state isolation and bounded in-memory data structures.
