# Changelog

All notable changes to RiskProof are documented here.

The project follows [Semantic Versioning](https://semver.org/).

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
