# Toolchain model

## Capabilities

| Capability | Alias | Meaning |
| ---------- | ----- | ------- |
| `EXTERNAL_INGESTION` | EIT | reads content from outside the trust boundary |
| `PRIVATE_ACCESS` | PAT | reads data inside the trust boundary |
| `EXTERNAL_ACTION` | NAT | sends data outside the trust boundary |
| `LOCAL_MUTATION` | — | writes/mutates local state |
| `CODE_EXECUTION` | — | executes code / a shell / a program |
| `CREDENTIAL_ACCESS` | — | reads credentials, secrets, or key material |

## The attack chain

The core cross-tool pattern:

```text
EXTERNAL_INGESTION → PRIVATE_ACCESS → EXTERNAL_ACTION
```

A single stage is usually safe; the composition is not:

- **Case A** — `EIT → PAT`: untrusted input starts influencing private access → **ask**.
- **Case B** — `EIT → PAT → NAT` without confirmed sensitive data in the outbound args → **ask**.
- **Case C** — `EIT → PAT → NAT` with `CUSTOMER_DATA` / `PII` / `SECRET` (or private provenance) actually in the outbound args → **deny**.

Additional v0.2 transitions reuse the same bounded session history:

- `EXTERNAL_INGESTION → CREDENTIAL_ACCESS` → `deny` under `balanced`.
- untrusted provenance entering `LOCAL_MUTATION` → `ask` under `balanced`.
- credentials entering a network-capable `CODE_EXECUTION` command → hard `deny`.

## Classification

The classifier is deterministic, using tool name, description, and input schema. English and common Chinese security vocabulary are recognized. A tool can carry several capabilities; general-purpose shells map to `CODE_EXECUTION` (and can implement every phase). Unknown tools classify to an empty set and take the configured `unknownTool` posture (default `ask`, fail closed).

Explicit `classification.overrides` win over heuristics:

```yaml
classification:
  overrides:
    gmail_send: [EXTERNAL_ACTION]
    company_db: [PRIVATE_ACCESS]
```

## State

The `ToolchainGuard` keeps a bounded, metadata-only history of successful calls (tool label + capabilities + context ids). It preserves event and capability order: `PAT → EIT` is not treated as `EIT → PAT`, and a single multi-capability event does not manufacture a cross-tool transition. A successful call records its capability event even when its result is empty or cannot be indexed. It never stores raw results. State is per-session, so one session's flow never contaminates another's.

## Code Mode

Code Mode sub-dispatches re-enter the full pipeline with a `parent` token, so nested `tools.*` calls are classified and protected like native calls. `run_code` itself classifies as `CODE_EXECUTION` and is **not** double-counted in the EIT/PAT/NAT chain — only its real sub-tools contribute provenance and toolchain events.
