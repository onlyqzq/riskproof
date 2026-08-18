# Configuration

RiskProof is configured through a Schemastery schema. Invalid values fail at plugin load — there is no half-configured startup.

## Full reference

```yaml
config:
  mode: enforce                 # enforce | observe

  provenance:
    enabled: true
    maxEntries: 256             # entries per session
    maxEntryBytes: 262144       # per entry
    maxTotalBytes: 2097152      # per session
    minMatchLength: 4           # substring-match floor (chars)

  taint:
    enabled: true

  toolchain:
    enabled: true
    maxEvents: 128
    chainWindow: 12

  classification:
    overrides: {}               # { toolName: [CAPABILITY, ...] }

  policy:
    sensitiveExternalAction: deny   # allow | ask | deny
    untrustedPrivateAccess: ask
    untrustedCodeExecution: deny
    unknownTool: ask
    internalDomains: []            # e.g. ["acme.com"]

  proof:
    enabled: true
    maxRecords: 1000
```

## Modes

- **`enforce`** — RiskProof applies `allow` / `ask` / `deny` and records proofs.
- **`observe`** — RiskProof analyzes, records proofs, and warns, but never changes execution. Use it during initial rollout and false-positive triage.

## Policy decisions

Each policy field accepts `allow`, `ask`, or `deny`. `ask` maps to DSH's native approval service; if no approval service is mounted, the DSH registry degrades `ask` to `deny` (fail closed).

## Capability overrides

Capabilities: `EXTERNAL_INGESTION`, `PRIVATE_ACCESS`, `EXTERNAL_ACTION`, `LOCAL_MUTATION`, `CODE_EXECUTION`, `CREDENTIAL_ACCESS`.

```yaml
classification:
  overrides:
    gmail_send: [EXTERNAL_ACTION]
    company_db: [PRIVATE_ACCESS]
    shell: [CODE_EXECUTION]
```

A typo in an override value fails at load — it cannot silently weaken the boundary.

## Internal domains

`policy.internalDomains` marks destinations as trusted, so `sensitive_data_external_action` does not flag, for example, customer data sent to `colleague@acme.com`. Private IP ranges, `localhost`, and link-local addresses are always internal. Cloud metadata hosts are always blocked.
