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
    preset: balanced                 # permissive | balanced | strict
    internalDomains: []            # e.g. ["acme.com"]
    blockedDomains: []             # always denied when named as a sink
    allowedExternalDomains: []     # empty disables allowlist enforcement
    sensitivePathPatterns: []      # e.g. ["**/private/*.asc"]

    # Optional per-rule overrides; leave commented to inherit the preset.
    # sensitiveExternalAction: deny   # allow | ask | deny
    # untrustedPrivateAccess: ask
    # untrustedCodeExecution: deny
    # untrustedLocalMutation: ask
    # credentialAccessAfterUntrusted: deny
    # sensitivePathRead: ask
    # sensitivePathMutation: deny
    # destructiveOperation: ask
    # remoteScriptExecution: deny
    # unlistedExternalAction: ask
    # unknownTool: ask

  proof:
    enabled: true
    maxRecords: 1000
    # file: /var/log/dsh/riskproof.jsonl   # optional, append-only
```

## Modes

- **`enforce`** — RiskProof applies `allow` / `ask` / `deny` and records proofs.
- **`observe`** — RiskProof analyzes, records proofs, and warns, but never changes execution. Use it during initial rollout and false-positive triage.

## Policy decisions

Each policy field accepts `allow`, `ask`, or `deny`. `ask` maps to DSH's native approval service; if no approval service is mounted, the DSH registry degrades `ask` to `deny` (fail closed).

Hard invariants are not configurable: cloud metadata/link-local access, catastrophic system operations, credential material in external/network actions, operator-blocked destinations, and confirmed private-data exfiltration remain `deny` under every preset.

## Policy presets

Presets provide a usable starting point; an explicitly configured decision overrides the selected preset.

| Policy | `permissive` | `balanced` (default) | `strict` |
| --- | --- | --- | --- |
| Sensitive external action | ask | deny | deny |
| Private access after ingestion | allow | ask | deny |
| Untrusted code execution | ask | deny | deny |
| Untrusted local mutation | allow | ask | deny |
| Credential access after ingestion | ask | deny | deny |
| Sensitive path read | ask | ask | deny |
| Sensitive path mutation | ask | deny | deny |
| Destructive operation | ask | ask | deny |
| Remote script execution | ask | deny | deny |
| Unlisted external destination | ask | ask | deny |
| Unknown tool | allow | ask | deny |

`permissive` does not bypass hard invariants. It is intended for an initial rollout after `observe`, not as a full-access mode.

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

`policy.internalDomains` marks email domains, URL hosts, and bare host targets as trusted, so `sensitive_data_external_action` does not flag, for example, customer data sent to `colleague@acme.com` or `https://api.acme.com`. Exact domains, subdomains, and `*.example.com` entries are supported. Private IP ranges and `localhost` are internal; cloud metadata and link-local targets are always blocked by the hard invariant.

## Egress domain policy

- `blockedDomains` denies recognized email and URL/bare-host destinations even when the payload has no detected sensitive data.
- `allowedExternalDomains` activates an external-destination allowlist. A recognized external destination outside the list uses `unlistedExternalAction`; an empty list disables this rule.
- `internalDomains` defines the trust boundary for sensitive-data rules and is independent of the allowlist.

Domain entries accept an exact domain/IP or a leading `*.` wildcard. Schemes, paths, credentials, control characters, and interior wildcards fail configuration validation. Destination policy examines recognized sink fields; it is not a DNS firewall and does not govern network traffic hidden inside an opaque tool implementation.

## Sensitive paths

Built-in patterns cover live `.env` variants, Git/network/package-registry credentials, shell histories, process environments, common cloud/container/cluster/developer-service credentials, SSH private keys, private-key/key-store extensions, Vault/Terraform credentials, and service-account files. Safe templates such as `.env.example`, `.env.sample`, and `.env.template` are excluded.

Use `sensitivePathPatterns` to add normalized full-path globs with `*`, `?`, or `**`:

```yaml
policy:
  sensitivePathPatterns:
    - "**/private/*.asc"
    - "**/production/credentials.json"
```

Proof evidence stores only the argument field and sensitivity category, not the raw path.

## Command-risk checks

`CODE_EXECUTION` tools receive bounded high-confidence checks for catastrophic system operations, forced/destructive Git or filesystem operations, remote content piped directly to an interpreter, privilege escalation, opaque PowerShell commands, and network-capable commands carrying credential taint. RiskProof is not a full shell parser; ambiguous or obfuscated syntax remains subject to the unknown/untrusted rules and the host sandbox.

## Proof persistence

Proofs are retained in a bounded in-memory ring by default. Set `proof.file` to append each redacted proof as one JSON object per line. The parent directory must already exist and be writable by the DSH process. Newly created files use mode `0600`; operators remain responsible for directory permissions, rotation, retention, and backups.

Proofs contain rule ids, decisions, risk levels, source ids, taint labels, toolchain state, remediation guidance, and opaque proof ids. They never contain raw tool arguments or results. `ask` and `deny` reasons include the proof id and up to two recommended actions for correlation and recovery. `proofStats()` aggregates retained records by decision, risk, and rule id.

## Validation limits

Configuration fails at plugin load when a value is out of range or inconsistent:

| Field | Maximum |
| ----- | ------- |
| `provenance.maxEntries` | 4096 |
| `provenance.maxEntryBytes` | 4 MiB |
| `provenance.maxTotalBytes` | 64 MiB |
| `provenance.minMatchLength` | 4096 |
| `toolchain.maxEvents` / `chainWindow` | 4096 |
| `proof.maxRecords` | 10000 |
| Each policy list | 256 entries |
| Each policy list entry | 512 characters |

`maxEntryBytes` cannot exceed `maxTotalBytes`, and `chainWindow` cannot exceed `maxEvents`.
