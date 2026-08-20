# Security model

## Objective

RiskProof reduces the risk of **cross-tool data exfiltration**: an agent ingests untrusted or private content, and later sends sensitive data to an external destination, where each individual call looked harmless.

## Decision model

RiskProof returns a deterministic decision:

| Decision | DSH mapping | Meaning |
| -------- | ----------- | ------- |
| `allow` | `{ kind: 'allow' }` | no rule matched, or the flow is safe |
| `require_approval` | `{ kind: 'ask', reason }` | a suspicious-but-unconfirmed pattern |
| `deny` | `{ kind: 'deny', reason }` | a confirmed dangerous pattern |

Merging with other plugins is strictly monotonic: `allow < ask < deny`. RiskProof never turns another plugin's `deny` into `allow`.

## Rules (v0.2, `balanced` preset)

| Rule id | Trigger | Default |
| ------- | ------- | ------- |
| `cloud_metadata_link_local` | external action targets a cloud metadata / link-local host | deny |
| `blocked_destination` | recognized destination matches `blockedDomains` | deny |
| `catastrophic_system_operation` | high-confidence disk wipe, root/home recursive deletion, or fork bomb | deny |
| `credential_external_action` | `SECRET` / `API_KEY` taint in an external action | deny |
| `credential_network_command` | network-capable command carries `SECRET` / `API_KEY` taint | deny |
| `credential_access_after_untrusted` | credential access follows external ingestion | deny |
| `sensitive_data_external_action` | sensitive taint in an external action with an external destination | deny |
| `sensitive_path_read` | private read names a built-in or configured credential path | ask |
| `sensitive_path_mutation` | local mutation names a built-in or configured credential path | deny |
| `remote_script_execution` | remote content is piped directly to an interpreter | deny |
| `untrusted_code_execution` | untrusted taint in code execution | deny |
| `untrusted_local_mutation` | untrusted taint is persisted to local state | ask |
| `destructive_operation` | recoverable but destructive command pattern | ask |
| `private_data_exfiltration_chain` | ordered EIT → PAT observed, sensitive data in an external action | deny |
| `suspicious_disclosure_chain` | ordered EIT → PAT observed, external action without confirmed sensitive data | ask |
| `untrusted_private_access` | private access after untrusted ingestion | ask |
| `unlisted_external_destination` | external destination is outside a configured non-empty allowlist | ask |
| `unknown_tool` | tool could not be classified | ask |

All rules are deterministic and explainable. No rule uses an LLM. `permissive` and `strict` change configurable rows, while hard invariants remain `deny`; see [configuration.md](configuration.md).

## Capabilities

Tools are classified into six capabilities (see [toolchain.md](toolchain.md)). The three `EXTERNAL_INGESTION`, `PRIVATE_ACCESS`, `EXTERNAL_ACTION` form the attack-chain model; `LOCAL_MUTATION`, `CODE_EXECUTION`, `CREDENTIAL_ACCESS` cover additional risky behavior.

Classification is heuristic and conservative: a false positive only adds scrutiny, never grants capability. Explicit operator overrides always win.

## Taint

Taint labels describe *what security attribute data carries*; provenance describes *where it came from*. Taint is additive — a tool output cannot remove a label (trusted declassification is future work).

## Failure handling

| Class | Behavior |
| ----- | -------- |
| Security decision failure | fail closed (`deny`) — a throwing `tools/pre-execute` listener denies the call |
| Proof/telemetry failure | contained — proof storage errors are logged and do not block execution |
| Invalid config | plugin fails to load (Schemastery validation) |
| Plugin programming bug | contained by the harness; the tool pipeline reports an error result |

## Known limitations

- **Provenance is substring-based.** Summaries, translations, Base64/compression/encryption, and invisible model reasoning are not tracked. RiskProof tracks *supported observable data flows*.
- **Taint is pattern-based**, not semantic DLP.
- **Command checks are high-confidence regex heuristics**, not a complete Bash, PowerShell, or interpreter parser. Encoded, fragmented, aliased, or dynamically constructed commands may not match.
- **Destination checks inspect recognized sink fields.** They do not resolve DNS, intercept process traffic, or observe network calls hidden inside an opaque tool.
- **Sensitive-path checks inspect recognized path fields.** They do not replace filesystem permissions and intentionally exclude common template files.
- **State is per-session, in-memory.** It does not span processes, machines, or sessions.
- **Proofs are decision evidence**, not proof that a real-world side effect happened.
- **Optional proof JSONL is an operator-managed audit log.** It is redacted and created with private permissions, but its directory, rotation, retention, and host access remain deployment responsibilities.
- **The plugin trusts the harness process.** It is not a boundary against a compromised process or an equally-privileged loaded plugin.

## Out of scope (v0.2)

OS sandbox, process-level network proxy/firewall, DNS/SSRF firewall, credential vault, tool-result rewriting, semantic DLP, LLM judge/approval, general-purpose permission-rule files, web dashboard, distributed provenance graph, multi-machine ledger, cross-session provenance, full shell parser, malware scanner, and plugin-installation scanner.
