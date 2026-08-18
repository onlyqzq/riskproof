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

## Rules (v0.1)

| Rule id | Trigger | Default |
| ------- | ------- | ------- |
| `cloud_metadata_link_local` | external action targets a cloud metadata / link-local host | deny |
| `credential_external_action` | `SECRET` / `API_KEY` taint in an external action | deny |
| `sensitive_data_external_action` | sensitive taint in an external action with an external destination | deny |
| `untrusted_code_execution` | untrusted taint in code execution | deny |
| `private_data_exfiltration_chain` | EIT + PAT observed, sensitive data in an external action | deny |
| `suspicious_disclosure_chain` | EIT + PAT observed, external action without confirmed sensitive data | ask |
| `untrusted_private_access` | private access after untrusted ingestion | ask |
| `unknown_tool` | tool could not be classified | ask |

All are deterministic and explainable. No rule uses an LLM.

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
- **State is per-session, in-memory.** It does not span processes, machines, or sessions.
- **Proofs are decision evidence**, not proof that a real-world side effect happened.
- **The plugin trusts the harness process.** It is not a boundary against a compromised process or an equally-privileged loaded plugin.

## Out of scope (v0.1)

OS sandbox, network firewall, DNS/SSRF firewall, credential vault, semantic DLP, LLM judge/approval, web dashboard, distributed provenance graph, multi-machine ledger, cross-session provenance, full shell parser, malware scanner, plugin-installation scanner.
