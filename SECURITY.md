# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## What RiskProof is

RiskProof is a **plugin inside the DeepSeek Harness Tool Runtime**. It observes tool executions and makes deterministic, evidence-backed allow / ask / deny decisions before a side effect runs. It does not execute tools itself, does not hold secrets, and does not replace the DSH sandbox or approval service.

## Trusted computing base

RiskProof trusts, and therefore assumes the integrity of:

- the DeepSeek Harness process and its Tool Runtime (`@deepseek-ai/dsh-tools`)
- the Cordis plugin lifecycle (`@deepseek-ai/cordis`)
- the DSH approval service (for `ask` decisions)
- the process running RiskProof (its memory and its proof output directory)

RiskProof is **not** a boundary against a compromised harness process. If the process, a loaded plugin with equal access, or the host is compromised, a `tools/pre-execute` listener can be bypassed or its decision ignored.

## Supported DSH paths

RiskProof protects tool calls that traverse the supported pipeline:

- `tools/pre-execute` — the allow / ask / deny gate before dispatch
- `tools/result` — the observe-only success notification that updates provenance and toolchain state

Both native tool calling and Code Mode sub-dispatches re-enter this pipeline, so both are covered. A tool that the harness executes outside this pipeline is not observed.

## Known limitations

### Provenance

Provenance is recovered with **exact and bounded substring matching** over per-session tool results. RiskProof does **not** track:

- summarization, translation, or semantic paraphrase
- Base64 / compression / encryption transformations
- multi-fragment recombination that no longer contains a tracked substring
- reasoning that happens invisibly inside the model

RiskProof tracks *supported observable data flows*, not all information flows.

### Taint

Taint detection is pattern-based and additive. It can be evaded by an adversary who transforms data past the recognized patterns. It is not a semantic DLP.

### Proofs

Proofs are audit evidence of RiskProof's own decision, not proof that a real-world side effect did or did not occur. A `deny` proof means the call was blocked at the pipeline; a successful tool result is not proof that its external effect happened.

### Single-process scope

State is per-session and in-memory. It does not span processes, machines, or sessions. Restarting the harness resets provenance and toolchain state.

### Determinism, not adversarial AI

RiskProof uses no LLM for security decisions. It cannot reason about a tool's *actual* behavior beyond its declared metadata and observable arguments/results.

## Reporting a vulnerability

Please report privately rather than opening a public issue. Include:

- the DSH and RiskProof versions
- a minimal reproduction
- whether the issue is a bypass (false negative), a false positive, or a stability/DoS issue

Send reports to the maintainers via the project's private security channel. We aim to acknowledge within 7 days and publish a fix + advisory for confirmed issues.
