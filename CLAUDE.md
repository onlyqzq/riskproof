# RiskProof Development Guide

## Product direction

RiskProof is a **provenance-aware execution security plugin for DeepSeek Harness**.

It is NOT a standalone MCP proxy, an HTTP sidecar, a Python SDK, a generic content
moderation system, or an LLM security judge.

It IS a deterministic layer over the DSH Tool Runtime that answers:

> Where did the data in this tool call come from, what did it flow through, and
> where is it about to go?

## Core idea

A single tool call is usually safe; the composition is not. RiskProof tracks
per-session provenance and taint, then detects the cross-tool attack chain

```text
EXTERNAL_INGESTION → PRIVATE_ACCESS → EXTERNAL_ACTION
```

and blocks or asks *before* the side effect executes, with structured evidence.

## Architecture map

- `src/index.ts` — Cordis plugin entry (`name` / `inject` / `Config` / `apply`).
- `src/config.ts` — Schemastery config schema (single source of tunables).
- `src/dsh/` — the only code that touches DSH types (adapter / lifecycle).
- `src/core/` — pure, deterministic engine + types + taint + destination.
- `src/classification/` — deterministic capability classifier.
- `src/provenance/` — bounded context tracker + mapper.
- `src/toolchain/` — cross-tool EIT/PAT/NAT state.
- `src/proof/` — privacy-preserving proof store + redaction.

## Engineering rules

Before coding:

- explain the task and the affected security property
- propose a file-level plan
- list acceptance criteria

During coding:

- small modules, strict TypeScript, no `any` unless unavoidable
- security decisions stay deterministic and fail closed
- every rule/classifier change needs a test vector

After coding:

- `npm run verify` (typecheck + build + test)
- summarize changed files and how they map to the security model

## Do not drift

- No LLM in the security decision path.
- No re-implementing tool dispatch, approval, or lifecycle.
- No raw arguments/results/credentials in proofs.
- No unbounded state; every tracker is bounded.
- RiskProof must never turn another plugin's `deny` into `allow`.
