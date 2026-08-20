# Architecture

RiskProof is a single Cordis plugin (`dsh-riskproof`) layered over the DSH Tool Runtime. It owns the security model; DSH owns the runtime.

## Layers

```text
                DeepSeek Agent
                      │
                      ▼
                DSH ToolRuntime
                      │
                      ▼
              tools/pre-execute
                      │
                      ▼
              ┌─────────────────┐
              │    RiskProof    │
              │  classification │
              │  provenance     │
              │  taint          │
              │  toolchain      │
              │  path/command   │
              │  destination    │
              │  engine         │
              └────────┬────────┘
                       │
              ┌────────┼────────┐
              ▼        ▼        ▼
            allow     ask      deny
                       │
                       ▼
                DSH Approval
                       │
                       ▼
                  Tool Execute
                       │
                       ▼
                  tools/result
                       │
              ┌────────┴────────┐
              ▼                 ▼
       ContextTracker        Toolchain
              │                 │
              └──── evidence ───┘
```

## Module map

| Path | Responsibility |
| ---- | -------------- |
| `src/index.ts` | Cordis plugin entry: `name`, `inject`, `Config`, `apply`. |
| `src/config.ts` | Schemastery schema; the single source of deployment tunables. |
| `src/dsh/runtime.ts` | DSH adapter: `ToolExecution` → `ToolSecurityContext` → `PreToolDecision`; `ToolExecutionResult` → state updates. |
| `src/dsh/decisions.ts` | Decision mapping (`require_approval` ↔ `ask`) and monotonic merge. |
| `src/dsh/runtime-state.ts` | Per-session state isolation. |
| `src/core/engine.ts` | Pure deterministic policy evaluation. No DSH imports. |
| `src/core/arguments.ts` | Bounded nested-argument traversal and stable leaf paths. |
| `src/core/taint.ts` | Source inference + value-based taint detection. |
| `src/core/destination.ts` | External destination / cloud-metadata detection. |
| `src/core/path-policy.ts` | Sensitive credential-path detection with bounded operator globs. |
| `src/core/command-risk.ts` | Bounded high-confidence destructive/network command checks. |
| `src/classification/` | Capability vocabulary, classifier, overrides. |
| `src/provenance/` | Bounded ContextTracker + ProvenanceMapper. |
| `src/toolchain/guard.ts` | Cross-tool EIT/PAT/NAT state. |
| `src/proof/` | Privacy-preserving ProofStore + redaction. |

## Data flow (pre-execute)

1. `tools/pre-execute` receives the `ToolExecution`.
2. The adapter classifies the effective scoped tool (`name` + description + input schema, with config overrides). Same-name definitions are cached separately per agent scope.
3. The per-session `ProvenanceMapper` maps nested argument leaves back to tracked results, yielding provenance ids and taints.
4. Taints are enriched additively (source inference + value detection).
5. The toolchain guard contributes the observed EIT/PAT/NAT state.
6. Destination, sensitive-path, and command-risk detectors add deterministic local evidence.
7. The pure engine evaluates hard invariants and preset-resolved policy rules, then returns a `SecurityDecision` with remediation guidance.
8. The decision maps to `allow` / `ask` / `deny` and merges monotonically with downstream plugins.
9. A privacy-preserving proof is recorded, including rule ids and remediation but no raw path, command, arguments, or results.

## Data flow (result)

On a successful result only:

1. The adapter infers a context kind from the tool + capabilities.
2. When searchable content exists, the result value is recorded in the per-session `ContextTracker` (bounded, metadata + searchable text only).
3. The toolchain guard always records the successful capability event, with any produced context ids. Empty or unindexable results therefore preserve execution order without claiming data provenance.

Failures never record "data obtained".

## Why the core is DSH-free

`src/core/` and `src/classification/`, `src/provenance/`, `src/toolchain/` import no DSH types. This keeps the security decision logic independently unit-testable and prevents the engine from accidentally depending on live runtime state. The DSH adapter is the only seam that knows about `ToolExecution`, `ToolExecutionResult`, and `PreToolDecision`.

## Lifecycle & HMR

Every listener is registered with `ctx.on(...)`, which is fiber-owned: a config reload disposes the previous plugin instance (and its listeners, tracker, and guard) before activating the replacement. The classifier cache is invalidated on `tools/change`. Per-session state is released on `agent/disposed` and bounded as a safety net.
