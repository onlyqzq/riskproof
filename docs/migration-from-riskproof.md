# Migrating from RiskProof (MCP)

RiskProof was previously an MCP Proxy / HTTP Sidecar / Python SDK product. It is now a DeepSeek Harness-native plugin. This page records what changed and why.

## What changed

| Before | After |
| ------ | ----- |
| Standalone MCP proxy process | `tools/pre-execute` + `tools/result` hooks inside DSH |
| HTTP evaluation server | in-process evaluation |
| Python SDK / LangGraph adapter | none (DSH-native) |
| Fixed seven tool names | capability classification (EIT/PAT/NAT + …) |
| Separate approval ticket runtime | DSH native approval (`ask`) |
| CLI (`riskproof serve/proxy`) | none |

## Why

DSH already provides the Agent Runtime, tool registry, dispatch, approval, lifecycle, Code Mode, and HMR. Re-implementing those outside DSH duplicated runtime while weakening the security story. RiskProof now owns only what DSH does not: security evidence, provenance, taint, cross-tool state, policy decisions, and proof.

## Migration path

There is no drop-in API migration — this is a product transformation.

1. Remove the MCP proxy / HTTP sidecar / Python SDK from your deployment.
2. Add `dsh-riskproof` to the DSH profile (see the [Quick Start](../README.md#quick-start)).
3. Port policy intent:
   - per-tool allowlists → `classification.overrides`
   - domain allowlists → `policy.internalDomains`
   - custom rules → deterministic engine rules (or file a feature request)
4. Run in `mode: observe` first, then switch to `enforce`.

## Preserved security core

The deterministic engine ideas, provenance tracking, taint analysis, cross-tool chain detection, redaction, and proof concepts were carried forward and re-founded on the capability model. Git history is the archive of the removed runtime code.
