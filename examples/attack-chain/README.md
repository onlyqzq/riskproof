# Attack-chain demo

This example demonstrates the core RiskProof scenario: three individually-safe
tool calls that, composed, form a data-exfiltration chain.

```text
1. web_fetch      → EXTERNAL_INGESTION   (untrusted content enters context)
2. database_query → PRIVATE_ACCESS       (customer data is read)
3. send_email     → EXTERNAL_ACTION      (customer data heads external)

RiskProof → DENY (before send_email executes)
```

## Run it

The scenario is reproducible as a deterministic test:

```bash
npm test -- tests/security/attack-chain.test.ts
```

The test drives the real `RiskProofRuntime` over the DSH adapter: it feeds the
three calls through `tools/pre-execute` / `tools/result` and asserts that the
third returns `deny`, that the proof records the `private_data_exfiltration_chain`
rule, and that the outbound argument carries `CUSTOMER_DATA`.

## What each stage contributes

| Call | Capability | Result taint |
| ---- | ---------- | ------------ |
| `web_fetch` | `EXTERNAL_INGESTION` | `UNTRUSTED_WEB` |
| `database_query` | `PRIVATE_ACCESS` | `CUSTOMER_DATA` (value-detected) |
| `send_email` | `EXTERNAL_ACTION` | outbound arg matches the tracked customer record |

## The safe control

The same fixture also proves the false-positive control: customer data sent to
`acme.internal` (a configured internal domain) is **allowed**.
