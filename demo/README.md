# Local demo

`run-attack-chain.mjs` boots a **real** Cordis context and the **real**
`@deepseek-ai/dsh-tools` ToolRuntime, registers three mock tools, loads
RiskProof in `enforce` mode, and drives three real tool executions through
`ctx.tools.execute()`.

No model, no API key, no DSH profile, no restart.

## Run

```bash
npm run demo
# or
npm run build && node demo/run-attack-chain.mjs
```

## What you should see

```text
[1/3] demo_web_fetch    → ✓ allowed          (EXTERNAL_INGESTION)
[2/3] demo_db_query     → ✓ allowed (asked)  (PRIVATE_ACCESS; ask auto-approved)
[3/3] demo_send_email   → ✗ DENIED           (EXTERNAL_ACTION carrying CUSTOMER_DATA)
```

The third call prints `✗ DENIED — tool body did NOT run`: the mock email tool's
body prints a `side effect!` line only when it actually executes, so the absence
of that line is the proof that the side effect was blocked. The structured proof
for the `deny` decision is printed at the end — it never contains raw arguments,
results, or credentials.

## What each stage demonstrates

| Call | Capability | RiskProof behavior |
| ---- | ---------- | ------------------ |
| `demo_web_fetch` | `EXTERNAL_INGESTION` | allowed, result tagged `UNTRUSTED_WEB` |
| `demo_db_query` | `PRIVATE_ACCESS` | `ask` (untrusted → private), then executes |
| `demo_send_email` | `EXTERNAL_ACTION` | `deny` — ingestion + private access + sensitive data + external action |
