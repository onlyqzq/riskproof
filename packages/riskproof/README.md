# riskproof

Deterministic risk evaluation and approval proofs for AI Agent tool calls.
RiskProof validates and evaluates `send_email`, `http_request`, and `shell_exec`
requests before a real integration executes them.

Requires Node.js 22 or newer.

## API

```ts
import { evaluate } from "riskproof";

const result = evaluate({
  tool: "http_request",
  args: {
    url: "https://external.example/upload",
    body: "customer export",
  },
  provenance: {
    body: ["internal_crm"],
  },
  taints: {
    body: ["CUSTOMER_DATA"],
  },
});

console.log(result.action); // ask_approval
console.log(result.proof.proofId);
```

Unknown JSON-facing tools and malformed arguments fail closed. The engine has
17 built-in match rules plus a configurable default-deny fallback. It does not
execute email, HTTP, or shell actions.

## CLI

```bash
riskproof --help
riskproof check event.json --pretty
riskproof serve --host 127.0.0.1 --port 9090
riskproof proxy --no-interactive --upstream <mcp-server-command...>
riskproof validate-config riskproof.json
```

The HTTP server binds to localhost, disables CORS, rejects caller-supplied
security context, and writes redacted private proofs by default. It has no
built-in authentication or rate limiter; do not expose it directly to the
public internet.

Use `/health` for liveness and `/ready` for liveness plus proof-store
writability.

## Configuration

```json
{
  "version": "1",
  "internalDomains": ["company.example"],
  "options": { "defaultDecision": "deny" },
  "rules": [
    {
      "id": "block_prod_deploy",
      "description": "Block direct production deploy commands",
      "tool": "shell_exec",
      "field": "command",
      "pattern": "deploy.*production",
      "decision": "deny",
      "risk": "critical",
      "consequence": "An unreviewed production change could cause an outage"
    }
  ]
}
```

Custom patterns use the bundled linear-time `re2js` runtime. JSON needs no
additional optional dependency. For `.yaml`/`.yml`, install the optional peer
dependency:

```bash
npm install yaml
```

Configuration version `1` rejects unknown fields, unsupported tools,
duplicate/reserved IDs, low-severity custom rules, and non-RE2 or oversized
regular expressions. Lookaround and backreferences are intentionally excluded.
The installed schema is exported as `riskproof/schema.json`; a complete config
is exported as `riskproof/example-config.json`.

## MCP approvals

The proxy removes poisoned tool definitions from model-visible `tools/list` and
retains a quarantine cache so direct calls remain blocked. It exposes a
side-effect-free `riskproof/evaluate` method for two-phase Agent approval.

Unsigned `_meta.riskproof_user_decision` is rejected by default. The
`--allow-client-decisions` switch is only for an explicitly trusted, local MVP
process chain and is not a signed human-approval token.

## Proof data

Detected secrets, API keys, PII, customer data, source code, financial data,
and patient data are redacted from stored proofs and user-facing output. Proof
directories/files use `0700`/`0600` on POSIX filesystems. Operators still need
encrypted storage, retention, backup, capacity monitoring, and access control.

## Development

From the monorepo root:

```bash
npm ci
npm run verify
npm run test:coverage -w packages/riskproof
```

See the main repository `README.md`, `SECURITY.md`, `TEST_REPORT.md`, and
`RELEASE_READINESS.md` for architecture, trust boundaries, exact validation
evidence, deployment, and rollback guidance.

License: Apache-2.0.
