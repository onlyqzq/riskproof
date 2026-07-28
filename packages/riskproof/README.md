# riskproof

Deterministic execution control and audit proofs for MCP/AI Agent toolchains.
RiskProof validates email, HTTP, shell, file, database, and browser requests,
tracks bounded provenance and cross-tool capability transitions, and decides
before a real integration executes them.

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
21 per-call rules, complete tool-descriptor identity commitments, an optional
host-held task contract, an EIT/PAT/NAT toolchain guard, configurable
default-deny, and OPA/Rego policies. It does not execute email, HTTP, or shell
actions.

## CLI

```bash
riskproof --help
riskproof check event.json --pretty
riskproof serve --host 127.0.0.1 --port 9090
riskproof proxy --no-interactive --upstream <mcp-server-command...>
riskproof proxy --task-contract trusted-task.json --no-interactive --upstream <mcp-server-command...>
riskproof check event.json --opa-policy compiled-policy.wasm
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
It builds a bounded in-memory index from MCP resources, prompts, and tool
results; later argument values receive semantic provenance IDs by exact
substring matching, with `agent_generated` used for unmatched values.

The complete tool descriptor is canonically hashed before it reaches the
planning model. Name collisions, pinned-manifest mismatches, late additions,
and descriptor rug pulls are sticky-quarantined. Default TOFU detects
continuity only; it does not authenticate the first server or prove backend
behavior. `TaskAuthorizationGuard` can additionally bind an exact tool,
descriptor digest, allowed host provenance, expiry, and global/per-tool call
budgets. Its `objectiveDigest` is a task binding, not semantic proof of task
alignment.

Successful calls are also recorded in a bounded metadata-only sequence monitor.
It requires review for external-ingestion → private-access transitions, raises a
complete ingestion → private-access → disclosure path to critical, and blocks a
final outbound call when its arguments carry private-result provenance or
sensitive taints. Raw tool results are not stored in the sequence history.

The CLI state covers one proxy process. Cross-server deployments need a shared
host/session ledger; custom hosts can share the exported `ToolchainGuard`.
Upstream processes receive a minimal environment allowlist, so credentials must
be passed explicitly. Do not expose a raw upstream server beside its wrapper.

Unsigned `_meta.riskproof_user_decision` is rejected by default. The
`--allow-client-decisions` switch is only for an explicitly trusted, local MVP
process chain and is not a signed human-approval token.

## Proof data

Detected secrets, API keys, PII, customer data, source code, financial data,
and patient data are redacted from stored proofs and user-facing output. Proof
directories/files use `0700`/`0600` on POSIX filesystems. `ProofStore` can
encrypt new records with AES-256-GCM, sign them with HMAC-SHA-256, read old keys
during rotation, require protected envelopes, and enforce age/count retention.
Operators still need external key management, backup/replication, capacity
monitoring, and OS access control.

## Development

From the monorepo root:

```bash
npm ci
npm run verify
npm run test:opa # requires the OPA CLI; compiles and executes the example Rego WASM
npm run test:coverage -w packages/riskproof
```

See the main repository `README.md`, `SECURITY.md`, `docs/threat-model.md`,
`docs/research-foundations.md`, `docs/docker.md`, and
`docs/publish-checklist.md` for architecture, evidence boundaries, deployment,
and rollback guidance.

License: Apache-2.0.
