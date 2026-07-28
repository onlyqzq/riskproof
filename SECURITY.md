# Security Policy

## Supported versions

RiskProof is currently an alpha project. Security fixes are prepared for the
latest `0.1.x` source and, after the first release, the latest published
`0.1.x` artifact. Older snapshots are not supported.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, personal
data, or proof files. Use the repository's private **Security → Report a
vulnerability** channel after private vulnerability reporting has been enabled.
Enabling and testing that channel is a release-owner requirement before public
distribution; the current checkout does not contain a private contact address
that can safely be invented here.

Include:

1. the affected commit or version;
2. a minimal reproduction using synthetic data;
3. expected and actual decisions;
4. likely impact and required trust assumptions; and
5. any suggested mitigation.

## Security model

RiskProof is a deterministic enforcement and evidence layer. It is not a sandbox,
authentication service, data-loss-prevention appliance, or proof that an Agent
is benign. Every real high-risk tool must be routed through the interceptor;
otherwise RiskProof cannot protect it.

The supported engine tools in `0.1.x` are `send_email`, `http_request`,
`shell_exec`, `file_read`, `file_write`, `database_query`, and
`browser_action`. Unknown external input is rejected by the JSON-facing
validation boundaries. The MCP adapter maps upstream business tool names
conservatively and requires approval when no trusted capability exists.

Within one proxy process, a bounded metadata-only toolchain guard classifies
external-ingestion, private-data-access, and external-disclosure capabilities.
It escalates suspicious transitions and blocks a complete exfiltration path when
the final arguments carry private-result provenance or sensitive taints. This is
sequence enforcement, not proof that a tool or server is benign.

Before model-visible discovery, a `ToolIdentityGuard` commits every complete
tool descriptor to a canonical SHA-256 digest and sticky-quarantines collisions,
manifest mismatches, late additions, and post-baseline changes. An optional
host-held `TaskAuthorizationGuard` binds calls to exact tool names, descriptor
digests, provenance IDs, expiry, and task/per-tool budgets. These are
deterministic continuity and structural authorization checks. TOFU is not
server-origin authentication, descriptor hashes do not attest backend behavior,
and an objective digest is not semantic proof of task alignment.

## Approval trust boundary

`params._meta.riskproof_user_decision` is an unsigned MVP compatibility field,
not cryptographic proof of a human decision. It is rejected by default by both
the TypeScript proxy and Python client. It is accepted only when an operator
explicitly enables both sides:

- proxy: `--allow-client-decisions`;
- Python: `allow_unsigned_client_decisions=True`.

Use this mode only for a single-user, local, trusted process chain where the
model cannot construct protocol-level JSON-RPC fields. Do not enable it across
a network, for a multi-tenant client, or when the MCP client itself is not
trusted. A production approval service should issue short-lived, single-use,
signed decisions bound to the proof ID, normalized tool name, argument digest,
user/session, expiry, and nonce.

## HTTP and MCP deployment

- The HTTP server has no built-in authentication or rate limiter. It binds to
  `127.0.0.1` by default and CORS is disabled by default. Keep it on localhost,
  a Unix-equivalent private boundary, or an authenticated private sidecar
  network. Never expose it directly to the public internet.
- Caller-supplied `capability`, `invariants`, and `options` are rejected over
  HTTP by default. `--trust-request-context` is only for an authenticated,
  trusted caller. Caller-controlled `options.referenceTime` is always rejected.
- The MCP proxy removes common LLM provider keys from the upstream child
  environment. More generally, it now uses a minimal launch-variable allowlist;
  cloud, registry, database, SSH-agent, and unknown parent credentials are not
  inherited. Pass only the minimum additional environment explicitly.
- Poisoned MCP tool definitions are removed from model-visible `tools/list`;
  the quarantine cache is retained so direct calls remain blocked.
- Unknown client request methods are rejected instead of forwarded. Unmatched
  upstream responses are dropped; server-initiated Sampling, Elicitation,
  Roots, and custom requests are rejected locally; advertised client
  capabilities are narrowed to the empty supported set.
- A trusted CLI task contract may be loaded with `--task-contract`. It is host
  policy, not MCP/model data. Protect the file with the same access controls as
  other authorization policy and use an operator-reviewed descriptor manifest.
- Never register the raw upstream MCP server beside its RiskProof wrapper. That
  creates an unprotected route around all policy and proof generation.
- Environment minimization does not sandbox a malicious upstream process. Run
  low-trust MCP servers with minimal/read-only mounts, a separate OS/container
  identity, resource limits, and controlled network egress.

## Proof data

Detected secrets, API keys, PII, customer data, source code, financial data,
and patient data are redacted in HTTP responses, approval cards, compact error
messages, and stored proofs. Proof directories and files are created with
`0700` and `0600` permissions where the filesystem supports POSIX modes.

Proof storage is local. New records can be protected with AES-256-GCM and an
HMAC-SHA-256 tamper-evident envelope. Strict read modes, old-key read keyrings,
age/count retention, and automatic pruning are available. Keys must come from a
secret file or key-management boundary; losing a key makes protected evidence
unreadable. HMAC proves possession of a shared secret, not public non-repudiation.
Operators must still supply remote replication, backups, OS access control,
capacity monitoring, and lifecycle management appropriate to their data.

## Known limitations

- Toolchain state is local to one stdio proxy process. Independent wrappers do
  not yet share session/task provenance, so cross-server parasitic chains can
  lose continuity. Use a common host interception point or shared trusted
  ledger before claiming cross-server coverage.
- Default tool identity is process-local TOFU. A restart loses its learned
  baseline and quarantine; it cannot authenticate the first server. Pinned
  manifests are the production-oriented mode. Each `tools/list` response is
  currently observed as a snapshot/page rather than one atomically aggregated
  multi-page manifest.
- A task contract proves that machine-checkable tool/version/source/time/budget
  constraints matched. It does not implement the ideal task/action semantic
  oracles from the research literature. CLI-only deployments cannot turn raw
  model arguments into authenticated user provenance; programmatic hosts must
  authenticate input out of band and preload a host-owned `ContextTracker`.
- The MCP proxy automatically indexes bounded resource, prompt, and tool-result
  content and reverse-maps exact argument substrings. It cannot see opaque LLM
  reasoning or infer lossy paraphrases. Integrations must declare additive
  `flows` for transformations, and explicitly supplied provenance is only as
  trustworthy as the integration that constructs it.
- Dangerous-shell detection is deterministic defense-in-depth, not complete
  shell parsing or isolation. Execute approved shell work in a separate sandbox
  with least privilege.
- The HTTP body limit and timeouts reduce abuse impact but do not replace an
  authenticated gateway, request-rate limits, or proof quotas. Built-in
  retention bounds local valid records but is not a storage-capacity guarantee.
- HMAC-protected file proofs are audit records, not publicly verifiable signed
  attestations. A compromised host or shared signing key can forge them.
- The stdio proxy now uses an explicit bidirectional method allowlist, but the
  first version blocks unsupported Sampling/Elicitation rather than providing a
  separately authorized implementation. It does not provide complete MCP
  version negotiation, remote transport authentication, OAuth validation, DNS
  rebinding protection, or every future protocol extension.
