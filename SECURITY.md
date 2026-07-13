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

RiskProof is a deterministic policy and approval layer. It is not a sandbox,
authentication service, data-loss-prevention appliance, or proof that an Agent
is benign. Every real high-risk tool must be routed through the interceptor;
otherwise RiskProof cannot protect it.

The supported engine tools in `0.1.x` are `send_email`, `http_request`, and
`shell_exec`. Unknown external input is rejected by the JSON-facing validation
boundaries. The MCP adapter maps upstream business tool names conservatively and
requires approval when no trusted capability exists.

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
  environment. Pass only the minimum additional environment explicitly.
- Poisoned MCP tool definitions are removed from model-visible `tools/list`;
  the quarantine cache is retained so direct calls remain blocked.

## Proof data

Detected secrets, API keys, PII, customer data, source code, financial data,
and patient data are redacted in HTTP responses, approval cards, compact error
messages, and stored proofs. Proof directories and files are created with
`0700` and `0600` permissions where the filesystem supports POSIX modes.

Proof storage is still local JSON storage. It does not provide encryption at
rest, retention enforcement, remote replication, tamper-evident signatures, or
cross-host authorization. Operators must supply volume encryption, retention,
backup, access control, and disk-capacity monitoring appropriate to their data.

## Known limitations

- Provenance supplied to the engine is only as trustworthy as the integration
  that constructs it. The current generic MCP proxy cannot reconstruct a full
  LLM context provenance graph; ordinary upstream arguments are labeled
  `mcp_tool`, while poisoned schemas are labeled separately.
- Dangerous-shell detection is deterministic defense-in-depth, not complete
  shell parsing or isolation. Execute approved shell work in a separate sandbox
  with least privilege.
- The HTTP body limit and timeouts reduce abuse impact but do not replace an
  authenticated gateway, request-rate limits, proof quotas, or retention jobs.
- File proofs are audit records, not cryptographically signed attestations.

See `RELEASE_READINESS.md` for deployment blockers and operational controls.
