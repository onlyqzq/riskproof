# Provenance & taint

## Provenance vs taint

- **Provenance** answers *where did this data come from* — the id of a tracked tool result.
- **Taint** answers *what security attribute does this data carry* — a label such as `CUSTOMER_DATA` or `UNTRUSTED_WEB`.

They are tracked independently and combined at decision time.

## ContextTracker

A per-session, bounded, in-memory index of successful tool results. Each entry keeps:

- `id` (e.g. `customer_data_3`)
- `kind` (e.g. `untrusted_web`, `customer_data`)
- `label` (the tool name)
- `taints` (kind-based + declared)
- `contentDigest` (SHA-256 of the searchable text)
- `byteCount` and `sequence`

Raw content is **never** exposed by the public API and never persisted. Only the bounded searchable text is held internally for matching.

### Bounds

| Limit | Default |
| ----- | ------- |
| `maxEntries` | 256 |
| `maxEntryBytes` | 256 KiB |
| `maxTotalBytes` | 2 MiB |
| `minMatchLength` | 4 |

All configurable via [configuration.md](configuration.md).

## ProvenanceMapper

For each scalar leaf, the mapper finds tracked entries that contain the argument, or a sufficiently long tracked result contained by a later wrapper string. Exact matching still supports short identifiers; reverse matching requires at least 12 characters to avoid common values such as `done` causing false provenance. Matched entry ids become the leaf's provenance; matched entry taints become its initial taints. Unmatched leaves are labeled `agent_generated`.

Nested objects and arrays are flattened into collision-resistant paths such as `message.body` and `recipients[0]`. The same paths are used by provenance, taint, policy evidence, and proofs, so a sensitive value cannot evade analysis merely by moving below the root schema level.

## Taint inference

Taint is produced three ways, additively:

1. **Kind-based** — a `web_fetch` result carries `UNTRUSTED_WEB`; a customer-record result carries `CUSTOMER_DATA`.
2. **Value detection** — deterministic patterns for secrets (`sk-…`, `api_key=…`), PII (email, phone), financial data, patient data, customer ids (`CUST-8842`), source code, and internal documents.
3. **Source inference** — a provenance id is inspected for known source keywords.

## Honest limits

The mapper recovers data that is *copied* as an exact or bounded substring. It does **not** track:

- summarization, translation, or paraphrase
- Base64 / compression / encryption
- recombination that drops every tracked substring
- reasoning inside the model that never appears in an argument

RiskProof tracks supported observable data flows across DSH tool calls — not all information flows.
