# Development

## Prerequisites

- Node.js >= 22
- npm >= 10

## Setup

```bash
npm install
```

## Commands

| Command | Purpose |
| ------- | ------- |
| `npm run build` | compile `src/` → `dist/` (tsc) |
| `npm test` | run the full Vitest suite |
| `npm run typecheck` | strict typecheck of `src/` |
| `npm run typecheck:test` | strict typecheck of `src/` + `tests/` |
| `npm run verify` | typecheck + build + test |
| `npm run pack:smoke` | build + `npm pack --dry-run` |

## Layout

- `src/core/` — pure deterministic engine; must stay DSH-free.
- `src/dsh/` — the only code importing DSH types.
- `tests/unit/` — pure unit tests.
- `tests/security/` — attack-chain regression fixtures.
- `tests/integration/` — real Cordis plugin lifecycle tests.

## Adding a rule

1. Add the rule to `src/core/engine.ts` (stable `id`, `reason`, `evidence`).
2. Add test vectors to `tests/unit/engine.test.ts`.
3. If it changes the threat model, update `docs/security-model.md`.

## Packaging a local tarball

```bash
npm run build
npm pack
```

Then install into a fresh profile:

```bash
DSH_HOME=/tmp/dsh-riskproof-smoke dsh plugin --profile test add ./dsh-riskproof-0.1.0.tgz
DSH_HOME=/tmp/dsh-riskproof-smoke dsh --profile test --dump-config
```

See `tests/` and `.github/workflows/ci.yml` for the automated equivalents.
