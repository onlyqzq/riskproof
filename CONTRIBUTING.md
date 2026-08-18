# Contributing to RiskProof

Thanks for contributing! RiskProof is a security plugin — small, focused, well-tested changes are the most valuable.

## Ways to contribute

- **False-positive reports** — the most valuable kind of issue for a security plugin.
- **Tool capability mappings** — teach the classifier about a tool it mis-classifies.
- **Policy rules** — new deterministic rules with test vectors.
- **Test fixtures** — new attack-chain or safe-flow scenarios.
- **DSH integrations** — fixes for how RiskProof interacts with the DSH pipeline.

## Ground rules

- Security decisions must stay **deterministic**. No LLM judges or classifiers in the decision path.
- **Tests are required.** Every rule and classifier change needs a unit or regression test.
- **Privacy first.** Proofs must never persist raw arguments, results, or credentials.
- **Fail closed, monotonic.** RiskProof must never turn another plugin's `deny` into an `allow`.

## Development setup

```bash
npm install
npm run verify      # lint + build + test
```

The test matrix is plain Vitest:

```bash
npm test                          # unit + integration + security regressions
npm run typecheck                 # strict TS, no emit
```

## Adding a tool capability mapping

1. Reproduce the mis-classification in [tests/unit/classifier.test.ts](tests/unit/classifier.test.ts).
2. If it is a general pattern, add it to `src/classification/classifier.ts`.
3. If it is vendor-specific, document it as a `classification.overrides` entry in [docs/configuration.md](docs/configuration.md) instead of hard-coding it.

## Adding a rule

1. Add the rule to `src/core/engine.ts` with a stable `id`, `reason`, and `evidence`.
2. Add test vectors to [tests/unit/engine.test.ts](tests/unit/engine.test.ts).
3. Update [docs/security-model.md](docs/security-model.md) if the rule changes the threat model.

## Reporting a false positive

Open an issue using the **False positive** template and include the tool sequence and the arguments that were wrongly blocked. A minimal, redacted reproduction gets the fastest response.

## Code of conduct

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
