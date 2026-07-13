# Contributing to RiskProof

Thanks for your interest in contributing! RiskProof is a security middleware — we take
code quality and safety seriously.

## Before You Start

1. **Read the vision**: [`docs/IDEA.md`](docs/IDEA.md) explains what RiskProof is and isn't
2. **Read the dev guide**: [`CLAUDE.md`](CLAUDE.md) has engineering rules
3. **Check existing issues**: Avoid duplicating work

## Development Setup

```bash
git clone https://github.com/qzq/riskproof.git
cd riskproof

# TypeScript core and integration tests
npm ci
npm run verify

# Python agent SDK
cd agent
uv sync --frozen --extra dev
uv run pytest --cov=riskproof_agent --cov-report=term-missing -q
```

## Project Structure

```
riskproof/
├── packages/riskproof/     # TypeScript core: engine, proxy, CLI (npm: riskproof)
│   ├── src/                #   types, engine, explainer, proxy-server, http-server, CLI
│   └── tests/              #   vitest unit tests
├── agent/                  # Python SDK: LangGraph agent (pip: riskproof-agent)
│   ├── src/riskproof_agent/ #  pip-installable package
│   └── demo.py             #  interactive demo runner
└── test-workspace/         # integration test scenarios and mock MCP servers
```

## How to Contribute

### Adding a Security Rule

1. Add your rule to `packages/riskproof/src/engine.ts` following existing patterns
2. Add a description entry in `packages/riskproof/src/explainer.ts` (`RULE_DB`)
3. Add test fixtures in `packages/riskproof/src/fixtures.ts`
4. Add unit tests in `packages/riskproof/tests/engine.test.ts`
5. Run `npm run verify` — all checks must pass

### Adding an Integration Mode

New integration modes (e.g., Fastify middleware, AWS Lambda handler) should:
- Live in their own file under `packages/riskproof/src/`
- Be exported from `packages/riskproof/src/index.ts`
- Include usage examples in the README

### Fixing Bugs

1. Open an issue describing the bug
2. Write a failing test that reproduces it
3. Fix the bug
4. Verify all tests pass: `npm run verify`
5. Submit a PR

## Code Standards

- **TypeScript**: Use explicit types, avoid `any`, prefer pure functions
- **Python**: Type hints on all public APIs, PEP 8
- **Security rules**: Must be deterministic — no LLM-based security decisions
- **Tests**: Every rule must have at least one passing and one blocking test case

## Pull Request Process

1. Branch from `main`
2. Make focused, small changes
3. Include tests
4. Update CHANGELOG.md
5. Ensure `npm run verify` and the Python suite pass
6. Submit PR with a clear description of what and why

### PR Title Format

```
type: short description
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `security`, `chore`

Examples:
- `feat: add pattern-based custom rule support`
- `fix: handle empty provenance map in engine`
- `security: add HMAC signing to approval tokens`
- `docs: add deployment guide for Docker`

## Security Contributions

If your contribution relates to security (new rule, vulnerability fix, etc.):
- Mark the PR with the `security` label
- Do NOT include exploit code in test fixtures without prior discussion
- Follow `SECURITY.md` and use private vulnerability reporting; do not put exploit details in a public PR

## Getting Help

Open a [GitHub Discussion](https://github.com/qzq/riskproof/discussions) for questions,
or an [Issue](https://github.com/qzq/riskproof/issues) for bugs and feature requests.
