# RiskProof Agent — Python SDK

Python integration for RiskProof's deterministic tool-call approval layer.
Requires Python 3.10–3.13 and patched LangGraph/LangChain 1.x dependencies.

The package provides:

- `RiskProofAgent`, which preflights all planned calls, batches approval
  requests, and then executes every allowed/approved tool at most once;
- `MCPClient`, a fail-closed, synchronized stdio JSON-RPC client;
- `RiskProofCallback` and `LangChainRiskProofHandler` for callback integration;
- explicit blocked, approval-required, transport, and protocol exceptions.

## Source setup

```bash
uv sync --frozen --extra dev
uv run ruff check src tests demo.py
uv run pytest --cov=riskproof_agent --cov-report=term-missing -q
```

Build and verify local distributions:

```bash
uv run python -m build
uv run twine check dist/*
```

## Minimal import

```python
from riskproof_agent import MCPClient, RiskProofAgent, RiskProofCallback
```

Importing the library does not load `.env`, modify provider environment
variables, or print credentials. The optional interactive `demo.py` loads
`agent/.env`; use a dedicated non-production test key.

`allow_unsigned_client_decisions=True` only works when the TypeScript proxy also
uses `--allow-client-decisions`. This is a trusted-local MVP compatibility mode,
not a signed approval protocol; leave it disabled for untrusted or remote
clients.

The current source checkout has not yet proved public PyPI publication. Follow
the root `RELEASE_READINESS.md` before advertising registry installation.

License: Apache-2.0.
