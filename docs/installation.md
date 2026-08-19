# Installation

RiskProof is a DeepSeek Harness plugin. Pick the install path that matches how you run DSH.

## From npm (recommended)

Prebuilt and fastest — no build step, no `allowBuilds` approval:

```bash
dsh plugin --profile <profile> add dsh-riskproof
```

Then add the row to the profile's `cordis.patch.yml` (or merge it into an existing one):

```yaml
- insert:
    - id: riskproof
      name: dsh-riskproof
```

Verify it is composed:

```bash
dsh --profile <profile> --dump-config
```

You should see a `riskproof` row from the `dsh-riskproof` package.

## From a prebuilt GitHub Release tarball

Each release publishes a signed tarball (with provenance). Useful for pinning an
exact version without going through npm:

```bash
dsh plugin --profile <profile> add \
  https://github.com/onlyqzq/riskproof/releases/download/v0.1.0/dsh-riskproof-0.1.0.tgz
```

## From source

```bash
git clone https://github.com/onlyqzq/riskproof
cd riskproof
npm ci
npm run build
dsh plugin --profile <profile> add ./   # installs the local package
```

## Confirm it is active

RiskProof is a passive layer over the Tool Runtime — it registers no tools. To
see it decide in a real pipeline without a model or profile, run the bundled
demo:

```bash
npm run demo
```

It boots a real Cordis context and the real `@deepseek-ai/dsh-tools`
ToolRuntime, registers three mock tools, and drives the
`web → database → email` attack chain to a `deny`.
