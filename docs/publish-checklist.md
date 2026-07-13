# Publish checklist

This document prepares a release; it does not authorize publishing. The release
owner must review the diff, establish the Git/registry trust roots, and approve
the protected GitHub environments.

## One-time repository setup

- Create the canonical GitHub repository and add it as `origin`.
- Create and protect `main`; require the `CI` workflow and human review.
- Enable private vulnerability reporting and verify the reporting path in
  `SECURITY.md`.
- Confirm ownership of `riskproof` on npm, `riskproof-agent` on PyPI, and the
  target GHCR namespace. Do not rename packages during a release run.
- Configure npm trusted publishing for `.github/workflows/publish.yml` and the
  `npm` GitHub environment.
- Configure a PyPI trusted publisher for the same workflow and the `pypi`
  environment.
- Protect the `npm`, `pypi`, and `ghcr` environments with required reviewers.
- Grant the workflow only `id-token: write`/`packages: write` permissions shown
  in the checked-in workflow; do not add long-lived registry tokens unless a
  documented emergency procedure requires them.

The current workspace has no initial commit or remote, so all items above are
manual blockers for the first release.

## Release-candidate verification

From a clean checkout on Node 22+:

```bash
npm ci
npm run check:versions
npm run lint
npm run build
npm run test:all
npm run test:coverage -w packages/riskproof
npm audit --audit-level=high
npm ls --all
```

Python:

```bash
cd agent
uv sync --frozen --extra dev
uv run ruff check src tests demo.py
uv run pytest --cov=riskproof_agent --cov-report=term-missing -q
uv run python -m compileall -q src tests demo.py
uv run pip-audit
uv pip check
rm -rf dist
uv run python -m build
uv run twine check dist/*
```

Build both npm and Python artifacts, then install the npm tarball, Python wheel,
and Python sdist independently into empty environments. Imports must produce no
unexpected stdout, public versions must match, and package contents must include
LICENSE and typing metadata without demo, credentials, legacy shims, or mock
servers.

Docker:

```bash
docker compose config --quiet
docker compose -f docker-compose.sidecar.yml config --quiet
docker build -t riskproof:release-candidate .
```

Run the `/ready`, dangerous-call block, proof-permission, and persistent-volume
restart smoke tests from `docs/docker.md`.

## Version gate

The following must all equal the intended semantic version:

- root `package.json`;
- `packages/riskproof/package.json`;
- `packages/riskproof/src/version.ts`;
- `agent/pyproject.toml`;
- `agent/src/riskproof_agent/__init__.py`;
- Docker OCI version label;
- `CHANGELOG.md` release heading;
- Git tag `v<version>`.

`npm run check:versions` enforces this and also checks `GITHUB_REF_NAME` in the
tag workflow.

## Review before tagging

- All P0/P1 code blockers are resolved; any accepted lower risk has an owner and
  due date.
- No `.env`, `.npmrc`, `.pypirc`, private key, token, proof, coverage output,
  build directory, or credential file is tracked.
- README registry commands match actual published availability.
- The release commit has passed CI on the protected branch.
- The release owner records the previous image/config/proof backup and the exact
  rollback decision maker.

## Tag and automated publication

After human approval:

```bash
git tag -s v0.1.0 -m "RiskProof v0.1.0"
git push origin v0.1.0
```

The prepared `Publish` workflow:

1. verifies the tag/version, Node suite, Python suite, audits, packages, and
   Docker build;
2. uploads immutable npm/Python workflow artifacts;
3. publishes the tested npm tarball with OIDC and provenance;
4. publishes the tested Python wheel/sdist with PyPI OIDC attestations;
5. publishes GHCR version and `latest` tags with SBOM/provenance;
6. creates the GitHub Release only after all registries succeed.

The three publishing jobs are intentionally sequenced to avoid simultaneous
partial publication. Registry publication itself is immutable and cannot be
made transactionally atomic across npm, PyPI, and GHCR.

## Post-publication verification

Use new empty directories and environments; do not reuse the development
checkout:

```bash
npm view riskproof@0.1.0 version dist.integrity
npm install riskproof@0.1.0
npx riskproof --help
```

```bash
python -m venv /tmp/riskproof-pypi-verify
/tmp/riskproof-pypi-verify/bin/pip install riskproof-agent==0.1.0
/tmp/riskproof-pypi-verify/bin/python -c \
  'import riskproof_agent; assert riskproof_agent.__version__ == "0.1.0"'
```

```bash
docker pull ghcr.io/qzq/riskproof:0.1.0
docker inspect ghcr.io/qzq/riskproof:0.1.0 --format '{{json .RepoDigests}}'
```

Verify npm/PyPI provenance or attestations in their registry UIs, verify the
GHCR digest matches the release record, then run the documented HTTP and proof
persistence smoke tests against that immutable digest.

## Partial-release recovery

If a registry publish succeeds and a later job fails:

1. stop; do not overwrite or delete an immutable package version;
2. record which exact npm/PyPI/GHCR artifacts and digests exist;
3. mark the GitHub release as incomplete; do not move `latest` manually;
4. fix the workflow on `main` and run the complete verification again;
5. if the already-published artifact is correct, publish the missing artifacts
   from the exact same source/tag after human approval;
6. if the published artifact is defective, deprecate/yank it according to the
   registry policy, publish a new patch version, and document the incident;
7. never reuse the same semantic version for different bytes.

npm unpublish and PyPI deletion have ecosystem and security consequences; they
require explicit release-owner/security approval and are not normal rollback.

## Deployment rollback

Publishing is not production deployment. Deployment must reference an immutable
image digest, preserve the proof volume, and follow `RELEASE_READINESS.md` and
`docs/docker.md`. Roll back to the prior image and configuration; do not delete
audit data or perform an irreversible database operation (there is no database
migration in `0.1.0`).
