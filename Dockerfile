# ============================================================================
# RiskProof — Multi-stage Docker Build
# ============================================================================
# Produces a minimal production image with Node.js and the small re2js runtime.
# Runs as non-root.
#
# Usage:
#   docker build -t riskproof:latest .
#
#   # HTTP server (default)
#   docker run -p 9090:9090 riskproof:latest
#
#   # MCP proxy mode
#   docker run -p 9090:9090 riskproof:latest proxy --upstream <cmd...>
#
#   # One-shot check
#   docker run -v $(pwd):/data riskproof:latest check /data/event.json
#
#   # Demo (generate proofs)
#   docker run -v $(pwd)/proofs:/proofs riskproof:latest demo --proof-dir /proofs
# ============================================================================

# ── Stage 1: Build TypeScript ──────────────────────────────────────────────
FROM node:22.20.0-alpine3.22 AS builder

WORKDIR /app

# The project uses npm workspaces. Copy root package files first so npm ci
# can resolve the workspace and install all dependencies (hoisted).
COPY package*.json .
COPY packages/riskproof/package*.json packages/riskproof/
RUN npm ci

# Copy TypeScript sources and compile via the workspace build script.
COPY packages/riskproof/tsconfig.json packages/riskproof/
COPY packages/riskproof/src/ packages/riskproof/src/
COPY packages/riskproof/bin/ packages/riskproof/bin/
# The workspace build also runs scripts/copy-assets.mjs, which resolves the
# canonical schema and example from the repository root. Keep these explicit
# so a Docker build uses the same complete input set as a local release build.
COPY packages/riskproof/scripts/ packages/riskproof/scripts/
COPY riskproof.schema.json riskproof.example.json ./
RUN npm run build -w packages/riskproof

# Verify build output exists
RUN test -f /app/packages/riskproof/dist/cli.js || \
    (echo "ERROR: dist/cli.js not found — TypeScript build failed" && exit 1)
RUN test -f /app/packages/riskproof/dist/engine.js || \
    (echo "ERROR: dist/engine.js not found — TypeScript build failed" && exit 1)
RUN test -f /app/packages/riskproof/dist/riskproof.schema.json || \
    (echo "ERROR: dist/riskproof.schema.json not found — asset copy failed" && exit 1)

# ── Stage 2: Minimal production image ──────────────────────────────────────
FROM node:22.20.0-alpine3.22

ARG VCS_REF="unknown"
ARG BUILD_DATE="unknown"

# Metadata
LABEL org.opencontainers.image.title="RiskProof"
LABEL org.opencontainers.image.description="Risk-aware approval middleware for AI Agent tool calls"
LABEL org.opencontainers.image.url="https://github.com/qzq/riskproof"
LABEL org.opencontainers.image.source="https://github.com/qzq/riskproof"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.revision="${VCS_REF}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"

# Create non-root user (node user already exists in node:22-alpine, but
# ensure the app directory is owned by it)
WORKDIR /app
RUN apk add --no-cache tini && \
    mkdir -p /app/proofs /app/config && \
    chown -R node:node /app

# Copy only what's needed at runtime from the builder stage. re2js is the
# linear-time regex engine; yaml is included so mounted .yaml configs behave
# the same way as local installations even though it remains an optional peer.
COPY --from=builder --chown=node:node \
    /app/packages/riskproof/dist/ ./dist/
COPY --from=builder --chown=node:node \
    /app/packages/riskproof/package.json ./

# The CLI launcher (bin/riskproof.js) is a convenience wrapper that tries
# dist/cli.js first. We ship it for compatibility with npm-style invocation.
COPY --from=builder --chown=node:node \
    /app/packages/riskproof/bin/ ./bin/
COPY --from=builder --chown=node:node \
    /app/node_modules/re2js/ ./node_modules/re2js/
COPY --from=builder --chown=node:node \
    /app/node_modules/yaml/ ./node_modules/yaml/

RUN node --input-type=module -e "await import('re2js'); await import('yaml')"

# Switch to non-root user
USER node

ENV NODE_ENV=production \
    RISKPROOF_HOST=0.0.0.0 \
    RISKPROOF_PORT=9090 \
    RISKPROOF_PROOF_DIR=/app/proofs

# Health check: /ready verifies both the server and writable proof storage.
# Uses wget (included in node:22-alpine). The healthcheck is only meaningful
# in serve mode; in proxy/check/demo modes it will fail, which is expected.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:9090/ready || exit 1

# Default port for HTTP server mode
EXPOSE 9090

# ENTRYPOINT is the compiled CLI. CMD supplies default arguments for
# HTTP server mode. Override CMD at runtime for other modes:
#
#   docker run riskproof:latest proxy --upstream npx my-mcp-server
#   docker run riskproof:latest check /data/event.json --pretty
#   docker run riskproof:latest demo --proof-dir /proofs
STOPSIGNAL SIGTERM
ENTRYPOINT ["/sbin/tini", "--", "node", "dist/cli.js"]
CMD ["serve"]
