#!/usr/bin/env node
// ============================================================================
// riskproof — RiskProof CLI Launcher
// ============================================================================
// Tries the compiled CLI first (production / npm install).
// Falls back to tsx for development (monorepo / source checkout).
// ============================================================================

import { spawnSync } from "node:child_process";
import { resolve, dirname } from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgRoot = resolve(__dirname, "..");
const cliCompiled = resolve(pkgRoot, "dist", "cli.js");
const cliSource = resolve(pkgRoot, "src", "cli.ts");
const monoRootModules = resolve(__dirname, "..", "..", "..", "node_modules");

// Production: use compiled JS
if (existsSync(cliCompiled)) {
  const result = spawnSync("node", [cliCompiled, ...process.argv.slice(2)], {
    stdio: "inherit",
    cwd: process.cwd(),
  });
  process.exit(result.status ?? 1);
}

// Development: use tsx on TypeScript source
const result = spawnSync(
  "node",
  ["--import", "tsx/esm", cliSource, ...process.argv.slice(2)],
  {
    stdio: "inherit",
    cwd: process.cwd(),
    env: {
      ...process.env,
      NODE_PATH: [monoRootModules, process.env.NODE_PATH].filter(Boolean).join(":"),
    },
  },
);

process.exit(result.status ?? 1);
