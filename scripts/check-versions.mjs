#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const rootPackage = JSON.parse(readFileSync(resolve(root, "package.json"), "utf-8"));
const npmPackage = JSON.parse(readFileSync(resolve(root, "packages/riskproof/package.json"), "utf-8"));
const pythonProject = readFileSync(resolve(root, "agent/pyproject.toml"), "utf-8");
const pythonInit = readFileSync(resolve(root, "agent/src/riskproof_agent/__init__.py"), "utf-8");
const tsVersion = readFileSync(resolve(root, "packages/riskproof/src/version.ts"), "utf-8");
const dockerfile = readFileSync(resolve(root, "Dockerfile"), "utf-8");
const changelog = readFileSync(resolve(root, "CHANGELOG.md"), "utf-8");

const expected = npmPackage.version;
const values = new Map([
  ["root package", rootPackage.version],
  ["Python project", capture(pythonProject, /^version\s*=\s*"([^"]+)"/m, "agent/pyproject.toml")],
  ["Python __version__", capture(pythonInit, /^__version__\s*=\s*"([^"]+)"/m, "agent __init__.py")],
  ["TypeScript VERSION", capture(tsVersion, /VERSION\s*=\s*"([^"]+)"/, "version.ts")],
  ["Docker label", capture(dockerfile, /image\.version="([^"]+)"/, "Dockerfile")],
]);

const mismatches = [...values].filter(([, value]) => value !== expected);
if (!changelog.includes(`## [${expected}]`)) {
  mismatches.push(["CHANGELOG heading", "missing"]);
}

const refName = process.env.GITHUB_REF_NAME;
if (refName?.startsWith("v") && refName !== `v${expected}`) {
  mismatches.push(["Git tag", refName]);
}

if (mismatches.length > 0) {
  for (const [name, value] of mismatches) {
    process.stderr.write(`Version mismatch: ${name}=${value}; expected ${expected}\n`);
  }
  process.exit(1);
}

process.stdout.write(`All release versions match ${expected}\n`);

function capture(text, pattern, source) {
  const match = text.match(pattern);
  if (!match) throw new Error(`Could not find version in ${source}`);
  return match[1];
}
