#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";

const root = resolve(import.meta.dirname, "..");
const opaBinary = process.env.RISKPROOF_OPA_BIN?.trim() || "opa";
const policySource = resolve(root, "examples/policies/production-deploy.rego");
const temporaryRoot = mkdtempSync(resolve(tmpdir(), "riskproof-opa-wasm-"));
const bundlePath = resolve(temporaryRoot, "bundle.tar.gz");
const wasmPath = resolve(temporaryRoot, "policy.wasm");

try {
  const version = runOpa(["version"]);
  runOpa(["check", "--strict", policySource]);
  runOpa([
    "build",
    "-t", "wasm",
    "-e", "riskproof/decision",
    "-o", bundlePath,
    policySource,
  ]);
  execFileSync("tar", ["-xzf", bundlePath, "-C", temporaryRoot], {
    encoding: "utf-8",
    maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });

  const { OpaPolicyEngine, evaluateWithOpa } = await import(
    "../packages/riskproof/dist/opa-policy.js"
  );
  const policy = await OpaPolicyEngine.loadFile(wasmPath, {
    id: "production_guard",
    entrypoint: "riskproof/decision",
    failureMode: "throw",
  });
  const referenceTime = "2026-07-19T00:00:00.000Z";
  const capability = { tool: "shell_exec" };
  const matched = evaluateWithOpa({
    tool: "shell_exec",
    args: { command: "deploy production" },
    capability,
    options: { referenceTime },
  }, [policy]);
  const expectedPolicy = "opa_production_guard_production_deploy_requires_approval";

  assert(matched.action === "ask_approval", `expected ask_approval, got ${matched.action}`);
  assert(matched.decision === "require_approval", `expected require_approval, got ${matched.decision}`);
  assert(matched.riskLevel === "high", `expected high risk, got ${matched.riskLevel}`);
  assert(
    matched.matchedPolicies.some(({ id }) => id === expectedPolicy),
    `compiled Rego did not produce ${expectedPolicy}`,
  );
  assert(
    isDeepStrictEqual(matched.proof.matchedRules, matched.matchedPolicies),
    "proof matchedRules diverged from the final policy list",
  );
  assert(
    isDeepStrictEqual(
      matched.proof.evidence,
      matched.matchedPolicies.flatMap(({ evidence }) => evidence),
    ),
    "proof evidence diverged from the final policy list",
  );

  const unmatched = evaluateWithOpa({
    tool: "shell_exec",
    args: { command: "deploy staging" },
    capability,
    options: { referenceTime },
  }, [policy]);
  assert(unmatched.action === "allow", `expected unmatched policy to allow, got ${unmatched.action}`);
  assert(
    !unmatched.matchedPolicies.some(({ id }) => id.startsWith("opa_production_guard_")),
    "compiled Rego unexpectedly matched a non-production deployment",
  );

  const firstVersionLine = version.split(/\r?\n/u).find((line) => line.startsWith("Version:")) ?? "Version: unknown";
  process.stdout.write([
    `OPA/Rego WASM integration passed (${firstVersionLine})`,
    `Matched policy: ${expectedPolicy}`,
    "Non-matching policy path: allow",
    "Proof consistency: verified",
    "",
  ].join("\n"));
} catch (error) {
  if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
    throw new Error(
      `OPA integration requires '${opaBinary}' and a POSIX tar implementation; install OPA or set RISKPROOF_OPA_BIN`,
      { cause: error },
    );
  }
  throw error;
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}

function runOpa(args) {
  return execFileSync(opaBinary, args, {
    encoding: "utf-8",
    maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
