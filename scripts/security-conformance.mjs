#!/usr/bin/env node

import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluate, parseEngineInput } from "../packages/riskproof/dist/index.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = resolve(ROOT, "test-workspace/test-cases/scenarios");
const format = parseFormat(process.argv.slice(2));

const cases = readdirSync(CORPUS)
  .filter((name) => name.endsWith(".json"))
  .sort()
  .map((name) => loadCase(name));

const results = cases.map((testCase) => runCase(testCase));
const report = buildReport(results);

process.stdout.write(format === "json"
  ? `${JSON.stringify(report, null, 2)}\n`
  : renderMarkdown(report));

if (results.some(({ conforms }) => !conforms)) process.exitCode = 1;

function parseFormat(args) {
  if (args.length === 0) return "markdown";
  if (args.length === 2 && args[0] === "--format" && ["json", "markdown"].includes(args[1])) {
    return args[1];
  }
  throw new Error("Usage: security-conformance.mjs [--format json|markdown]");
}

function loadCase(name) {
  const raw = JSON.parse(readFileSync(resolve(CORPUS, name), "utf-8"));
  if (!raw || typeof raw !== "object" || Array.isArray(raw) || typeof raw.scenario !== "string") {
    throw new TypeError(`Invalid conformance case: ${name}`);
  }
  const expectedAction = raw.scenario.includes("BLOCK")
    ? "block"
    : raw.scenario.includes("ASK_APPROVAL")
      ? "ask_approval"
      : raw.scenario.includes("ALLOW")
        ? "allow"
        : undefined;
  if (!expectedAction) throw new TypeError(`Scenario has no explicit expected action: ${name}`);
  const { scenario, ...event } = raw;
  return {
    id: name.replace(/\.json$/u, ""),
    scenario,
    expectedAction,
    class: expectedAction === "allow" ? "benign" : "attack",
    event,
  };
}

function runCase(testCase) {
  const output = evaluate(parseEngineInput(testCase.event));
  const policyIds = output.matchedPolicies.map(({ id }) => id);
  const proofPolicyIds = output.proof.matchedRules.map(({ id }) => id);
  const argumentsList = Object.values(output.arguments);
  const attributedArguments = argumentsList.filter(({ source }) =>
    source.some((value) => value !== "agent_generated")).length;
  const proofConsistent = output.proof.decision === output.decision &&
    output.proof.riskLevel === output.riskLevel &&
    JSON.stringify(proofPolicyIds) === JSON.stringify(policyIds) &&
    (output.action === "allow" || output.matchedPolicies.every(({ evidence }) => evidence.length > 0));
  return {
    id: testCase.id,
    scenario: testCase.scenario,
    class: testCase.class,
    expectedAction: testCase.expectedAction,
    actualAction: output.action,
    conforms: output.action === testCase.expectedAction,
    riskLevel: output.riskLevel,
    policyIds,
    proofConsistent,
    attributedArguments,
    totalArguments: argumentsList.length,
  };
}

function buildReport(results) {
  const attacks = results.filter(({ class: kind }) => kind === "attack");
  const benign = results.filter(({ class: kind }) => kind === "benign");
  const totalArguments = sum(results.map(({ totalArguments: count }) => count));
  const attributedArguments = sum(results.map(({ attributedArguments: count }) => count));
  return {
    schemaVersion: "1",
    corpus: {
      id: "riskproof-local-conformance-v1",
      cases: results.length,
      attackCases: attacks.length,
      benignCases: benign.length,
      repetitionsPerCase: 1,
      execution: "deterministic local pre-dispatch evaluation",
      scope: "Regression/conformance evidence only; not ecosystem prevalence, production ASR, or a zero-error claim.",
    },
    attack: {
      validRuns: attacks.length,
      expectedBlocks: attacks.filter(({ expectedAction }) => expectedAction === "block").length,
      expectedStepUps: attacks.filter(({ expectedAction }) => expectedAction === "ask_approval").length,
      preDispatchBlocks: attacks.filter(({ actualAction }) => actualAction === "block").length,
      stepUps: attacks.filter(({ actualAction }) => actualAction === "ask_approval").length,
      escapes: attacks.filter(({ actualAction }) => actualAction === "allow").length,
      expectedDecisionConformance: ratio(attacks.filter(({ conforms }) => conforms).length, attacks.length),
    },
    benign: {
      validRuns: benign.length,
      completed: benign.filter(({ actualAction }) => actualAction === "allow").length,
      falseBlocks: benign.filter(({ actualAction }) => actualAction === "block").length,
      unnecessaryStepUps: benign.filter(({ actualAction }) => actualAction === "ask_approval").length,
      completionRate: ratio(benign.filter(({ actualAction }) => actualAction === "allow").length, benign.length),
    },
    evidence: {
      validRuns: results.length,
      internallyConsistentDecisionProofs: results.filter(({ proofConsistent }) => proofConsistent).length,
      decisionProofConsistencyRate: ratio(
        results.filter(({ proofConsistent }) => proofConsistent).length,
        results.length,
      ),
      attributedArguments,
      totalArguments,
      nonAgentProvenanceCoverage: ratio(attributedArguments, totalArguments),
      limitation: "Exact provenance coverage counts declared or deterministically mapped non-agent sources; it does not recover implicit model influence or transformed values without an explicit flow edge.",
    },
    cases: results,
  };
}

function renderMarkdown(report) {
  const attack = report.attack;
  const benign = report.benign;
  const evidence = report.evidence;
  const lines = [
    "# RiskProof fixed-denominator security conformance report",
    "",
    `Corpus: \`${report.corpus.id}\` — ${report.corpus.cases} cases ` +
      `(${report.corpus.attackCases} attack, ${report.corpus.benignCases} benign), ` +
      `${report.corpus.repetitionsPerCase} deterministic run per case.`,
    "",
    `> ${report.corpus.scope}`,
    "",
    "## Attack outcomes",
    "",
    "| Denominator | Pre-dispatch block | Step-up | Escape | Expected-decision conformance |",
    "|---:|---:|---:|---:|---:|",
    `| ${attack.validRuns} | ${attack.preDispatchBlocks} | ${attack.stepUps} | ${attack.escapes} | ${percent(attack.expectedDecisionConformance)} |`,
    "",
    "A step-up is reported separately. It is neither counted as an automatic prevention nor as an escape.",
    "",
    "## Benign outcomes",
    "",
    "| Denominator | Completed | False block | Unnecessary step-up | Completion rate |",
    "|---:|---:|---:|---:|---:|",
    `| ${benign.validRuns} | ${benign.completed} | ${benign.falseBlocks} | ${benign.unnecessaryStepUps} | ${percent(benign.completionRate)} |`,
    "",
    "## Evidence outcomes",
    "",
    "| Denominator | Internally consistent decision proofs | Proof consistency | Attributed arguments | Non-agent provenance coverage |",
    "|---:|---:|---:|---:|---:|",
    `| ${evidence.validRuns} | ${evidence.internallyConsistentDecisionProofs} | ${percent(evidence.decisionProofConsistencyRate)} | ${evidence.attributedArguments}/${evidence.totalArguments} | ${percent(evidence.nonAgentProvenanceCoverage)} |`,
    "",
    `Limitation: ${evidence.limitation}`,
    "",
    "## Per-case results",
    "",
    "| Case | Class | Expected | Actual | Conforms | Policies |",
    "|---|---|---|---|---|---|",
    ...report.cases.map((item) =>
      `| ${escapeCell(item.id)} | ${item.class} | ${item.expectedAction} | ${item.actualAction} | ${item.conforms ? "yes" : "no"} | ${escapeCell(item.policyIds.join(", ") || "none")} |`),
    "",
  ];
  return `${lines.join("\n")}\n`;
}

function ratio(numerator, denominator) {
  return denominator === 0 ? null : Number((numerator / denominator).toFixed(6));
}

function percent(value) {
  return value === null ? "n/a" : `${(value * 100).toFixed(1)}%`;
}

function sum(values) {
  return values.reduce((total, value) => total + value, 0);
}

function escapeCell(value) {
  return String(value).replaceAll("|", "\\|").replaceAll("\n", " ");
}
