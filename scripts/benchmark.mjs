#!/usr/bin/env node

import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { evaluate, ProofStore, startHttpServer } from "../packages/riskproof/dist/index.js";

const engineIterations = positiveInteger(process.env.RISKPROOF_BENCH_ENGINE, 10_000);
const proofIterations = positiveInteger(process.env.RISKPROOF_BENCH_PROOFS, 1_000);
const httpIterations = positiveInteger(process.env.RISKPROOF_BENCH_HTTP, 500);
const httpConcurrency = positiveInteger(process.env.RISKPROOF_BENCH_CONCURRENCY, 20);
const temporaryRoot = mkdtempSync(resolve(tmpdir(), "riskproof-benchmark-"));

const safeInput = {
  tool: "http_request",
  args: { url: "https://api.company.example/status", method: "GET" },
  options: { internalDomains: ["company.example"] },
};

try {
  for (let index = 0; index < 1_000; index += 1) evaluate(safeInput);

  const engineStarted = performance.now();
  for (let index = 0; index < engineIterations; index += 1) evaluate(safeInput);
  const engineMs = performance.now() - engineStarted;

  const proofStore = new ProofStore(resolve(temporaryRoot, "proofs-direct"));
  const proofOutputs = Array.from({ length: proofIterations }, () => evaluate(safeInput));
  const proofStarted = performance.now();
  for (const output of proofOutputs) proofStore.save(output);
  const proofMs = performance.now() - proofStarted;

  const server = startHttpServer({
    host: "127.0.0.1",
    port: 0,
    proofDir: resolve(temporaryRoot, "proofs-http"),
    logger: () => {},
  });
  if (!server.listening) await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("HTTP benchmark did not bind TCP");
  const endpoint = `http://127.0.0.1:${address.port}/evaluate`;
  const requestBody = JSON.stringify({
    tool: "http_request",
    args: { url: "https://api.company.example/status", method: "GET" },
  });
  const request = async () => {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: requestBody,
    });
    if (!response.ok) throw new Error(`HTTP benchmark failed with ${response.status}`);
    await response.arrayBuffer();
  };

  const sequentialLatencies = [];
  for (let index = 0; index < httpIterations; index += 1) {
    const started = performance.now();
    await request();
    sequentialLatencies.push(performance.now() - started);
  }

  const concurrentStarted = performance.now();
  for (let offset = 0; offset < httpIterations; offset += httpConcurrency) {
    const count = Math.min(httpConcurrency, httpIterations - offset);
    await Promise.all(Array.from({ length: count }, request));
  }
  const concurrentMs = performance.now() - concurrentStarted;

  await new Promise((resolveClose, rejectClose) => {
    server.close((error) => error ? rejectClose(error) : resolveClose());
  });

  const sortedLatencies = [...sequentialLatencies].sort((a, b) => a - b);
  const report = {
    runtime: {
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
    },
    engine: metric(engineIterations, engineMs),
    proofStore: metric(proofIterations, proofMs),
    httpSequential: {
      ...metric(httpIterations, sequentialLatencies.reduce((sum, value) => sum + value, 0)),
      p50Ms: percentile(sortedLatencies, 0.5),
      p95Ms: percentile(sortedLatencies, 0.95),
    },
    httpConcurrent: {
      ...metric(httpIterations, concurrentMs),
      concurrency: httpConcurrency,
    },
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}

function metric(iterations, elapsedMs) {
  return {
    iterations,
    elapsedMs: round(elapsedMs),
    averageMs: round(elapsedMs / iterations),
    operationsPerSecond: round(iterations / (elapsedMs / 1_000)),
  };
}

function percentile(sortedValues, fraction) {
  const index = Math.min(sortedValues.length - 1, Math.floor(sortedValues.length * fraction));
  return round(sortedValues[index]);
}

function round(value) {
  return Number(value.toFixed(3));
}

function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`Benchmark iteration values must be positive integers, got '${value}'`);
  }
  return parsed;
}
