import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  MCP_MAX_LINE_BYTES,
  MCP_MAX_PENDING_REQUESTS,
  MCP_SHUTDOWN_GRACE_MS,
  McpProxyServer,
} from "../src/proxy-server.js";

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number;
  result?: unknown;
  error?: { code: number; message: string };
}

interface TestPendingRequest {
  resolve: (response: JsonRpcResponse) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../..");
const CLI = resolve(ROOT, "packages/riskproof/src/cli.ts");
const children: ChildProcessWithoutNullStreams[] = [];
const tempDirs: string[] = [];

function spawnProxy(
  upstreamCode: string,
  options: { interactive?: boolean; detached?: boolean } = {},
): ChildProcessWithoutNullStreams {
  const proofDir = mkdtempSync(resolve(tmpdir(), "riskproof-proxy-lifecycle-"));
  tempDirs.push(proofDir);
  const child = spawn(
    process.execPath,
    [
      "--import", "tsx/esm", CLI, "proxy",
      ...(options.interactive ? [] : ["--no-interactive"]),
      "--proof-dir", proofDir,
      "--upstream", process.execPath, "-e", upstreamCode,
    ],
    { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"], detached: options.detached },
  );
  children.push(child);
  return child;
}

function waitForResponse(child: ChildProcessWithoutNullStreams, id: number): Promise<JsonRpcResponse> {
  return new Promise((resolveResponse, reject) => {
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    const stderr: Buffer[] = [];
    const onStderr = (chunk: Buffer) => stderr.push(chunk);
    child.stderr.on("data", onStderr);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out waiting for response ${id}: ${Buffer.concat(stderr).toString("utf-8")}`));
    }, 5_000);
    const cleanup = (): void => {
      clearTimeout(timer);
      child.stderr.off("data", onStderr);
      lines.close();
    };
    lines.on("line", (line) => {
      try {
        const response = JSON.parse(line) as JsonRpcResponse;
        if (response.id === id) {
          cleanup();
          resolveResponse(response);
        }
      } catch {
        // Ignore diagnostic output; the CLI protocol response is JSON.
      }
    });
    child.once("exit", (code) => {
      if (child.exitCode !== null) {
        cleanup();
        reject(new Error(`proxy exited (${code}) before response ${id}`));
      }
    });
  });
}

function waitForExit(child: ChildProcessWithoutNullStreams): Promise<number | null> {
  if (child.exitCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolveExit) => child.once("exit", (code) => resolveExit(code)));
}

afterEach(async () => {
  await Promise.all(children.splice(0).map(async (child) => {
    if (child.exitCode !== null) return;
    child.kill("SIGTERM");
    await Promise.race([
      waitForExit(child),
      new Promise<void>((resolveTimeout) => setTimeout(resolveTimeout, 1_000)),
    ]);
    if (child.exitCode === null) child.kill("SIGKILL");
  }));
  for (const directory of tempDirs.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("MCP proxy lifecycle", () => {
  it("rejects non-scalar JSON-RPC ids before they can create orphan pending requests", () => {
    const server = new McpProxyServer({ upstream: [process.execPath, "-e", ""] });
    const parse = (server as unknown as {
      parseMessage: (line: string) => unknown;
    }).parseMessage.bind(server);

    for (const id of [null, true, false, {}, [], [1], { nested: 1 }]) {
      expect(parse(JSON.stringify({ jsonrpc: "2.0", id, method: "initialize" }))).toBeNull();
    }
    expect(parse(JSON.stringify({ jsonrpc: "2.0", id: 0, method: "initialize" })))
      .not.toBeNull();
    expect(parse(JSON.stringify({ jsonrpc: "2.0", id: "request-1", method: "initialize" })))
      .not.toBeNull();
    server.stop();
  });

  it("bounds the number of in-flight upstream requests", async () => {
    const server = new McpProxyServer({ upstream: [process.execPath, "-e", ""] });
    const pending = (server as unknown as {
      pending: Map<number | string, TestPendingRequest>;
    }).pending;
    for (let index = 0; index < MCP_MAX_PENDING_REQUESTS; index += 1) {
      pending.set(index, {
        resolve: () => {},
        reject: () => {},
        timer: setTimeout(() => {}, 60_000),
      });
    }
    const forwardRequest = (server as unknown as {
      forwardRequest: (request: object) => Promise<JsonRpcResponse>;
    }).forwardRequest.bind(server);

    await expect(forwardRequest({
      jsonrpc: "2.0",
      id: "overflow",
      method: "initialize",
    })).rejects.toThrow(/too many in-flight.*128/);
    server.stop();
  });

  it("rejects every pending request, clears its timer, and tolerates repeated stop calls", async () => {
    const server = new McpProxyServer({ upstream: [process.execPath, "-e", ""] });
    let timerFired = false;
    const timer = setTimeout(() => { timerFired = true; }, 20);
    const rejected = new Promise<Error>((resolveReject) => {
      const pending = (server as unknown as { pending: Map<number | string, TestPendingRequest> }).pending;
      pending.set(7, {
        resolve: () => {},
        reject: resolveReject,
        timer,
      });
    });

    server.stop();
    server.stop();

    await expect(rejected).resolves.toMatchObject({ message: "MCP proxy stopped" });
    await expect(server.waitForExit()).resolves.toBe(0);
    await new Promise<void>((resolveWait) => setTimeout(resolveWait, 40));
    expect(timerFired).toBe(false);
  });

  it("returns an internal JSON-RPC error promptly when upstream exits with a request pending", async () => {
    const child = spawnProxy("process.stdin.once('data', () => process.exit(0)); process.stdin.resume();");
    const responsePromise = waitForResponse(child, 1);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`);

    const response = await responsePromise;
    expect(response.error?.code).toBe(-32603);
    expect(response.error?.message).toMatch(/upstream (stdout closed|exited)/);
    await expect(waitForExit(child)).resolves.toBe(1);
  });

  it("rejects a pending request when upstream stdout reaches EOF before the process exits", async () => {
    const child = spawnProxy(
      "process.stdin.once('data', () => { process.stdout.end(); setInterval(() => {}, 1000); }); process.stdin.resume();",
    );
    const responsePromise = waitForResponse(child, 1);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`);

    const response = await responsePromise;
    expect(response.error?.code).toBe(-32603);
    expect(response.error?.message).toContain("upstream stdout closed");
    await expect(waitForExit(child)).resolves.toBe(1);
  });

  it("terminates an oversized upstream JSON-RPC line and wakes the pending request", async () => {
    const child = spawnProxy(
      `process.stdin.once('data', () => process.stdout.write(Buffer.alloc(${MCP_MAX_LINE_BYTES + 1}, 0x61))); process.stdin.resume();`,
    );
    const responsePromise = waitForResponse(child, 1);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`);

    const response = await responsePromise;
    expect(response.error?.code).toBe(-32603);
    expect(response.error?.message).toContain(`${MCP_MAX_LINE_BYTES} byte limit`);
    await expect(waitForExit(child)).resolves.toBe(1);
  });

  it("terminates the proxy when a client JSON-RPC line exceeds the byte limit", async () => {
    const child = spawnProxy("process.stdin.resume(); setInterval(() => {}, 1000);");
    const stderr: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.stdin.on("error", () => {});
    child.stdin.end(Buffer.alloc(MCP_MAX_LINE_BYTES + 1, 0x61));

    await expect(waitForExit(child)).resolves.toBe(1);
    expect(Buffer.concat(stderr).toString("utf-8")).toContain(`${MCP_MAX_LINE_BYTES} byte limit`);
  });

  it("escalates to SIGKILL when an upstream ignores graceful shutdown", async () => {
    const upstreamCode = [
      "process.on('SIGTERM', () => {});",
      "const readline = require('node:readline');",
      "const rl = readline.createInterface({ input: process.stdin });",
      "rl.on('line', (line) => {",
      "  const request = JSON.parse(line);",
      "  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result: {} }) + '\\n');",
      "});",
      "setInterval(() => {}, 1000);",
    ].join("\n");
    const child = spawnProxy(upstreamCode);

    const initialized = waitForResponse(child, 1);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" })}\n`);
    expect((await initialized).result).toBeDefined();

    const started = Date.now();
    child.kill("SIGTERM");
    await expect(waitForExit(child)).resolves.toBe(0);
    expect(Date.now() - started).toBeGreaterThanOrEqual(MCP_SHUTDOWN_GRACE_MS - 100);
    expect(Date.now() - started).toBeLessThan(MCP_SHUTDOWN_GRACE_MS + 2_000);
  });

  it("fails closed without consuming protocol stdin when interactive approval has no TTY", async () => {
    const upstreamCode = [
      "const readline = require('node:readline');",
      "const rl = readline.createInterface({ input: process.stdin });",
      "rl.on('line', (line) => {",
      "  const request = JSON.parse(line);",
      "  let result = {};",
      "  if (request.method === 'tools/list') result = { tools: [{ name: 'parse_resume', description: 'Parse a resume', inputSchema: { type: 'object' } }] };",
      "  if (request.method === 'tools/call') result = { content: [{ type: 'text', text: 'unexpected execution' }] };",
      "  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\\n');",
      "});",
    ].join("\n");
    const child = spawnProxy(upstreamCode, { interactive: true, detached: true });
    const stderr: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

    let responsePromise = waitForResponse(child, 1);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} })}\n`);
    expect((await responsePromise).result).toBeDefined();

    responsePromise = waitForResponse(child, 2);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`);
    expect((await responsePromise).result).toBeDefined();

    responsePromise = waitForResponse(child, 3);
    child.stdin.write(`${JSON.stringify({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "parse_resume", arguments: { file_path: "/tmp/resume.pdf" } },
    })}\n`);
    const denied = await responsePromise;
    expect(denied.error?.code).toBe(-32000);
    expect(denied.error?.message).toBe("Rejected by user");

    responsePromise = waitForResponse(child, 4);
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list" })}\n`);
    expect((await responsePromise).result).toBeDefined();
    expect(Buffer.concat(stderr).toString("utf-8")).toContain("No independent TTY is available");
  });
});
