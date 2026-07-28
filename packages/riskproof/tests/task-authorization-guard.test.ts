import { describe, expect, it } from "vitest";
import { evaluate } from "../src/engine.js";
import {
  applyTaskAuthorizationGuard,
  TaskAuthorizationGuard,
} from "../src/task-authorization-guard.js";

const DIGEST_A = "a".repeat(64);
const DIGEST_B = "b".repeat(64);
const OBJECTIVE_DIGEST = "c".repeat(64);

function contract() {
  return {
    taskId: "trusted-task-42",
    objectiveDigest: OBJECTIVE_DIGEST,
    expiresAt: "2026-08-01T00:00:00.000Z",
    maxCalls: 3,
    allowedTools: [
      {
        toolName: "read_file",
        descriptorDigest: DIGEST_A,
        maxCalls: 2,
        allowedProvenance: ["agent_generated", "user_request_1"],
      },
      { toolName: "send_email", maxCalls: 1 },
    ],
  } as const;
}

function guard() {
  return new TaskAuthorizationGuard(contract(), {
    clock: () => new Date("2026-07-27T00:00:00.000Z"),
  });
}

describe("TaskAuthorizationGuard", () => {
  it("authorizes only the exact host-held tool, descriptor, and provenance", () => {
    const monitor = guard();
    const result = monitor.reserve({
      toolName: "read_file",
      descriptorDigest: DIGEST_A,
      provenance: { path: ["user_request_1"], encoding: ["agent_generated"] },
    });

    expect(result).toMatchObject({
      reservation: 1,
      decisions: [{
        decision: "allow",
        riskLevel: "low",
        policy: { id: "task_contract_matched" },
      }],
    });
    if (!("reservation" in result)) throw new Error("expected reservation");
    expect(monitor.complete(result.reservation)).toBe(true);
    expect(monitor.complete(result.reservation)).toBe(false);
    expect(monitor.listEvents().map(({ status }) => status)).toEqual(["pending", "completed"]);
    expect(JSON.stringify(monitor.listEvents())).not.toContain("trusted-task-42");
    expect(monitor.getContractDigest()).toMatch(/^[a-f0-9]{64}$/);
    expect(monitor.getTaskDigest()).toMatch(/^[a-f0-9]{64}$/);
  });

  it("denies tools outside the task allowlist and merges the decision monotonically", () => {
    const monitor = guard();
    const output = evaluate({
      tool: "http_request",
      args: { url: "https://example.com" },
      options: { referenceTime: "2026-07-27T00:00:00.000Z" },
    });
    const guarded = applyTaskAuthorizationGuard(output, monitor, {
      toolName: "fetch_web",
      provenance: { url: ["agent_generated"] },
    });

    expect(guarded.action).toBe("block");
    expect(guarded.riskLevel).toBe("critical");
    expect(guarded.matchedPolicies.map(({ id }) => id)).toContain("task_tool_not_authorized");
    expect(guarded.proof.decision).toBe(guarded.decision);
  });

  it("fails closed when the current tool descriptor differs or is unavailable", () => {
    const monitor = guard();
    for (const descriptorDigest of [DIGEST_B, undefined]) {
      expect(monitor.assess({
        toolName: "read_file",
        ...(descriptorDigest ? { descriptorDigest } : {}),
        provenance: { path: ["user_request_1"] },
      })).toMatchObject([{
        decision: "deny",
        riskLevel: "critical",
        policy: { id: "task_tool_identity_mismatch" },
      }]);
    }
  });

  it("blocks provenance not authorized by the trusted contract without exposing raw IDs", () => {
    const monitor = guard();
    const findings = monitor.assess({
      toolName: "read_file",
      descriptorDigest: DIGEST_A,
      provenance: { path: ["webpage_9"], mode: ["agent_generated"] },
    });

    expect(findings).toMatchObject([{
      policy: {
        id: "task_source_not_authorized",
        triggeredArgs: ["path"],
      },
    }]);
    expect(JSON.stringify(findings)).not.toContain("webpage_9");
  });

  it("counts pending reservations so concurrent calls cannot overrun budgets", () => {
    const monitor = guard();
    const first = monitor.reserve({
      toolName: "send_email",
      provenance: { body: ["agent_generated"] },
    });
    expect(first).toHaveProperty("reservation");

    expect(monitor.reserve({
      toolName: "send_email",
      provenance: { body: ["agent_generated"] },
    })).toMatchObject({
      decisions: [{ policy: { id: "task_tool_budget_exhausted" } }],
    });

    if (!("reservation" in first)) throw new Error("expected reservation");
    expect(monitor.abort(first.reservation)).toBe(true);
    expect(monitor.abort(first.reservation)).toBe(false);
    expect(monitor.reserve({ toolName: "send_email" })).toHaveProperty("reservation");
  });

  it("enforces task-wide budgets and expiry from the trusted clock", () => {
    const budgeted = new TaskAuthorizationGuard({
      taskId: "one-call-task",
      maxCalls: 1,
      allowedTools: [{ toolName: "read_file" }],
    });
    const first = budgeted.reserve({ toolName: "read_file" });
    if (!("reservation" in first)) throw new Error("expected reservation");
    budgeted.complete(first.reservation);
    expect(budgeted.reserve({ toolName: "read_file" })).toMatchObject({
      decisions: [{ policy: { id: "task_call_budget_exhausted" } }],
    });

    const expired = new TaskAuthorizationGuard(contract(), {
      clock: () => new Date("2026-08-01T00:00:00.000Z"),
    });
    expect(expired.assess({
      toolName: "read_file",
      descriptorDigest: DIGEST_A,
      provenance: { path: ["user_request_1"] },
    })).toMatchObject([{ policy: { id: "task_contract_expired" } }]);
  });

  it("snapshots the contract so callers and tool output cannot expand authority", () => {
    const mutable = {
      taskId: "immutable-task",
      allowedTools: [{ toolName: "read_file", maxCalls: 1 }],
    };
    const monitor = new TaskAuthorizationGuard(mutable);
    mutable.allowedTools.push({ toolName: "send_email", maxCalls: 99 });

    expect(monitor.assess({ toolName: "send_email" })).toMatchObject([{
      policy: { id: "task_tool_not_authorized" },
    }]);
  });

  it("rejects ambiguous, malformed, and accessor-bearing contracts", () => {
    expect(() => new TaskAuthorizationGuard({
      taskId: "duplicate",
      allowedTools: [{ toolName: "read_file" }, { toolName: "read_file" }],
    })).toThrow(/duplicate/);
    expect(() => new TaskAuthorizationGuard({
      taskId: "bad-digest",
      objectiveDigest: "not-a-digest",
      allowedTools: [{ toolName: "read_file" }],
    })).toThrow(/SHA-256/);

    const raw: Record<string, unknown> = { allowedTools: [{ toolName: "read_file" }] };
    Object.defineProperty(raw, "taskId", {
      enumerable: true,
      get: () => "getter-task",
    });
    expect(() => new TaskAuthorizationGuard(raw as unknown as ReturnType<typeof contract>))
      .toThrow(/accessors/);
  });
});
