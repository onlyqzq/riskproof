import { describe, expect, it } from "vitest";
import { ContextTracker } from "../../src/provenance/context-tracker.js";
import { ProvenanceMapper } from "../../src/provenance/mapper.js";

describe("ContextTracker + ProvenanceMapper", () => {
  it("maps an exact substring back to its source", () => {
    const tracker = new ContextTracker({ minMatchLength: 4 });
    tracker.record("customer_data", "CUST-8842 balance 125000", "database_query");
    const mapper = new ProvenanceMapper(tracker);
    const mapping = mapper.mapArguments({ body: "CUST-8842 balance 125000" });
    expect(mapping.provenance.body).toContain("customer_data_1");
    expect(mapping.taints.body).toContain("CUSTOMER_DATA");
  });

  it("maps a bounded substring back to its source", () => {
    const tracker = new ContextTracker({ minMatchLength: 4 });
    tracker.record("customer_data", "CUST-8842 balance 125000", "database_query");
    const mapper = new ProvenanceMapper(tracker);
    const mapping = mapper.mapArguments({ body: "balance 125000" });
    expect(mapping.provenance.body).toContain("customer_data_1");
  });

  it("maps a stored result when later text wraps it", () => {
    const tracker = new ContextTracker({ minMatchLength: 4 });
    tracker.record("customer_data", "CUST-8842 balance 125000", "database_query");
    const mapping = new ProvenanceMapper(tracker).mapArguments({
      body: "Please forward this record: CUST-8842 balance 125000",
    });
    expect(mapping.provenance.body).toContain("customer_data_1");
  });

  it("does not reverse-match short common result values", () => {
    const tracker = new ContextTracker({ minMatchLength: 4 });
    tracker.record("tool_output", "done", "task_status");
    const mapping = new ProvenanceMapper(tracker).mapArguments({ body: "The work is done and reviewed" });
    expect(mapping.provenance.body).toEqual(["agent_generated"]);
  });

  it("tracks nested arguments by stable leaf path", () => {
    const tracker = new ContextTracker({ minMatchLength: 4 });
    tracker.record("customer_data", "CUST-8842 balance 125000", "database_query");
    const mapping = new ProvenanceMapper(tracker).mapArguments({
      message: { body: "CUST-8842 balance 125000" },
    });
    expect(mapping.provenance["message.body"]).toContain("customer_data_1");
    expect(mapping.taints["message.body"]).toContain("CUSTOMER_DATA");
  });

  it("indexes __proto__ as data rather than object metadata", () => {
    const tracker = new ContextTracker({ minMatchLength: 4 });
    tracker.record("customer_data", "CUST-8842", "database_query");
    const args = JSON.parse('{"__proto__":"CUST-8842"}') as Record<string, unknown>;
    const mapping = new ProvenanceMapper(tracker).mapArguments(args);
    expect(Object.hasOwn(mapping.provenance, "__proto__")).toBe(true);
    expect(mapping.provenance.__proto__).toContain("customer_data_1");
  });

  it("does not match a substring below the minimum length", () => {
    const tracker = new ContextTracker({ minMatchLength: 4 });
    tracker.record("customer_data", "CUST-8842 balance 125000", "database_query");
    const mapper = new ProvenanceMapper(tracker);
    const mapping = mapper.mapArguments({ body: "CUS" });
    expect(mapping.provenance.body).toEqual(["agent_generated"]);
  });

  it("marks untracked arguments as agent-generated", () => {
    const tracker = new ContextTracker();
    const mapper = new ProvenanceMapper(tracker);
    const mapping = mapper.mapArguments({ body: "never seen before" });
    expect(mapping.provenance.body).toEqual(["agent_generated"]);
    expect(mapping.taints.body).toEqual([]);
  });

  it("bounds oversized entries", () => {
    const tracker = new ContextTracker({ maxEntryBytes: 1024 });
    const big = "A".repeat(100_000);
    const entry = tracker.record("tool_output", big, "big_tool");
    expect(entry).not.toBeNull();
    expect(entry!.byteCount).toBeLessThanOrEqual(1024);
  });

  it("evicts the oldest entries past maxEntries", () => {
    const tracker = new ContextTracker({ maxEntries: 2, maxTotalBytes: 1_000_000 });
    tracker.record("tool_output", "first", "t");
    tracker.record("tool_output", "second", "t");
    tracker.record("tool_output", "third", "t");
    expect(tracker.list().length).toBe(2);
    expect(tracker.list().map((e) => e.id)).toEqual(["tool_output_2", "tool_output_3"]);
  });

  it("never exposes raw content through the public API", () => {
    const tracker = new ContextTracker();
    tracker.record("secret", "api_key=supersecret123", "vault");
    const entry = tracker.list()[0];
    expect(JSON.stringify(entry)).not.toContain("supersecret");
  });
});
