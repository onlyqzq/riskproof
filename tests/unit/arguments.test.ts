import { describe, expect, it } from "vitest";
import { argumentLeaves, argumentsAsRecord } from "../../src/core/arguments.js";

describe("argument traversal", () => {
  it("flattens nested objects and arrays into stable paths", () => {
    expect(argumentLeaves({
      message: { recipients: ["a@example.com", "b@example.com"], body: "hello" },
    })).toEqual([
      { path: "message.recipients[0]", field: "recipients", value: "a@example.com" },
      { path: "message.recipients[1]", field: "recipients", value: "b@example.com" },
      { path: "message.body", field: "body", value: "hello" },
    ]);
  });

  it("uses collision-resistant notation for unusual field names", () => {
    expect(argumentLeaves({ "message.body": "flat", message: { body: "nested" } }).map((leaf) => leaf.path))
      .toEqual(["[\"message.body\"]", "message.body"]);
  });

  it("wraps root arrays and scalars without discarding them", () => {
    expect(argumentLeaves(argumentsAsRecord(["first", "second"])).map((leaf) => leaf.path))
      .toEqual(["$[0]", "$[1]"]);
    expect(argumentsAsRecord("command")).toEqual({ $: "command" });
  });

  it("bounds traversal depth", () => {
    expect(() => argumentLeaves({ a: { b: { c: "value" } } }, 100, 1)).toThrow(/depth/);
  });
});
