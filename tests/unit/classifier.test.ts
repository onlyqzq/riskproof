import { describe, expect, it } from "vitest";
import { classifyTool } from "../../src/classification/classifier.js";

function caps(name: string, description = "", inputSchema: Record<string, unknown> = {}) {
  return classifyTool({ name, description, inputSchema });
}

describe("classifyTool", () => {
  it("classifies web_fetch as EXTERNAL_INGESTION", () => {
    expect(caps("web_fetch", "Fetch the content of a URL")).toContain("EXTERNAL_INGESTION");
  });

  it("classifies web_search as EXTERNAL_INGESTION", () => {
    expect(caps("web_search", "Search the web")).toContain("EXTERNAL_INGESTION");
  });

  it("classifies database_query as PRIVATE_ACCESS", () => {
    expect(caps("database_query", "Query a SQL database")).toContain("PRIVATE_ACCESS");
  });

  it("classifies send_email as EXTERNAL_ACTION", () => {
    expect(caps("send_email", "Send an email")).toContain("EXTERNAL_ACTION");
  });

  it("classifies gmail_send as EXTERNAL_ACTION", () => {
    expect(caps("gmail_send", "Send a message via Gmail")).toContain("EXTERNAL_ACTION");
  });

  it("classifies bash as CODE_EXECUTION", () => {
    expect(caps("bash", "Run a shell command")).toContain("CODE_EXECUTION");
  });

  it("classifies run_code as CODE_EXECUTION", () => {
    expect(caps("run_code", "Execute a program")).toContain("CODE_EXECUTION");
  });

  it("does not classify source_code tools as CODE_EXECUTION", () => {
    expect(caps("read_source_code", "Read source code from a repository")).not.toContain("CODE_EXECUTION");
  });

  it("classifies file_read as PRIVATE_ACCESS", () => {
    expect(caps("file_read", "Read a file from disk")).toContain("PRIVATE_ACCESS");
  });

  it("classifies file_write as LOCAL_MUTATION", () => {
    expect(caps("file_write", "Write a file")).toContain("LOCAL_MUTATION");
  });

  it("classifies credential_get as CREDENTIAL_ACCESS", () => {
    expect(caps("credential_get", "Read a credential from the vault")).toContain("CREDENTIAL_ACCESS");
  });

  it("returns an empty set for an unknown tool", () => {
    expect(caps("mystery_gadget")).toEqual([]);
  });

  it("supports multi-capability tools", () => {
    const result = caps("shell_exec", "Execute a command", { properties: { url: {} } });
    expect(result).toContain("CODE_EXECUTION");
  });
});
