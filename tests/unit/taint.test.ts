import { describe, expect, it } from "vitest";
import {
  detectValueTaints,
  enrichArgumentTaints,
  inferKindFromTool,
  inferTaintsFromSource,
} from "../../src/core/taint.js";

describe("taint inference", () => {
  it("detects an API key", () => {
    expect(detectValueTaints("sk-abcdefghijklmnopqrstuvwxyz123456")).toContain("API_KEY");
  });

  it("detects a bearer token", () => {
    expect(detectValueTaints("Authorization: Bearer abc.def.ghi123456789")).toContain("API_KEY");
  });

  it("detects a key=value secret", () => {
    expect(detectValueTaints("api_key=supersecretvalue123")).toContain("SECRET");
  });

  it("detects customer data", () => {
    expect(detectValueTaints("customer record for CUST-8842")).toContain("CUSTOMER_DATA");
  });

  it("detects PII email", () => {
    expect(detectValueTaints("contact alice@example.com")).toContain("PII");
  });

  it("detects financial data", () => {
    expect(detectValueTaints("bank account IBAN DE89 3704")).toContain("FINANCIAL_DATA");
  });

  it("detects patient data", () => {
    expect(detectValueTaints("patient diagnosis: hypertension")).toContain("PATIENT_DATA");
  });

  it("combines multiple taints additively", () => {
    const taints = detectValueTaints("customer alice@example.com api_key=secret123");
    expect(taints).toContain("CUSTOMER_DATA");
    expect(taints).toContain("PII");
    expect(taints).toContain("SECRET");
  });

  it("infers taints from a source id", () => {
    expect(inferTaintsFromSource("webpage_1")).toContain("UNTRUSTED_WEB");
    expect(inferTaintsFromSource("customer_data_3")).toContain("CUSTOMER_DATA");
  });

  it("infers a context kind from tool name + capability", () => {
    expect(inferKindFromTool("database_query", ["PRIVATE_ACCESS"])).toBe("tool_output");
    expect(inferKindFromTool("customer_database_query", ["PRIVATE_ACCESS"])).toBe("customer_data");
    expect(inferKindFromTool("web_fetch", ["EXTERNAL_INGESTION"])).toBe("untrusted_web");
    expect(inferKindFromTool("get_secret", ["CREDENTIAL_ACCESS"])).toBe("secret");
  });

  it("enriches argument taints additively", () => {
    const args = { body: "CUST-8842 balance 125000" };
    const provenance = { body: ["webpage_1"] };
    const base = { body: [] };
    const enriched = enrichArgumentTaints(args, provenance, base);
    expect(enriched.body).toContain("UNTRUSTED_WEB");
    expect(enriched.body).toContain("CUSTOMER_DATA");
  });
});
