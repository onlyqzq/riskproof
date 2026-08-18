// ============================================================================
// dsh-riskproof — deterministic tool capability classifier
// ============================================================================
// Classifies an arbitrary DSH tool into security capabilities using only
// deterministic, explainable metadata: tool name, description, and input
// schema. No LLM, no network lookup, no execute-function inspection.
//
// A tool may carry several capabilities. Classification can only add scrutiny;
// it never grants a capability the tool does not actually have, and unknown
// tools fall back to an empty capability set (which the engine treats with the
// configured `unknownTool` posture).
// ============================================================================

import type { SecurityCapability } from "../core/types.js";
import { CAPABILITY_ORDER } from "./capabilities.js";

export interface ToolMetadata {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

const CODE_EXECUTION = /\b(?:shell|bash|zsh|pwsh|powershell|terminal|command|cmd|exec(?:ute)?|script|python|node|run code|code execution|execute code)\b/;
const CREDENTIAL = /\b(?:credential|secret|vault|keychain|api[_-]?key|password|token|keystore)\b/;

const INGEST_ACTION = /\b(?:fetch|search|scrape|crawl|browse|visit|download|retrieve|read|get|list|watch|subscribe|query)\b/;
const EXTERNAL_SOURCE = /\b(?:web|webpage|url|uri|http|https|internet|remote|feed|social|post|issue|channel|slack|teams|discord|mail|email|inbox|message|news|browser|rss)\b/;

const DISCLOSURE_ACTION = /\b(?:send|post|publish|upload|notify|forward|deliver|transmit|webhook|request|patch|put|push|comment|share|tweet|reply|create|append|write|update|submit)\b/;
const DISCLOSURE_TARGET = /\b(?:mail|email|message|slack|teams|discord|issue|comment|campaign|document|page|api|url|uri|http|https|endpoint|network|remote|webhook|web|notion|lark|feishu|calendar|drive|gist)\b/;

const PRIVATE_ACTION = /\b(?:read|get|list|search|query|inspect|retrieve|load|open|show|view|export|access|lookup|find)\b/;
const PRIVATE_SOURCE = /\b(?:file|filesystem|directory|folder|path|workspace|repository|repo|config(?:uration)?|environment|env|history|clipboard|contact|database|sql|record|customer|client|patient|medical|financial|invoice|log|excel|sheet|board|drive|notion|document|knowledge|wiki|internal)\b/;

const LOCAL_MUTATION_ACTION = /\b(?:write|create|update|delete|remove|move|rename|append|commit|merge|install|mkdir|touch|truncate|replace|save)\b/;
const LOCAL_MUTATION_TARGET = /\b(?:file|path|directory|folder|repository|repo|config(?:uration)?|settings|notion|drive|database|workspace|branch|issue|pr)\b/;

const NETWORK_SINK_FIELD = /\b(?:url|uri|endpoint|recipient|recipients|to|cc|bcc|body|payload|content|message|query|webhook|address|destination|target|channel|topic)\b/;

/** Normalize a metadata string into a lowercase, word-separated search text. */
function normalizeText(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function safeSchemaText(schema: Record<string, unknown> | undefined): string {
  if (!schema) return "";
  try {
    return JSON.stringify(schema);
  } catch {
    return "";
  }
}

function schemaFieldNames(schema: Record<string, unknown> | undefined): string[] {
  if (!schema) return [];
  const properties = schema.properties;
  if (typeof properties !== "object" || properties === null || Array.isArray(properties)) {
    return [];
  }
  return Object.keys(properties as Record<string, unknown>);
}

/**
 * Deterministically classify one tool. The result is a subset of the six
 * capability classes, ordered canonically. Classification is best-effort and
 * conservative: false positives only add scrutiny, never grant capability.
 */
export function classifyTool(
  metadata: ToolMetadata,
): SecurityCapability[] {
  if (!metadata || typeof metadata !== "object" || typeof metadata.name !== "string") {
    throw new TypeError("tool metadata must contain a string name");
  }
  const name = normalizeText(metadata.name).slice(0, 1_024);
  const description = normalizeText(
    typeof metadata.description === "string" ? metadata.description : "",
  ).slice(0, 8_192);
  const schemaText = safeSchemaText(metadata.inputSchema).slice(0, 16_384);
  const fieldNames = schemaFieldNames(metadata.inputSchema)
    .map(normalizeText)
    .join(" ");

  const semantic = `${name} ${description}`.trim();
  const all = `${semantic} ${schemaText} ${fieldNames}`.trim();

  const capabilities = new Set<SecurityCapability>();

  // General-purpose code execution can implement every phase (curl/read/send).
  if (CODE_EXECUTION.test(semantic)) {
    capabilities.add("CODE_EXECUTION");
  }

  if (CREDENTIAL.test(semantic)) {
    capabilities.add("CREDENTIAL_ACCESS");
  }

  // External ingestion: an ingest action against an external source.
  if (
    (INGEST_ACTION.test(semantic) && EXTERNAL_SOURCE.test(all)) ||
    /\b(?:fetch url|web search|visit page|scrape|crawl|read mail|read email|channel history|social feed|web fetch)\b/.test(semantic)
  ) {
    capabilities.add("EXTERNAL_INGESTION");
  }

  // External action: a disclosure action against an external target, or a
  // network sink field in the schema.
  if (
    (DISCLOSURE_ACTION.test(semantic) && DISCLOSURE_TARGET.test(all)) ||
    /\b(?:send mail|send email|post message|publish post|create issue|create campaign|upload file|send message|post comment)\b/.test(semantic) ||
    (DISCLOSURE_ACTION.test(semantic) && NETWORK_SINK_FIELD.test(fieldNames))
  ) {
    capabilities.add("EXTERNAL_ACTION");
  }

  // Private access: a read action against an internal/private source.
  if (
    (PRIVATE_ACTION.test(semantic) && PRIVATE_SOURCE.test(all)) ||
    /\b(?:read file|print env|get config|execute query|query database|read database|read data)\b/.test(semantic)
  ) {
    capabilities.add("PRIVATE_ACCESS");
  }

  // Local mutation: a write action against a local target, without an
  // external disclosure target.
  if (
    (LOCAL_MUTATION_ACTION.test(semantic) && LOCAL_MUTATION_TARGET.test(all)) &&
    !capabilities.has("EXTERNAL_ACTION")
  ) {
    capabilities.add("LOCAL_MUTATION");
  }

  return CAPABILITY_ORDER.filter((capability) => capabilities.has(capability));
}
