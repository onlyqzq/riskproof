// ============================================================================
// RiskProof — Explainer (v3: 4-section approval card)
// ============================================================================
// Generates human-readable approval cards that explain:
//   1. WHAT is happening (action + risk level)
//   2. WHERE arguments come from (provenance chain)
//   3. WHAT protections triggered (matched policies with severity)
//   4. WHAT could go wrong (consequences if approved)
//
// Plus a clear recommendation and user choices.
// ============================================================================

import type { EngineOutput } from "./types.js";
import { redactEngineOutput, redactLogText, redactedValue } from "./redaction.js";

// ─── Risk/Action Display ────────────────────────────────────────────────────────

const RISK_BAR: Record<string, string> = {
  critical: "██████████ CRITICAL",
  high: "████████░░ HIGH",
  medium: "██████░░░░ MEDIUM",
  low: "████░░░░░░ LOW",
};

// ─── Rule Database ─────────────────────────────────────────────────────────────

interface RuleDescription {
  label: string;
  detail: string;
  consequence: string;
}

const RULE_DB: Record<string, RuleDescription> = {
  // deny rules
  secret_external_send: {
    label: "凭据/密钥通过邮件外发",
    detail: "邮件参数包含 API Key、Secret 或 Password，且收件人为外部域名",
    consequence: "凭据泄露到外部，可能被用于未授权访问内部系统、窃取数据或发起进一步攻击",
  },
  secret_external_http: {
    label: "凭据/密钥通过 HTTP 外发",
    detail: "HTTP 请求参数包含 API Key、Secret 或 Token，且目标为外部 URL",
    consequence: "凭据泄露到外部服务，可能导致 API 被滥用、数据被盗或服务被接管",
  },
  dangerous_shell_pattern: {
    label: "命令包含危险操作模式",
    detail: "Shell 命令匹配 curl|bash、rm -rf、chmod 777、eval 等已知危险模式",
    consequence: "恶意代码可能在系统上执行，导致数据被删除、系统被破坏、后门被安装",
  },
  capability_tool_mismatch: {
    label: "工具授权不匹配",
    detail: "能力授权的工具与当前调用的工具不一致，可能是越权操作",
    consequence: "Agent 可能在执行未经授权的操作，暗示越权或能力劫持",
  },
  capability_expired: {
    label: "能力授权已过期",
    detail: "工具的能力授权已超过有效期",
    consequence: "操作缺少有效授权，可能是旧会话重放或权限未及时续期",
  },
  capability_forbidden_taint: {
    label: "参数含禁止的污点标签",
    detail: "参数被标记为安全能力明确禁止的污点类型",
    consequence: "参数来源不可信（如工具描述被投毒），执行可能导致数据泄露或恶意行为",
  },
  capability_recipient_domain_not_allowed: {
    label: "收件人域名不在授权范围",
    detail: "收件人域名不在能力授权的允许列表中",
    consequence: "数据可能被发送到未经授权的第三方，违反数据外发策略",
  },
  invariant_forbidden_tool: {
    label: "工具被安全不变式禁止",
    detail: "系统安全约束明确禁止执行此工具，不可绕过",
    consequence: "绕过可能导致系统合规违规、审计失败或安全事故",
  },
  invariant_protected_taint_modified: {
    label: "受保护数据将被外发或修改",
    detail: "参数包含受安全不变式保护的数据标签（如患者数据、财务数据）",
    consequence: "受保护数据可能被未授权访问或篡改，违反行业监管要求",
  },
  invariant_numeric_range_violation: {
    label: "参数超出安全阈值",
    detail: "参数值超出安全不变式定义的数值范围",
    consequence: "批量操作可能超出系统承载能力，导致服务中断或级联故障",
  },

  // require_approval rules
  customer_data_external_send: {
    label: "敏感数据发往外部邮件地址",
    detail: "邮件参数含客户、个人、源码、财务或患者数据，且收件人为外部域名",
    consequence: "敏感数据可能泄露到组织外部，造成隐私、知识产权或行业合规风险",
  },
  sensitive_data_external_http: {
    label: "敏感数据发往外部 HTTP 地址",
    detail: "HTTP 请求参数含客户、个人、源码、财务或患者数据，且目标为外部 URL",
    consequence: "敏感数据可能泄露到组织外部，导致隐私、知识产权或行业合规风险",
  },
  untrusted_influenced_shell: {
    label: "Shell 命令受不可信来源影响",
    detail: "命令参数含不可信来源的污点标签（UNTRUSTED_WEB/EMAIL/TOOL_SCHEMA）",
    consequence: "可能是间接 prompt injection 攻击，不可信内容通过 Agent 进入了命令执行环节",
  },
  untrusted_provenance_email_to: {
    label: "收件人地址来自不可信来源",
    detail: "收件人地址的来源为不可信渠道，且目标为外部域名",
    consequence: "可能是间接 prompt injection：不可信网页或邮件中的内容诱导 Agent 将数据发送到攻击者控制的地址",
  },
  untrusted_provenance_shell: {
    label: "Shell 命令来源不可信",
    detail: "命令参数来源为不可信渠道",
    consequence: "不可信来源的内容进入了命令执行路径，可能导致任意代码执行",
  },
  high_risk_tool_requires_capability: {
    label: "高风险工具缺少能力授权",
    detail: "该工具属于高风险类别，但未提供能力授权声明",
    consequence: "Agent 可能在执行未经显式授权的操作，建议确认该操作是否在预期任务范围内",
  },
  capability_provenance_not_allowed: {
    label: "参数来源不在白名单",
    detail: "参数来源不在能力授权的允许列表中",
    consequence: "数据来自未经授权的渠道，可能与预期业务流程不符",
  },
  dangerous_database_query: {
    label: "数据库语句包含危险变更",
    detail: "查询包含 DROP、TRUNCATE、ALTER、GRANT、DELETE 或 UPDATE 等变更操作",
    consequence: "可能导致数据被删除、批量修改、权限提升或数据库结构被破坏",
  },
  untrusted_mutative_tool: {
    label: "可变更工具受不可信内容影响",
    detail: "文件写入、数据库或浏览器操作的参数来自网页、邮件或其他不可信 MCP 内容",
    consequence: "间接 prompt injection 可能借此修改文件、数据库或外部系统状态",
  },
};

const RULE_DB_EN: Record<string, RuleDescription> = {
  secret_external_send: { label: "Credentials sent by email", detail: "Email arguments contain a credential and target an external domain", consequence: "Leaked credentials could enable unauthorized system access and further data theft" },
  secret_external_http: { label: "Credentials sent over HTTP", detail: "HTTP arguments contain a credential and target an external host", consequence: "An external service could abuse the credential, steal data, or take over an account" },
  dangerous_shell_pattern: { label: "Dangerous shell pattern", detail: "The command matches a known dangerous execution or destruction pattern", consequence: "Malicious code could execute, delete data, damage the system, or install persistence" },
  capability_tool_mismatch: { label: "Capability tool mismatch", detail: "The capability authorizes a different tool", consequence: "The agent may be attempting an operation outside its granted authority" },
  capability_expired: { label: "Capability expired", detail: "The capability is no longer valid", consequence: "This may be a replayed session or an operation without current authorization" },
  capability_forbidden_taint: { label: "Forbidden taint present", detail: "An argument has a taint explicitly prohibited by the capability", consequence: "Untrusted or protected data could cause disclosure or malicious behavior" },
  capability_recipient_domain_not_allowed: { label: "Recipient domain not authorized", detail: "An email recipient is outside the capability allowlist", consequence: "Data could be disclosed to an unauthorized third party" },
  invariant_forbidden_tool: { label: "Tool forbidden by invariant", detail: "A non-overridable safety invariant forbids this tool", consequence: "Bypassing the invariant could cause a compliance or security incident" },
  invariant_protected_taint_modified: { label: "Protected data would be modified", detail: "The operation contains data protected by a safety invariant", consequence: "Regulated or protected data could be disclosed or modified without authorization" },
  invariant_numeric_range_violation: { label: "Safety threshold exceeded", detail: "A numeric value is outside an invariant's permitted range", consequence: "An oversized operation could overload the service or cause cascading failure" },
  customer_data_external_send: { label: "Sensitive data sent externally", detail: "Email content contains sensitive data and targets an external domain", consequence: "Privacy, intellectual-property, or regulatory data could leave the organization" },
  sensitive_data_external_http: { label: "Sensitive data sent to external HTTP host", detail: "An HTTP payload contains sensitive data and targets an external host", consequence: "Privacy, intellectual-property, or regulated data could be disclosed" },
  untrusted_influenced_shell: { label: "Shell command influenced by untrusted input", detail: "The command carries web, email, or MCP-schema taint", consequence: "Indirect prompt injection could reach arbitrary command execution" },
  untrusted_provenance_email_to: { label: "Recipient came from an untrusted source", detail: "The external recipient address originated in untrusted content", consequence: "Prompt injection may be steering data to an attacker-controlled mailbox" },
  untrusted_provenance_shell: { label: "Shell command has untrusted provenance", detail: "The command originated in an untrusted source", consequence: "Untrusted content in an execution path could lead to arbitrary code execution" },
  high_risk_tool_requires_capability: { label: "High-risk tool lacks a capability", detail: "No explicit capability authorizes this high-risk operation", consequence: "The agent may be operating outside the intended task boundary" },
  capability_provenance_not_allowed: { label: "Provenance is not allowlisted", detail: "An argument came from a source not permitted by the capability", consequence: "The data path does not match the authorized workflow" },
  dangerous_database_query: { label: "Dangerous database mutation", detail: "The statement contains destructive, mutating, or permission-changing SQL", consequence: "Data, permissions, or database structure could be irreversibly changed" },
  untrusted_mutative_tool: { label: "Mutative tool influenced by untrusted input", detail: "A file, database, or browser mutation is influenced by untrusted MCP content", consequence: "Indirect prompt injection could modify local or remote system state" },
};

export type ExplainerLocale = "zh-CN" | "en";

export interface FormatMetadata {
  toolName?: string;
  toolDesc?: string;
  locale?: ExplainerLocale;
}

const UI = {
  "zh-CN": {
    action: { allow: "✅ 允许执行", block: "🔴 已阻止", ask_approval: "⚠️  需要审批" } as Record<string, string>,
    actionLabel: "操作", riskLabel: "风险", argumentChain: "参数来源链", protections: "已触发的防护策略",
    consequences: "若批准，可能造成", approve: "[A]批准  [R]拒绝", blocked: "操作已阻止——请使用安全参数后重试",
    allowed: "操作已允许——将自动继续", decision: "决策", rules: "规则", consequenceLabel: "潜在后果",
    recommendation: "建议", none: "无", noProvenance: "无来源信息", sourceArrow: "来源",
  },
  en: {
    action: { allow: "✅ PASS", block: "🔴 BLOCKED", ask_approval: "⚠️  APPROVAL REQUIRED" } as Record<string, string>,
    actionLabel: "Action", riskLabel: "Risk", argumentChain: "ARGUMENT CHAIN", protections: "PROTECTIONS TRIGGERED",
    consequences: "IF APPROVED, THIS COULD", approve: "[A]pprove  [R]eject", blocked: "Action blocked — retry with safe parameters",
    allowed: "Action allowed — proceeding automatically", decision: "Decision", rules: "Rules", consequenceLabel: "Consequences",
    recommendation: "Recommendation", none: "none", noProvenance: "no provenance", sourceArrow: "source",
  },
} as const;

// ─── Taint Classification ──────────────────────────────────────────────────────

const UNTRUSTED = new Set(["UNTRUSTED_WEB", "UNTRUSTED_EMAIL", "UNTRUSTED_TOOL_SCHEMA"]);
const SENSITIVE = new Set(["CUSTOMER_DATA", "PII", "SECRET", "API_KEY", "SOURCE_CODE", "FINANCIAL_DATA", "PATIENT_DATA"]);

function classifyTaints(taints: string[]): { untrusted: string[]; sensitive: string[] } {
  const untrusted: string[] = [];
  const sensitive: string[] = [];
  for (const t of taints) {
    if (UNTRUSTED.has(t)) untrusted.push(t);
    if (SENSITIVE.has(t)) sensitive.push(t);
  }
  return { untrusted, sensitive };
}

// ─── Card Builder ──────────────────────────────────────────────────────────────

const SEP = "─".repeat(58);

export function formatCard(output: EngineOutput, metadata: FormatMetadata = {}): string {
  const action = output.action;
  const risk = output.riskLevel;
  const locale = metadata.locale ?? "zh-CN";
  const ui = UI[locale];
  const db = locale === "en" ? RULE_DB_EN : RULE_DB;
  const toolName = sanitizeTerminal(metadata.toolName ?? output.proof.tool, 200);

  const lines: string[] = [];

  // Header
  lines.push(`╔${"═".repeat(56)}╗`);
  lines.push(boxLine(`  ${ui.action[action] ?? action.toUpperCase()}`));
  lines.push(`╠${"═".repeat(56)}╣`);
  lines.push(boxLine(`  ${padRight(ui.actionLabel + ":", 9)}${toolName}`));
  lines.push(boxLine(`  ${padRight(ui.riskLabel + ":", 9)}${RISK_BAR[risk] ?? risk.toUpperCase()}`));
  lines.push(`╠${"═".repeat(56)}╣`);

  // Section 1: Argument Chain
  lines.push(boxLine());
  lines.push(boxLine(`  ┌─ ${sectionHeading(ui.argumentChain)}`));
  for (const [name, arg] of Object.entries(output.arguments)) {
    const safeName = sanitizeTerminal(name, 200);
    const val = formatValue(redactedValue(arg));
    const { untrusted, sensitive } = classifyTaints(arg.taints);
    const sourceStr = arg.source.length > 0
      ? sanitizeTerminal(arg.source.join(", "), 500)
      : `(${ui.noProvenance})`;

    lines.push(boxLine("  │"));
    lines.push(boxLine(`  │ ${safeName}:`));
    if (val) lines.push(boxLine(`  │   ${val}`));
    lines.push(boxLine(`  │   ⬅ ${ui.sourceArrow}: ${sourceStr}`));
    if (untrusted.length > 0) lines.push(boxLine(`  │   [UNTRUSTED] ${untrusted.join(", ")}`));
    if (sensitive.length > 0) lines.push(boxLine(`  │   [SENSITIVE] ${sensitive.join(", ")}`));
  }
  lines.push(boxLine(`  └${"─".repeat(53)}`));

  // Section 2: Protections Triggered
  if (output.matchedPolicies.length > 0) {
    lines.push(boxLine());
    lines.push(boxLine(`  ┌─ ${sectionHeading(ui.protections)}`));
    for (const p of output.matchedPolicies) {
      const info = db[p.id];
      const icon = output.action === "block" ? "🔴" : "🟡";
      lines.push(boxLine("  │"));
      lines.push(boxLine(`  │ ${icon} ${sanitizeTerminal(p.id, 128)}`));
      if (info) {
        lines.push(boxLine(`  │   ${info.label}`));
        for (const wrapped of wrapText(info.detail, 50)) {
          lines.push(boxLine(`  │   ${wrapped}`));
        }
      } else if (p.reason) {
        for (const wrapped of wrapText(sanitizeTerminal(redactLogText(p.reason), 1000), 50)) {
          lines.push(boxLine(`  │   ${wrapped}`));
        }
      }
    }
    lines.push(boxLine(`  └${"─".repeat(53)}`));
  }

  // Section 3: Consequences
  const consequences = output.matchedPolicies
    .map((p) => db[p.id]?.consequence ?? (p.reason ? redactLogText(p.reason) : undefined))
    .filter((c): c is string => !!c)
    .filter((c, i, arr) => arr.indexOf(c) === i);

  if (consequences.length > 0) {
    lines.push(boxLine());
    lines.push(boxLine(`  ┌─ ${sectionHeading(ui.consequences)}`));
    for (const c of consequences) {
      for (const wrapped of wrapText(sanitizeTerminal(c, 4000), 50)) {
        lines.push(boxLine(`  │ • ${wrapped}`));
      }
    }
    lines.push(boxLine(`  └${"─".repeat(53)}`));
  }

  // Section 4: Recommendation + Choices
  lines.push(boxLine());
  const rec = recommend(output, locale);
  lines.push(boxLine(`  → ${rec}`));
  lines.push(boxLine());

  if (action === "ask_approval") {
    lines.push(boxLine(`  ${ui.approve}`));
  } else if (action === "block") {
    lines.push(boxLine(`  ${ui.blocked}`));
  } else {
    lines.push(boxLine(`  ${ui.allowed}`));
  }

  lines.push(`╚${"═".repeat(56)}╝`);
  return lines.join("\n");
}

// ─── Compact Format (for non-interactive / log) ────────────────────────────────

export function formatCompact(output: EngineOutput, metadata: FormatMetadata = {}): string {
  const locale = metadata.locale ?? "zh-CN";
  const ui = UI[locale];
  const db = locale === "en" ? RULE_DB_EN : RULE_DB;
  const toolName = sanitizeTerminal(metadata.toolName ?? output.proof.tool, 200);
  const lines: string[] = [
    `${SEP}`,
    `  ${ui.action[output.action]} | ${ui.riskLabel}: ${output.riskLevel.toUpperCase()} | ${ui.actionLabel}: ${toolName}`,
    `  ${ui.decision}: ${output.decision} | ${ui.rules}: ${output.matchedPolicies.map((p) => p.id).join(", ") || ui.none}`,
  ];

  for (const [name, arg] of Object.entries(output.arguments)) {
    const safeName = sanitizeTerminal(name, 200);
    const taints = arg.taints.length > 0 ? ` [${arg.taints.join(", ")}]` : "";
    const src = arg.source.length > 0 ? ` ← ${sanitizeTerminal(arg.source.join(", "), 500)}` : "";
    lines.push(`  ${safeName}: ${formatValue(redactedValue(arg))?.slice(0, 40) ?? "?"}${src}${taints}`);
  }

  const consequences = output.matchedPolicies
    .map((p) => db[p.id]?.consequence ?? (p.reason ? redactLogText(p.reason) : undefined))
    .filter((c): c is string => !!c);
  if (consequences.length > 0) {
    lines.push(`  ${ui.consequenceLabel}:`);
    for (const c of [...new Set(consequences)]) {
      lines.push(`    - ${c}`);
    }
  }

  lines.push(`  ${ui.recommendation}: ${recommend(output, locale)}`);
  lines.push(SEP);
  return lines.join("\n");
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function recommend(output: EngineOutput, locale: ExplainerLocale): string {
  if (locale === "zh-CN") {
    if (output.action === "allow") return "允许——未检测到安全风险";
    const ids = output.matchedPolicies.map((p) => p.id);
    if (ids.some((id) => id.includes("secret"))) return "拒绝——参数中检测到凭据";
    if (ids.some((id) => id.includes("dangerous_shell") || id.includes("dangerous_database"))) return "拒绝——检测到危险操作模式";
    if (ids.some((id) => id.includes("forbidden_taint") || id.includes("untrusted"))) return "拒绝——检测到不可信来源，可能存在注入攻击";
    if (ids.some((id) => id.includes("invariant"))) return "拒绝——安全不变式不可绕过";
    if (ids.some((id) => id.includes("customer_data"))) return "谨慎审查——客户数据将被发送到外部";
    if (ids.some((id) => id.includes("requires_capability"))) return "审查——确认该操作已获授权";
    return output.action === "block" ? "拒绝——已命中安全策略" : "审查——请确认风险与授权范围";
  }
  if (output.action === "allow") return "Pass — no security risk detected";
  const ids = output.matchedPolicies.map((p) => p.id);
  if (ids.some((id) => id.includes("secret"))) return "REJECT — credentials detected in arguments";
  if (ids.some((id) => id.includes("dangerous_shell") || id.includes("dangerous_database"))) {
    return "REJECT — dangerous operation pattern detected";
  }
  if (ids.some((id) => id.includes("forbidden_taint") || id.includes("untrusted")))
    return "REJECT — untrusted source detected, possible injection attack";
  if (ids.some((id) => id.includes("invariant"))) return "REJECT — security invariant violated, cannot override";
  if (ids.some((id) => id.includes("customer_data"))) return "Review carefully — customer data being sent externally";
  if (ids.some((id) => id.includes("requires_capability"))) return "Review — confirm this operation is authorized";
  return "REJECT — security policy matched";
}

export interface ExplanationPolisher {
  polish(input: {
    locale: ExplainerLocale;
    authoritativeDecision: Pick<EngineOutput, "action" | "decision" | "riskLevel">;
    redactedOutput: EngineOutput;
    deterministicExplanation: string;
  }): Promise<string>;
}

export interface PolishedExplanationOptions extends FormatMetadata {
  timeoutMs?: number;
  maxCharacters?: number;
}

/**
 * Adds an optional LLM-written narrative after the authoritative deterministic
 * card. Only a redacted output is sent to the provider; failures, timeouts, and
 * invalid responses safely fall back to the template-only card.
 */
export async function formatPolishedCard(
  output: EngineOutput,
  polisher: ExplanationPolisher,
  options: PolishedExplanationOptions = {},
): Promise<string> {
  const deterministicExplanation = formatCard(output, options);
  const timeoutMs = boundedInteger(options.timeoutMs ?? 5_000, 100, 60_000, "timeoutMs");
  const maxCharacters = boundedInteger(options.maxCharacters ?? 4_000, 1, 16_000, "maxCharacters");
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error("explanation polisher timed out")), timeoutMs);
    });
    const narrative = await Promise.race([
      polisher.polish({
        locale: options.locale ?? "zh-CN",
        authoritativeDecision: {
          action: output.action,
          decision: output.decision,
          riskLevel: output.riskLevel,
        },
        redactedOutput: redactEngineOutput(output),
        deterministicExplanation,
      }),
      timeout,
    ]);
    if (typeof narrative !== "string" || narrative.trim().length === 0) return deterministicExplanation;
    const safe = sanitizeTerminal(narrative, maxCharacters).trim();
    if (!safe) return deterministicExplanation;
    const label = options.locale === "en" ? "AI-assisted explanation" : "AI 辅助说明（不改变上述确定性决策）";
    return `${deterministicExplanation}\n\n${label}:\n${safe}`;
  } catch {
    return deterministicExplanation;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function boundedInteger(value: number, min: number, max: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new RangeError(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}

function formatValue(value: unknown): string {
  if (typeof value === "string") {
    const safe = sanitizeTerminal(value, 200);
    return safe.length > 50 ? safe.slice(0, 47) + "..." : safe;
  }
  if (value === null || value === undefined) return "";
  return JSON.stringify(value).slice(0, 50);
}

export function sanitizeTerminal(value: string, maxLength = 1000): string {
  const withoutAnsi = value
    // OSC sequences (including hyperlinks/title changes)
    .replace(/\u001B\][^\u0007]*(?:\u0007|\u001B\\)/g, "")
    // CSI and common single-character escape sequences
    .replace(/\u001B(?:\[[0-?]*[ -/]*[@-~]|[@-_])/g, "");
  return withoutAnsi
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ")
    .slice(0, maxLength);
}

function padRight(s: string, len: number): string {
  const fitted = truncateVisual(s, len);
  return fitted + " ".repeat(Math.max(0, len - displayWidth(fitted)));
}

function boxLine(content = ""): string {
  return `║${padRight(content, 56)}║`;
}

function displayWidth(value: string): number {
  let visual = 0;
  for (const ch of value) {
    if (/\p{Mark}/u.test(ch) || ch === "\u200d" || /[\ufe00-\ufe0f]/u.test(ch)) continue;
    visual += /\p{Extended_Pictographic}/u.test(ch) ||
      /[\u1100-\u115F\u2329\u232A\u2E80-\uA4CF\uAC00-\uD7A3\uF900-\uFAFF\uFE10-\uFE19\uFE30-\uFE6F\uFF00-\uFF60\uFFE0-\uFFE6]/.test(ch)
      ? 2
      : 1;
  }
  return visual;
}

function truncateVisual(value: string, maxWidth: number): string {
  let result = "";
  let width = 0;
  for (const char of value) {
    const charWidth = displayWidth(char);
    if (width + charWidth > maxWidth) break;
    result += char;
    width += charWidth;
  }
  return result;
}

function sectionHeading(title: string): string {
  const safe = truncateVisual(title, 49);
  return `${safe} ${"─".repeat(Math.max(0, 50 - displayWidth(safe)))}`;
}

function wrapText(text: string, maxLen: number): string[] {
  const result: string[] = [];
  let current = "";
  let width = 0;
  for (const char of text) {
    const charWidth = displayWidth(char);
    if (current && width + charWidth > maxLen) {
      result.push(current);
      current = "";
      width = 0;
    }
    if (charWidth <= maxLen) {
      current += char;
      width += charWidth;
    }
  }
  if (current) result.push(current);
  return result;
}

export { RULE_DB, RULE_DB_EN };
