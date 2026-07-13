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
import { redactedValue } from "./redaction.js";

// ─── Risk/Action Display ────────────────────────────────────────────────────────

const RISK_BAR: Record<string, string> = {
  critical: "██████████ CRITICAL",
  high: "████████░░ HIGH",
  medium: "██████░░░░ MEDIUM",
  low: "████░░░░░░ LOW",
};

const ACTION_LABEL: Record<string, string> = {
  allow: "✅ PASS",
  block: "🔴 BLOCKED",
  ask_approval: "⚠️  APPROVAL REQUIRED",
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
};

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

export function formatCard(output: EngineOutput, metadata?: { toolName?: string; toolDesc?: string }): string {
  const action = output.action;
  const risk = output.riskLevel;
  const toolName = sanitizeTerminal(metadata?.toolName ?? output.proof.tool, 200);

  const lines: string[] = [];

  // Header
  lines.push(`╔${"═".repeat(56)}╗`);
  lines.push(`║  ${ACTION_LABEL[action] ?? action.toUpperCase()}${" ".repeat(Math.max(0, 52 - (ACTION_LABEL[action]?.length ?? action.length)))}║`);
  lines.push(`╠${"═".repeat(56)}╣`);
  lines.push(`║  Action:  ${padRight(toolName, 46)}║`);
  lines.push(`║  Risk:    ${padRight(RISK_BAR[risk] ?? risk.toUpperCase(), 46)}║`);
  lines.push(`╠${"═".repeat(56)}╣`);

  // Section 1: Argument Chain
  lines.push(`║${" ".repeat(56)}║`);
  lines.push(`║  ┌─ ARGUMENT CHAIN ${"─".repeat(36)}║`);
  for (const [name, arg] of Object.entries(output.arguments)) {
    const safeName = sanitizeTerminal(name, 200);
    const val = formatValue(redactedValue(arg));
    const { untrusted, sensitive } = classifyTaints(arg.taints);
    const sourceStr = arg.source.length > 0
      ? sanitizeTerminal(arg.source.join(", "), 500)
      : "(no provenance)";

    lines.push(`║  │${" ".repeat(54)}║`);
    lines.push(`║  │ ${padRight(safeName + ":", 54)}║`);
    if (val) lines.push(`║  │   ${padRight(val, 52)}║`);
    lines.push(`║  │   ⬅ ${padRight(sourceStr, 50)}║`);
    if (untrusted.length > 0) lines.push(`║  │   ${padRight("[UNTRUSTED] " + untrusted.join(", "), 50)}║`);
    if (sensitive.length > 0) lines.push(`║  │   ${padRight("[SENSITIVE] " + sensitive.join(", "), 50)}║`);
  }
  lines.push(`║  └${"─".repeat(52)}║`);

  // Section 2: Protections Triggered
  if (output.matchedPolicies.length > 0) {
    lines.push(`║${" ".repeat(56)}║`);
    lines.push(`║  ┌─ PROTECTIONS TRIGGERED ${"─".repeat(31)}║`);
    for (const p of output.matchedPolicies) {
      const info = RULE_DB[p.id];
      const icon = output.action === "block" ? "🔴" : "🟡";
      lines.push(`║  │${" ".repeat(54)}║`);
      lines.push(`║  │ ${icon} ${padRight(sanitizeTerminal(p.id, 128), 51)}║`);
      if (info) {
        lines.push(`║  │   ${padRight(info.label, 50)}║`);
        lines.push(`║  │   ${padRight(info.detail, 50)}║`);
      }
    }
    lines.push(`║  └${"─".repeat(52)}║`);
  }

  // Section 3: Consequences
  const consequences = output.matchedPolicies
    .map((p) => RULE_DB[p.id]?.consequence)
    .filter((c): c is string => !!c)
    .filter((c, i, arr) => arr.indexOf(c) === i);

  if (consequences.length > 0) {
    lines.push(`║${" ".repeat(56)}║`);
    lines.push(`║  ┌─ IF APPROVED, THIS COULD ${"─".repeat(29)}║`);
    for (const c of consequences) {
      for (const wrapped of wrapText(c, 50)) {
        lines.push(`║  │ • ${padRight(wrapped, 50)}║`);
      }
    }
    lines.push(`║  └${"─".repeat(52)}║`);
  }

  // Section 4: Recommendation + Choices
  lines.push(`║${" ".repeat(56)}║`);
  const rec = recommend(output);
  lines.push(`║  → ${padRight(rec, 50)}║`);
  lines.push(`║${" ".repeat(56)}║`);

  if (action === "ask_approval") {
    lines.push(`║  [A]pprove  [R]eject${" ".repeat(34)}║`);
  } else if (action === "block") {
    lines.push(`║  Action blocked — review and retry with safe parameters   ║`);
  } else {
    lines.push(`║  Action allowed — proceeding automatically                ║`);
  }

  lines.push(`╚${"═".repeat(56)}╝`);
  return lines.join("\n");
}

// ─── Compact Format (for non-interactive / log) ────────────────────────────────

export function formatCompact(output: EngineOutput, metadata?: { toolName?: string }): string {
  const toolName = sanitizeTerminal(metadata?.toolName ?? output.proof.tool, 200);
  const lines: string[] = [
    `${SEP}`,
    `  ${ACTION_LABEL[output.action]} | Risk: ${output.riskLevel.toUpperCase()} | Tool: ${toolName}`,
    `  Decision: ${output.decision} | Rules: ${output.matchedPolicies.map((p) => p.id).join(", ") || "none"}`,
  ];

  for (const [name, arg] of Object.entries(output.arguments)) {
    const safeName = sanitizeTerminal(name, 200);
    const taints = arg.taints.length > 0 ? ` [${arg.taints.join(", ")}]` : "";
    const src = arg.source.length > 0 ? ` ← ${sanitizeTerminal(arg.source.join(", "), 500)}` : "";
    lines.push(`  ${safeName}: ${formatValue(redactedValue(arg))?.slice(0, 40) ?? "?"}${src}${taints}`);
  }

  const consequences = output.matchedPolicies
    .map((p) => RULE_DB[p.id]?.consequence)
    .filter((c): c is string => !!c);
  if (consequences.length > 0) {
    lines.push(`  Consequences:`);
    for (const c of [...new Set(consequences)]) {
      lines.push(`    - ${c}`);
    }
  }

  lines.push(`  Recommendation: ${recommend(output)}`);
  lines.push(SEP);
  return lines.join("\n");
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function recommend(output: EngineOutput): string {
  if (output.action === "allow") return "Pass — no security risk detected";
  const ids = output.matchedPolicies.map((p) => p.id);
  if (ids.some((id) => id.includes("secret"))) return "REJECT — credentials detected in arguments";
  if (ids.some((id) => id.includes("dangerous_shell"))) return "REJECT — dangerous command pattern detected";
  if (ids.some((id) => id.includes("forbidden_taint") || id.includes("untrusted")))
    return "REJECT — untrusted source detected, possible injection attack";
  if (ids.some((id) => id.includes("invariant"))) return "REJECT — security invariant violated, cannot override";
  if (ids.some((id) => id.includes("customer_data"))) return "Review carefully — customer data being sent externally";
  if (ids.some((id) => id.includes("requires_capability"))) return "Review — confirm this operation is authorized";
  return "REJECT — security policy matched";
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
  // Account for CJK characters (roughly 2× width)
  let visual = 0;
  for (const ch of s) {
    visual += /[一-鿿　-〿＀-￯]/.test(ch) ? 2 : 1;
  }
  const pad = Math.max(0, len - visual);
  return s + " ".repeat(pad);
}

function wrapText(text: string, maxLen: number): string[] {
  const result: string[] = [];
  let remaining = text;
  while (remaining.length > maxLen) {
    result.push(remaining.slice(0, maxLen));
    remaining = remaining.slice(maxLen);
  }
  if (remaining.length > 0) result.push(remaining);
  return result;
}

export { RULE_DB };
