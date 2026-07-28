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

/** Policy records that attest a satisfied authorization constraint, not risk. */
const AUTHORIZATION_EVIDENCE_POLICY_IDS = new Set(["task_contract_matched"]);

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
  cloud_metadata_link_local_http: {
    label: "访问云元数据或链路本地地址",
    detail: "HTTP 目标指向云实例元数据服务或链路本地控制面地址",
    consequence: "攻击者可能读取临时云凭据、实例身份或宿主控制面数据，并进一步接管云资源",
  },
  protected_system_path_write: {
    label: "写入系统配置或持久化位置",
    detail: "文件或 Shell 操作会修改系统配置、SSH、启动脚本、计划任务或自动启动位置",
    consequence: "可能改变主机安全配置、安装持久化后门，或让恶意命令在未来会话和重启后继续执行",
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
  tool_name_collision: {
    label: "MCP 工具名称发生冲突",
    detail: "同一次工具清单中有多个完整定义声明了相同名称，调用目标无法建立唯一身份",
    consequence: "规划模型看到的可信名称可能实际指向攻击者定义，形成 tool squatting 或 shadowing",
  },
  tool_manifest_mismatch: {
    label: "工具定义与固定清单不一致",
    detail: "工具的完整描述符摘要与 operator 批准的 pinned manifest 不匹配",
    consequence: "MCP Server、依赖包或发布产物可能已被替换，工具权限与行为不再是已审核版本",
  },
  tool_descriptor_changed: {
    label: "受信工具定义发生变化",
    detail: "工具建立信任后修改了描述、输入/输出 Schema、annotations、_meta 或其他身份字段",
    consequence: "服务端可能实施 rug pull，在获得 Agent 信任后扩大能力、注入指令或改变数据流向",
  },
  unexpected_tool_added: {
    label: "工具清单出现未批准的新工具",
    detail: "基线建立后出现了不在 TOFU 快照或 pinned manifest 中的新名称",
    consequence: "新增工具可能抢占相似名称、诱导模型改选攻击路径，或扩大 MCP Server 的未审核能力",
  },
  task_contract_expired: {
    label: "可信任务合同已过期",
    detail: "Host 签发的任务授权已经超过有效期，当前调用不能继续使用旧权限",
    consequence: "继续执行可能把过期会话、重放请求或旧审批变成新的真实副作用",
  },
  task_contract_matched: {
    label: "结构化任务合同匹配",
    detail: "工具、描述符版本、来源、有效期和预算满足 Host 持有的确定性约束",
    consequence: "这只证明机器可检查的授权约束匹配，不证明调用在语义上服务于用户目标",
  },
  task_tool_not_authorized: {
    label: "工具不在任务授权范围",
    detail: "当前 MCP 工具不在 Host 持有的任务级 allowlist 中",
    consequence: "Agent 可能偏离原始任务，调用未委托的读取、发送、执行或变更能力",
  },
  task_tool_identity_mismatch: {
    label: "任务绑定的工具版本不匹配",
    detail: "当前完整工具描述符摘要与任务合同批准的版本不一致或无法确认",
    consequence: "旧任务授权可能被重用于已经变更、替换或扩大权限的 MCP 工具",
  },
  task_call_budget_exhausted: {
    label: "任务调用预算已耗尽",
    detail: "当前任务已完成和正在执行的调用达到 Host 设定的总上限",
    consequence: "继续执行会扩大自动化轨迹，可能造成循环调用、费用耗尽或越权操作",
  },
  task_tool_budget_exhausted: {
    label: "单工具调用预算已耗尽",
    detail: "该工具在当前任务中的已完成和 pending 调用达到独立上限",
    consequence: "重复调用可能把一次授权扩大成批量读取、发送、修改或执行",
  },
  task_source_not_authorized: {
    label: "参数来源未获任务授权",
    detail: "影响当前工具参数的 Host provenance 不在任务合同允许的来源集合中",
    consequence: "网页、邮件、工具结果或其他未授权来源可能正借用 Agent 的真实执行权",
  },
  self_contained_toolchain_capability: {
    label: "单个工具可覆盖完整攻击链",
    detail: "该工具同时具备外部内容摄入、私密数据访问和对外披露能力",
    consequence: "一个被注入的调用可能在工具内部完成数据收集与外发，绕过逐步调用审查",
  },
  cross_tool_private_access_after_ingestion: {
    label: "外部内容之后发生私密访问",
    detail: "工具链从不可信外部内容摄入跃迁到文件、配置、历史记录或其他私密数据访问",
    consequence: "寄生指令可能正在借用 Agent 已有权限收集本地或应用私密数据",
  },
  parasitic_toolchain_combined_sink: {
    label: "组合式收集与外发路径",
    detail: "外部内容进入上下文后，下一工具可在单步内同时读取私密数据并对外发送",
    consequence: "中间敏感结果不会暴露给逐参数追踪，仍可能在工具内部直接泄露",
  },
  parasitic_toolchain_disclosure_path: {
    label: "潜在寄生工具链对外披露",
    detail: "已观察到外部摄入、私密访问和对外发送三阶段能力序列",
    consequence: "即使当前参数没有精确匹配私密结果，完整能力路径仍可能导致隐蔽数据泄露",
  },
  parasitic_toolchain_data_exfiltration: {
    label: "已确认寄生工具链数据外发",
    detail: "对外参数携带了此前私密访问结果的来源或敏感数据证据",
    consequence: "私密数据将离开受控边界并到达外部目标，发送后通常无法撤回",
  },
};

const RULE_DB_EN: Record<string, RuleDescription> = {
  secret_external_send: { label: "Credentials sent by email", detail: "Email arguments contain a credential and target an external domain", consequence: "Leaked credentials could enable unauthorized system access and further data theft" },
  secret_external_http: { label: "Credentials sent over HTTP", detail: "HTTP arguments contain a credential and target an external host", consequence: "An external service could abuse the credential, steal data, or take over an account" },
  cloud_metadata_link_local_http: { label: "Cloud metadata or link-local access", detail: "The HTTP target is a cloud instance metadata service or a link-local control-plane address", consequence: "An attacker could obtain temporary cloud credentials, instance identity, or host control-plane data and use it to compromise cloud resources" },
  protected_system_path_write: { label: "Protected system or persistence write", detail: "A file or shell operation would change system configuration, SSH state, startup scripts, scheduled tasks, or autostart locations", consequence: "The operation could weaken host security, install persistence, or execute malicious commands in future sessions and after reboot" },
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
  tool_name_collision: { label: "MCP tool-name collision", detail: "Multiple complete definitions in one tool list claim the same name, so the invocation target has no unique identity", consequence: "A trusted-looking name may resolve to an attacker definition through tool squatting or shadowing" },
  tool_manifest_mismatch: { label: "Tool definition differs from the pinned manifest", detail: "The complete tool-descriptor digest does not match the operator-approved manifest", consequence: "The MCP server, dependency, or release artifact may have been replaced, changing reviewed authority and behavior" },
  tool_descriptor_changed: { label: "Trusted tool definition changed", detail: "After trust was established, the tool changed its description, input/output schema, annotations, _meta, or another identity field", consequence: "The server may be performing a rug pull by expanding authority, injecting instructions, or redirecting data after gaining trust" },
  unexpected_tool_added: { label: "Unapproved tool added", detail: "A new name appeared after the TOFU baseline or outside the pinned manifest", consequence: "The tool may squat on a similar name, steer model selection to an attack path, or expand the server's unreviewed authority" },
  task_contract_expired: { label: "Trusted task contract expired", detail: "The host-issued task authority is past its validity window", consequence: "Continuing could turn an expired session, replay, or old approval into a new real-world side effect" },
  task_contract_matched: { label: "Structured task contract matched", detail: "The tool, descriptor version, provenance, validity window, and budgets satisfy host-held deterministic constraints", consequence: "This establishes machine-checkable authority, not semantic proof that the action advances the user's objective" },
  task_tool_not_authorized: { label: "Tool is outside task authority", detail: "The MCP tool is absent from the host-held task allowlist", consequence: "The agent may have drifted from the delegated task into an unapproved read, disclosure, execution, or mutation capability" },
  task_tool_identity_mismatch: { label: "Task-bound tool version mismatch", detail: "The complete current descriptor does not match the version approved by the task contract or cannot be verified", consequence: "Old authority may be reused for a changed, replaced, or privilege-expanded MCP tool" },
  task_call_budget_exhausted: { label: "Task call budget exhausted", detail: "Completed and pending calls reached the host-defined task limit", consequence: "Further execution could expand the automation trajectory, loop, consume resources, or exceed delegated authority" },
  task_tool_budget_exhausted: { label: "Per-tool call budget exhausted", detail: "Completed and pending calls for this tool reached its task-scoped limit", consequence: "A one-call grant could otherwise become bulk reading, disclosure, mutation, or execution" },
  task_source_not_authorized: { label: "Argument source is not task-authorized", detail: "Host-derived provenance influencing this call is outside the task contract", consequence: "A webpage, email, tool result, or another unauthorized source may be borrowing the agent's real execution authority" },
  self_contained_toolchain_capability: { label: "Self-contained attack-chain capability", detail: "One tool can ingest external content, access private data, and disclose it externally", consequence: "An injected call could collect and exfiltrate data internally, bypassing per-step review" },
  cross_tool_private_access_after_ingestion: { label: "Private access after external ingestion", detail: "The chain transitions from untrusted external content to a private file, configuration, history, or data source", consequence: "Parasitic instructions may be using the agent's authority to collect private data" },
  parasitic_toolchain_combined_sink: { label: "Combined collection and disclosure path", detail: "After external ingestion, one tool can both access private data and send it externally", consequence: "The tool may disclose data internally without exposing an intermediate value to argument tracking" },
  parasitic_toolchain_disclosure_path: { label: "Potential parasitic disclosure chain", detail: "The observed sequence covers external ingestion, private access, and external disclosure", consequence: "The complete capability path may enable covert disclosure even without an exact argument match" },
  parasitic_toolchain_data_exfiltration: { label: "Confirmed parasitic data exfiltration", detail: "An outbound argument carries provenance or sensitive-data evidence from an earlier private access", consequence: "Private data would leave the controlled boundary and usually cannot be recalled" },
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
    actionLabel: "操作", riskLabel: "风险", conclusion: "先看结论", riskPath: "风险如何发生",
    evidence: "判断依据", consequences: "批准后的现实后果", safer: "降低风险后再执行",
    argumentChain: "参数来源链", protections: "已触发的防护策略", authorizationEvidence: "已验证的授权证据",
    verify: "批准前请确认", approve: "[R]拒绝（默认）  [A]确认风险并批准",
    blocked: "操作已阻止——请按降险建议修改后重试", allowed: "操作已允许——将自动继续",
    decision: "决策", rules: "规则", consequenceLabel: "潜在后果", recommendation: "建议",
    none: "无", noProvenance: "无来源信息", sourceArrow: "来源", affected: "涉及参数",
    scope: "影响范围", reversibility: "可逆性", evidenceCoverage: "来源证据",
  },
  en: {
    action: { allow: "✅ PASS", block: "🔴 BLOCKED", ask_approval: "⚠️  APPROVAL REQUIRED" } as Record<string, string>,
    actionLabel: "Action", riskLabel: "Risk", conclusion: "BOTTOM LINE", riskPath: "HOW THE RISK HAPPENS",
    evidence: "WHY THIS WAS FLAGGED", consequences: "REAL-WORLD IMPACT IF APPROVED", safer: "SAFER WAY TO PROCEED",
    argumentChain: "ARGUMENT CHAIN", protections: "PROTECTIONS TRIGGERED", authorizationEvidence: "VERIFIED AUTHORIZATION EVIDENCE",
    verify: "VERIFY BEFORE APPROVING", approve: "[R]eject (default)  [A]cknowledge & approve",
    blocked: "Action blocked — apply a safer change and retry", allowed: "Action allowed — proceeding automatically",
    decision: "Decision", rules: "Rules", consequenceLabel: "Consequences", recommendation: "Recommendation",
    none: "none", noProvenance: "no provenance", sourceArrow: "source", affected: "arguments",
    scope: "Scope", reversibility: "Reversibility", evidenceCoverage: "Source evidence",
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

// ─── Structured Explanation Model ──────────────────────────────────────────────

export type RiskPathKind = "source" | "data" | "action" | "impact";
export type EvidenceCoverageLevel = "complete" | "partial" | "limited";
export type ExplanationRecommendationAction = "allow" | "review" | "reject";

export interface RiskPathStep {
  kind: RiskPathKind;
  label: string;
}

export interface RiskFinding {
  policyId: string;
  title: string;
  detail: string;
  triggeredArguments: string[];
}

export interface AuthorizationEvidence {
  policyId: string;
  title: string;
  detail: string;
}

export interface RiskConsequence {
  title: string;
  detail: string;
  scope: string;
  reversibility: string;
}

export interface EvidenceCoverage {
  level: EvidenceCoverageLevel;
  knownArguments: number;
  totalArguments: number;
  missingArguments: string[];
  summary: string;
}

/**
 * UI-neutral explanation payload for terminal, web, and agent approval clients.
 * It combines a causal risk path with counterfactual safer actions. The policy
 * engine remains the only authority for the decision.
 */
export interface RiskExplanation {
  version: "1";
  locale: ExplainerLocale;
  headline: string;
  actionSummary: string;
  severity: {
    level: EngineOutput["riskLevel"];
    label: string;
    meaning: string;
  };
  riskPath: RiskPathStep[];
  findings: RiskFinding[];
  authorizationEvidence: AuthorizationEvidence[];
  consequences: RiskConsequence[];
  evidenceCoverage: EvidenceCoverage;
  saferAlternatives: string[];
  verificationQuestions: string[];
  recommendation: {
    action: ExplanationRecommendationAction;
    label: string;
    reason: string;
  };
}

interface LocalizedText {
  "zh-CN": string;
  en: string;
}

interface ImpactTemplate {
  title: LocalizedText;
  scope: LocalizedText;
  reversibility: LocalizedText;
}

const IMPACT_TEMPLATES = {
  credential: {
    title: { "zh-CN": "凭据可能被盗用", en: "Credential compromise" },
    scope: { "zh-CN": "该凭据能够访问的账号、API 与数据", en: "Every account, API, and dataset accessible with the credential" },
    reversibility: { "zh-CN": "发送后无法收回；需立即轮换并排查滥用", en: "Cannot be recalled; requires immediate rotation and abuse review" },
  },
  data: {
    title: { "zh-CN": "敏感数据可能离开受控边界", en: "Sensitive-data disclosure" },
    scope: { "zh-CN": "外部接收方及其后续存储、转发范围", en: "The external recipient and any downstream storage or forwarding" },
    reversibility: { "zh-CN": "外发后通常难以彻底撤回", en: "Usually difficult to fully recall after transmission" },
  },
  execution: {
    title: { "zh-CN": "主机可能执行攻击者控制的操作", en: "Host compromise or destructive execution" },
    scope: { "zh-CN": "当前主机、文件以及该进程可访问的内部资源", en: "The host, its files, and internal resources reachable by the process" },
    reversibility: { "zh-CN": "删除、加密或后门行为可能不可逆", en: "Deletion, encryption, or persistence may be irreversible" },
  },
  database: {
    title: { "zh-CN": "数据或数据库结构可能被破坏", en: "Database integrity or availability loss" },
    scope: { "zh-CN": "命中语句涉及的记录、表、权限及其下游业务", en: "Affected records, tables, permissions, and dependent services" },
    reversibility: { "zh-CN": "无备份或事务保护时可能不可逆", en: "May be irreversible without a backup or transaction boundary" },
  },
  availability: {
    title: { "zh-CN": "服务可能中断或发生级联故障", en: "Service disruption or cascading failure" },
    scope: { "zh-CN": "超过阈值的任务及其依赖服务", en: "The oversized operation and its dependent services" },
    reversibility: { "zh-CN": "通常可恢复，但可能造成持续业务影响", en: "Often recoverable, but business impact may persist" },
  },
  authorization: {
    title: { "zh-CN": "操作可能越过既定授权边界", en: "Operation outside the authorized boundary" },
    scope: { "zh-CN": "当前任务、账号权限与受该策略保护的资源", en: "The current task, account privileges, and policy-protected resources" },
    reversibility: { "zh-CN": "取决于实际副作用；事后审计不能撤销已发生的操作", en: "Depends on side effects; an audit cannot undo an executed action" },
  },
  injection: {
    title: { "zh-CN": "不可信内容可能借 Agent 改变真实系统", en: "Indirect prompt injection reaches a real system" },
    scope: { "zh-CN": "被调用工具能够修改的文件、数据或外部系统", en: "Files, data, or external systems the invoked tool can modify" },
    reversibility: { "zh-CN": "取决于工具副作用，部分修改无法自动回滚", en: "Depends on tool side effects; some changes cannot be automatically rolled back" },
  },
  supply_chain: {
    title: { "zh-CN": "MCP 工具身份或供应链可能已被替换", en: "MCP tool identity or supply-chain compromise" },
    scope: { "zh-CN": "依赖该工具定义做出的规划、调用及其可访问资源", en: "Plans, calls, and reachable resources that rely on this tool definition" },
    reversibility: { "zh-CN": "隔离可阻止后续调用；建立基线后的既往执行仍需审计", en: "Quarantine blocks subsequent calls; executions since the baseline still require review" },
  },
  compliance: {
    title: { "zh-CN": "可能触发合规、审计或受保护数据事件", en: "Compliance or protected-data incident" },
    scope: { "zh-CN": "安全不变式覆盖的数据、系统与监管责任", en: "Data, systems, and regulatory obligations covered by the invariant" },
    reversibility: { "zh-CN": "违规事实不可撤销，且可能需要报告与补救", en: "The violation itself cannot be undone and may require reporting" },
  },
  generic: {
    title: { "zh-CN": "操作可能造成未预期的安全影响", en: "Potential unintended security impact" },
    scope: { "zh-CN": "命中策略的参数与目标系统", en: "The policy-matched arguments and target system" },
    reversibility: { "zh-CN": "当前证据不足以确认能否完整回滚", en: "Current evidence does not establish that the action can be fully rolled back" },
  },
} as const satisfies Record<string, ImpactTemplate>;

type ImpactKind = keyof typeof IMPACT_TEMPLATES;

const RULE_IMPACT: Record<string, ImpactKind> = {
  secret_external_send: "credential",
  secret_external_http: "credential",
  cloud_metadata_link_local_http: "credential",
  protected_system_path_write: "execution",
  dangerous_shell_pattern: "execution",
  dangerous_database_query: "database",
  invariant_numeric_range_violation: "availability",
  customer_data_external_send: "data",
  sensitive_data_external_http: "data",
  capability_recipient_domain_not_allowed: "data",
  untrusted_provenance_email_to: "data",
  untrusted_influenced_shell: "execution",
  untrusted_provenance_shell: "execution",
  untrusted_mutative_tool: "injection",
  invariant_forbidden_tool: "compliance",
  invariant_protected_taint_modified: "compliance",
  capability_tool_mismatch: "authorization",
  capability_expired: "authorization",
  capability_forbidden_taint: "authorization",
  high_risk_tool_requires_capability: "authorization",
  capability_provenance_not_allowed: "authorization",
  tool_name_collision: "supply_chain",
  tool_manifest_mismatch: "supply_chain",
  tool_descriptor_changed: "supply_chain",
  unexpected_tool_added: "supply_chain",
  task_contract_expired: "authorization",
  task_contract_matched: "authorization",
  task_tool_not_authorized: "authorization",
  task_tool_identity_mismatch: "authorization",
  task_call_budget_exhausted: "authorization",
  task_tool_budget_exhausted: "authorization",
  task_source_not_authorized: "authorization",
  self_contained_toolchain_capability: "injection",
  cross_tool_private_access_after_ingestion: "injection",
  parasitic_toolchain_combined_sink: "data",
  parasitic_toolchain_disclosure_path: "data",
  parasitic_toolchain_data_exfiltration: "data",
};

const TOOL_ACTIONS: Record<string, LocalizedText> = {
  send_email: { "zh-CN": "发送邮件", en: "send an email" },
  http_request: { "zh-CN": "向外部服务发起请求", en: "send a request to an external service" },
  shell_exec: { "zh-CN": "在主机上执行命令", en: "run a command on the host" },
  file_read: { "zh-CN": "读取文件", en: "read a file" },
  file_write: { "zh-CN": "写入或修改文件", en: "write or modify a file" },
  database_query: { "zh-CN": "执行数据库语句", en: "execute a database statement" },
  browser_action: { "zh-CN": "操作浏览器或外部页面", en: "act in a browser or external page" },
};

const TARGET_ARGUMENTS: Record<string, string[]> = {
  send_email: ["to", "recipient", "recipients"],
  http_request: ["url", "uri", "endpoint"],
  shell_exec: ["command", "cmd"],
  file_read: ["path", "file", "filename"],
  file_write: ["path", "file", "filename"],
  database_query: ["query", "sql", "table", "database"],
  browser_action: ["url", "action", "selector"],
};

/**
 * Build a UI-neutral, redacted explanation model. Terminal cards remain a
 * deterministic renderer, while web/agent clients can present the same causal
 * source -> data -> action -> impact story without parsing terminal text.
 */
export function buildRiskExplanation(
  output: EngineOutput,
  metadata: FormatMetadata = {},
): RiskExplanation {
  const safeOutput = redactEngineOutput(output);
  const locale = metadata.locale ?? "zh-CN";
  const db = locale === "en" ? RULE_DB_EN : RULE_DB;
  const tool = safeOutput.proof.tool;
  const toolAction = TOOL_ACTIONS[tool]?.[locale] ?? sanitizeTerminal(metadata.toolName ?? tool, 128);
  const targetField = TARGET_ARGUMENTS[tool]?.find((name) => safeOutput.arguments[name] !== undefined);
  const target = targetField === undefined
    ? undefined
    : formatValue(redactedValue(safeOutput.arguments[targetField]));
  const actionSummary = target
    ? `${toolAction}: ${target}`
    : toolAction;
  const authorizationPolicies = safeOutput.matchedPolicies
    .filter(({ id }) => AUTHORIZATION_EVIDENCE_POLICY_IDS.has(id));
  const riskPolicies = safeOutput.matchedPolicies
    .filter(({ id }) => !AUTHORIZATION_EVIDENCE_POLICY_IDS.has(id));

  const sourceLabels = [...new Set(Object.values(safeOutput.arguments)
    .flatMap((argument) => argument.source)
    .filter(Boolean))];
  const taints = [...new Set(Object.values(safeOutput.arguments)
    .flatMap((argument) => argument.taints))];
  const { untrusted, sensitive } = classifyTaints(taints);
  const riskPath: RiskPathStep[] = [];
  if (sourceLabels.length > 0) {
    riskPath.push({
      kind: "source",
      label: locale === "en"
        ? `Source: ${sanitizeTerminal(sourceLabels.join(", "), 500)}`
        : `来源：${sanitizeTerminal(sourceLabels.join("、"), 500)}`,
    });
  }
  if (untrusted.length > 0 || sensitive.length > 0) {
    const labels = [...untrusted, ...sensitive].join(", ");
    riskPath.push({
      kind: "data",
      label: locale === "en" ? `Data labels: ${labels}` : `数据标签：${labels}`,
    });
  }
  riskPath.push({ kind: "action", label: actionSummary });

  const impactKinds = [...new Set(riskPolicies
    .map(({ id }) => RULE_IMPACT[id] ?? "generic"))];
  const consequences: RiskConsequence[] = impactKinds.map((kind) => {
    const template = IMPACT_TEMPLATES[kind];
    const matchingPolicy = riskPolicies.find(({ id }) =>
      (RULE_IMPACT[id] ?? "generic") === kind);
    const info = matchingPolicy ? db[matchingPolicy.id] : undefined;
    return {
      title: template.title[locale],
      detail: info?.consequence ?? matchingPolicy?.reason ?? template.title[locale],
      scope: template.scope[locale],
      reversibility: template.reversibility[locale],
    };
  });
  if (consequences.length > 0) {
    riskPath.push({ kind: "impact", label: consequences.map(({ title }) => title).join("; ") });
  }

  const argumentEntries = Object.entries(safeOutput.arguments);
  const attributed = argumentEntries.filter(([, argument]) =>
    argument.source.some((source) => source !== "agent_generated"));
  const missingArguments = argumentEntries
    .filter(([, argument]) => !argument.source.some((source) => source !== "agent_generated"))
    .map(([name]) => name);
  const coverageLevel: EvidenceCoverageLevel = argumentEntries.length > 0 && attributed.length === argumentEntries.length
    ? "complete"
    : attributed.length > 0
      ? "partial"
      : "limited";
  const evidenceCoverage: EvidenceCoverage = {
    level: coverageLevel,
    knownArguments: attributed.length,
    totalArguments: argumentEntries.length,
    missingArguments,
    summary: locale === "en"
      ? `${attributed.length}/${argumentEntries.length} arguments have non-agent provenance`
      : `${attributed.length}/${argumentEntries.length} 个参数具有非 Agent 自生成的来源证据`,
  };

  const findings: RiskFinding[] = riskPolicies.map((policy) => ({
    policyId: policy.id,
    title: db[policy.id]?.label ?? policy.id,
    detail: db[policy.id]?.detail ?? policy.reason ?? policy.evidence.join("; "),
    triggeredArguments: [...policy.triggeredArgs],
  }));
  const authorizationEvidence: AuthorizationEvidence[] = authorizationPolicies.map((policy) => ({
    policyId: policy.id,
    title: db[policy.id]?.label ?? policy.id,
    detail: policy.evidence.length > 0
      ? policy.evidence.join("; ")
      : db[policy.id]?.detail ?? policy.reason ?? policy.id,
  }));

  const chainDetected = riskPolicies.some(({ id }) =>
    id.includes("toolchain") || id === "cross_tool_private_access_after_ingestion");
  const saferAlternatives = locale === "en"
    ? [
        ...(chainDetected ? ["Start a new trusted task without carrying external content into private-data tools"] : []),
        "Reduce the capability to the exact resource and destination required",
        "Remove or redact sensitive data before any external disclosure",
      ]
    : [
        ...(chainDetected ? ["新建可信任务，避免把外部内容上下文带入私密数据工具"] : []),
        "把 capability 收窄到本次所需的精确资源与目标",
        "任何对外发送前先移除或脱敏敏感数据",
      ];
  const verificationQuestions = locale === "en"
    ? ["Did the user explicitly request this exact action?", "Is the destination trusted and expected?", "Is every included data field necessary?"]
    : ["用户是否明确要求了这一精确操作？", "目标地址是否可信且符合预期？", "发送或修改的每项数据是否都确有必要？"];

  const recommendationAction: ExplanationRecommendationAction = safeOutput.action === "allow"
    ? "allow"
    : safeOutput.action === "block"
      ? "reject"
      : "review";
  const recommendationLabel = locale === "en"
    ? recommendationAction === "allow" ? "Proceed" : recommendationAction === "reject" ? "Reject" : "Step-up review"
    : recommendationAction === "allow" ? "允许执行" : recommendationAction === "reject" ? "拒绝执行" : "升级审批";
  const headline = locale === "en"
    ? `${safeOutput.action === "allow" ? "Allowed" : safeOutput.action === "block" ? "Blocked" : "Review required"}: ${actionSummary}`
    : `${safeOutput.action === "allow" ? "允许" : safeOutput.action === "block" ? "阻断" : "需要审批"}：${actionSummary}`;

  return {
    version: "1",
    locale,
    headline,
    actionSummary,
    severity: {
      level: safeOutput.riskLevel,
      label: RISK_BAR[safeOutput.riskLevel] ?? safeOutput.riskLevel.toUpperCase(),
      meaning: locale === "en"
        ? `The deterministic policy result is ${safeOutput.decision}`
        : `确定性策略结果为 ${safeOutput.decision}`,
    },
    riskPath,
    findings,
    authorizationEvidence,
    consequences,
    evidenceCoverage,
    saferAlternatives,
    verificationQuestions,
    recommendation: {
      action: recommendationAction,
      label: recommendationLabel,
      reason: recommend(safeOutput, locale),
    },
  };
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
  const authorizationPolicies = output.matchedPolicies
    .filter(({ id }) => AUTHORIZATION_EVIDENCE_POLICY_IDS.has(id));
  const riskPolicies = output.matchedPolicies
    .filter(({ id }) => !AUTHORIZATION_EVIDENCE_POLICY_IDS.has(id));

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
  if (authorizationPolicies.length > 0) {
    lines.push(boxLine());
    lines.push(boxLine(`  ┌─ ${sectionHeading(ui.authorizationEvidence)}`));
    for (const p of authorizationPolicies) {
      const info = db[p.id];
      lines.push(boxLine("  │"));
      lines.push(boxLine(`  │ ✅ ${sanitizeTerminal(p.id, 128)}`));
      if (info) lines.push(boxLine(`  │   ${info.label}`));
      for (const evidence of p.evidence) {
        for (const wrapped of wrapText(sanitizeTerminal(redactLogText(evidence), 1000), 50)) {
          lines.push(boxLine(`  │   ${wrapped}`));
        }
      }
    }
    lines.push(boxLine(`  └${"─".repeat(53)}`));
  }

  if (riskPolicies.length > 0) {
    lines.push(boxLine());
    lines.push(boxLine(`  ┌─ ${sectionHeading(ui.protections)}`));
    for (const p of riskPolicies) {
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
  const consequences = riskPolicies
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
  const authorizationPolicies = output.matchedPolicies
    .filter(({ id }) => AUTHORIZATION_EVIDENCE_POLICY_IDS.has(id));
  const riskPolicies = output.matchedPolicies
    .filter(({ id }) => !AUTHORIZATION_EVIDENCE_POLICY_IDS.has(id));
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

  if (authorizationPolicies.length > 0) {
    lines.push(`  ${ui.authorizationEvidence}: ${authorizationPolicies.map(({ id }) => id).join(", ")}`);
  }

  const consequences = riskPolicies
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
