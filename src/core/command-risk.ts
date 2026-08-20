// ============================================================================
// dsh-riskproof - bounded, deterministic command-risk detection
// ============================================================================
// This is intentionally a high-confidence detector, not a shell parser. It
// recognizes operations whose risk is clear from a bounded command string and
// leaves ambiguous syntax to the configured unknown/destructive posture.
// ============================================================================

import { argumentLeaves } from "./arguments.js";

export type CommandRiskKind =
  | "catastrophic_operation"
  | "destructive_operation"
  | "remote_script_execution"
  | "network_egress";

export interface CommandRiskFinding {
  field: string;
  kind: CommandRiskKind;
  category: string;
}

const MAX_COMMAND_CHARS = 32_768;

const COMMAND_FIELD_ALIASES = new Set([
  "command", "cmd", "code", "script", "shell", "powershell", "pwsh",
  "bash", "zsh", "input", "program",
]);

const REMOTE_SCRIPT = /\b(?:curl|wget)\b[\s\S]{0,4096}\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|pwsh|powershell|python(?:3)?|node)\b/i;
const NETWORK_EGRESS = /\b(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|rsync|ssh|telnet)\b/i;
const CATASTROPHIC = [
  /\b(?:mkfs(?:\.[a-z0-9_-]+)?|wipefs)\b/i,
  /\bdd\b[\s\S]{0,2048}\bof\s*=\s*\/dev\/(?!null\b|zero\b|random\b|urandom\b)[^\s;&|]+/i,
  /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*;\s*\}\s*;\s*:/,
  /\brm\b[\s\S]{0,256}(?:-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive[\s\S]{0,64}--force|--force[\s\S]{0,64}--recursive)[\s\S]{0,256}(?:^|\s)(?:\/(?:\*|\.\*|\.\?\?\*)?|~(?:\/\*)?|\$HOME(?:\/\*)?|\$\{HOME\}(?:\/\*)?)(?=\s|$|[;&|])/i,
  /\bremove-item\b(?=[\s\S]{0,256}(?:-recurse|-r\b))(?=[\s\S]{0,256}(?:-force|-f\b))[\s\S]{0,256}\b[a-z]:\\(?:\*)?(?=\s|$|[;&|])/i,
];

const DESTRUCTIVE_PATTERNS: Array<{ category: string; pattern: RegExp }> = [
  { category: "recursive deletion", pattern: /\b(?:rm|rmdir|remove-item)\b[\s\S]{0,512}(?:-[a-z]*r|--recursive|\/s\b)/i },
  { category: "forced Git history rewrite", pattern: /\bgit\s+(?:push\b[\s\S]{0,256}(?:--force(?:-with-lease)?|-f\b)|reset\s+--hard\b|clean\b[\s\S]{0,128}(?:-[a-z]*f|--force)|branch\s+-D\b|stash\s+(?:drop|clear)\b)/i },
  { category: "discarding working-tree changes", pattern: /\bgit\s+(?:checkout\s+--\s+|restore\b|switch\s+--discard-changes\b)/i },
  { category: "bulk file deletion", pattern: /\bfind\b[\s\S]{0,1024}\s-delete\b/i },
  { category: "system power operation", pattern: /\b(?:shutdown|reboot|poweroff|halt)\b/i },
  { category: "privilege escalation", pattern: /(?:^|[;&|]\s*|\s)sudo\s+/i },
  { category: "unsafe permission change", pattern: /\bchmod\b[\s\S]{0,128}(?:777|a\+w)\b/i },
  { category: "opaque PowerShell command", pattern: /\b(?:powershell|pwsh)\b[\s\S]{0,128}-(?:encodedcommand|enc)\b/i },
  { category: "dynamic evaluation", pattern: /(?:^|[;&|]\s*|\s)eval\s+(?:\$|[`"'])/i },
];

function normalizeFieldName(field: string): string {
  return field.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Find high-confidence command risks without retaining command text. */
export function analyzeCommandRisks(args: Record<string, unknown>): CommandRiskFinding[] {
  const findings: CommandRiskFinding[] = [];
  for (const leaf of argumentLeaves(args)) {
    if (typeof leaf.value !== "string") continue;
    if (!COMMAND_FIELD_ALIASES.has(normalizeFieldName(leaf.field))) continue;
    const command = leaf.value.slice(0, MAX_COMMAND_CHARS);

    if (CATASTROPHIC.some((pattern) => pattern.test(command))) {
      findings.push({ field: leaf.path, kind: "catastrophic_operation", category: "irreversible system damage" });
    }
    if (REMOTE_SCRIPT.test(command)) {
      findings.push({ field: leaf.path, kind: "remote_script_execution", category: "download-and-execute pipeline" });
    }
    for (const { category, pattern } of DESTRUCTIVE_PATTERNS) {
      if (pattern.test(command)) {
        findings.push({ field: leaf.path, kind: "destructive_operation", category });
      }
    }
    if (NETWORK_EGRESS.test(command)) {
      findings.push({ field: leaf.path, kind: "network_egress", category: "network-capable command" });
    }
  }
  return dedupeFindings(findings);
}

function dedupeFindings(findings: CommandRiskFinding[]): CommandRiskFinding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.field}\0${finding.kind}\0${finding.category}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
