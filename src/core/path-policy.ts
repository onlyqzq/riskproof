// ============================================================================
// dsh-riskproof - sensitive path detection
// ============================================================================
// Paths are classified by normalized shape only. Evidence contains the field
// and category, never the operator's raw path.
// ============================================================================

import { argumentLeaves } from "./arguments.js";

export interface SensitivePathFinding {
  field: string;
  category: string;
}

const PATH_FIELD_ALIASES = new Set([
  "path", "filepath", "file", "filename", "source", "src", "target",
  "destination", "dest", "directory", "dir", "cwd", "workspace",
]);

const SAFE_ENV_TEMPLATES = /(?:^|\/)\.env\.(?:example|sample|template|dist|default)$/i;

const BUILTIN_SENSITIVE_PATHS: Array<{ category: string; pattern: RegExp }> = [
  { category: "environment secrets", pattern: /(?:^|\/)\.env(?:\.[^/]+)?$/i },
  { category: "Git credentials", pattern: /(?:^|\/)\.git-credentials$/i },
  { category: "network credentials", pattern: /(?:^|\/)\.(?:netrc|pgpass)$/i },
  { category: "package registry credentials", pattern: /(?:^|\/)\.(?:npmrc|pypirc)$/i },
  { category: "shell history", pattern: /(?:^|\/)\.(?:bash_history|zsh_history|python_history|mysql_history|psql_history)$/i },
  { category: "cloud credentials", pattern: /(?:^|\/)\.aws\/credentials$/i },
  { category: "cloud credentials", pattern: /(?:^|\/)\.config\/gcloud\/application_default_credentials\.json$/i },
  { category: "cloud credentials", pattern: /(?:^|\/)\.azure\/(?:accessTokens|azureProfile)\.json$/i },
  { category: "container registry credentials", pattern: /(?:^|\/)\.docker\/config\.json$/i },
  { category: "cluster credentials", pattern: /(?:^|\/)\.kube\/config$/i },
  { category: "developer service credentials", pattern: /(?:^|\/)\.config\/(?:gh\/hosts\.yml|glab-cli\/config\.yml)$/i },
  { category: "infrastructure credentials", pattern: /(?:^|\/)\.terraform\.d\/credentials\.tfrc\.json$/i },
  { category: "vault token", pattern: /(?:^|\/)\.vault-token$/i },
  { category: "process environment", pattern: /(?:^|\/)proc\/(?:self|\d+)\/environ$/i },
  { category: "SSH private key", pattern: /(?:^|\/)\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)$/i },
  { category: "private key or key store", pattern: /(?:^|\/)[^/]+\.(?:key|p12|pfx|jks|keystore|kdbx|ppk)$/i },
  { category: "service credentials", pattern: /(?:^|\/)(?:credentials|service-account\.json)$/i },
];

function normalizeFieldName(field: string): string {
  return field.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function normalizePathForPolicy(raw: string): string {
  let path = raw.trim().replace(/^(["'])(.*)\1$/, "$2");
  if (path.startsWith("file://")) path = path.slice("file://".length);
  path = path.replaceAll("\\", "/").replace(/\/{2,}/g, "/");
  const output: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") output.pop();
    else output.push(segment);
  }
  const prefix = path.startsWith("/") ? "/" : "";
  return prefix + output.join("/");
}

/** Match a small, safe glob vocabulary: `*`, `?`, and `**`. */
export function matchesPathPattern(path: string, pattern: string): boolean {
  return compilePathPattern(pattern).test(path);
}

function compilePathPattern(pattern: string): RegExp {
  const normalizedPattern = normalizePathForPolicy(pattern);
  let source = "";
  for (let index = 0; index < normalizedPattern.length; index += 1) {
    const char = normalizedPattern[index];
    if (char === "*") {
      if (normalizedPattern[index + 1] === "*") {
        source += ".*";
        index += 1;
      } else {
        source += "[^/]*";
      }
    } else if (char === "?") {
      source += "[^/]";
    } else {
      source += /[|\\{}()[\]^$+.]/.test(char) ? `\\${char}` : char;
    }
  }
  return new RegExp(`^${source}$`, "i");
}

export function findSensitivePaths(
  args: Record<string, unknown>,
  additionalPatterns: readonly string[] = [],
): SensitivePathFinding[] {
  const findings: SensitivePathFinding[] = [];
  const compiledAdditionalPatterns = additionalPatterns.map(compilePathPattern);
  for (const leaf of argumentLeaves(args)) {
    if (typeof leaf.value !== "string") continue;
    if (!PATH_FIELD_ALIASES.has(normalizeFieldName(leaf.field))) continue;
    const path = normalizePathForPolicy(leaf.value.slice(0, 4_096));
    if (!path || SAFE_ENV_TEMPLATES.test(path)) continue;

    const builtin = BUILTIN_SENSITIVE_PATHS.find(({ pattern }) => pattern.test(path));
    if (builtin) {
      findings.push({ field: leaf.path, category: builtin.category });
      continue;
    }
    if (compiledAdditionalPatterns.some((pattern) => pattern.test(path))) {
      findings.push({ field: leaf.path, category: "operator-configured sensitive path" });
    }
  }
  return findings;
}
