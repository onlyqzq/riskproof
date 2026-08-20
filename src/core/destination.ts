// ============================================================================
// dsh-riskproof — external destination detection
// ============================================================================
// For EXTERNAL_ACTION tools, determine whether an argument targets an external
// sink (an email domain or URL host outside the configured internal domains).
// Only recognized sink fields are inspected, so a URL mentioned inside a
// message body is not mistaken for the actual destination.
// ============================================================================

import { argumentLeaves } from "./arguments.js";

export interface ExternalDestination {
  field: string;
  target: string;
  kind: "email" | "url";
}

export type NetworkDestination = ExternalDestination;

const EMAIL_RECIPIENT_FIELD_ALIASES = new Set([
  "to", "cc", "bcc", "mailto",
  "recipient", "recipients", "recipientlist",
  "email", "emails", "address", "addresses", "target", "targets",
  "recipientemail", "recipientemails", "recipientaddress", "recipientaddresses",
  "emailaddress", "emailaddresses", "targetemail", "targetemails",
  "targetaddress", "targetaddresses", "toemail", "toemails", "toaddress", "toaddresses",
]);

const URL_TARGET_FIELD_ALIASES = new Set([
  "url", "uri", "endpoint", "targeturl", "targeturi", "targetendpoint",
  "webhook", "webhookurl", "webhookuri", "requesturl", "requesturi",
  "destination", "destinationurl", "destinationuri", "callbackurl", "callbackuri",
  "baseurl", "apiendpoint", "host", "hostname", "origin", "channel", "topic",
]);

function normalizeFieldName(field: string): string {
  return field.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function normalizeHost(host: string): string {
  return host.toLowerCase().trim().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
}

/** Exact domain/IP or suffix match. `*.example.com` also admits the base. */
export function matchesDomainPattern(host: string, pattern: string): boolean {
  const lower = normalizeHost(host);
  const normalized = normalizeHost(pattern.replace(/^\*\./, ""));
  if (!normalized) return false;
  return lower === normalized || lower.endsWith(`.${normalized}`);
}

/** Extract email domains from a value. */
export function extractEmailDomains(value: unknown): string[] {
  const text = valueToText(value);
  if (!text) return [];
  const domains = new Set<string>();
  const email = /@[\s]*([a-zA-Z0-9.-]+|\[[0-9a-fA-F:.]+\])/g;
  for (const match of text.matchAll(email)) {
    const domain = match[1].replace(/^\[|\]$/g, "").replace(/\.+$/, "").toLowerCase();
    if (domain.includes(".") || domain === "localhost") domains.add(domain);
  }
  return [...domains];
}

function extractUrlHosts(value: unknown): string[] {
  const text = valueToText(value);
  if (!text) return [];
  const hosts = new Set<string>();
  const urls = text.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  for (const raw of urls) {
    try {
      hosts.add(normalizeHost(new URL(raw.replace(/[),.;}\]]+$/, "")).hostname));
    } catch {
      // invalid URL: left to the downstream tool's own schema validation
    }
  }
  return [...hosts];
}

/** Extract network hosts from a value (full URLs and bare host strings). */
export function extractHosts(value: unknown): string[] {
  const hosts = new Set(extractUrlHosts(value));
  if (typeof value !== "string") return [...hosts];
  const candidate = value.trim().replace(/^["']|["']$/g, "");
  if (!candidate || /\s/.test(candidate)) return [...hosts];
  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(candidate);
    const parsed = new URL(hasScheme ? candidate : `http://${candidate}`);
    const host = normalizeHost(parsed.hostname);
    // Do not reinterpret ordinary sink values such as channel="general" as
    // hosts. Explicit URLs remain valid even with a single-label host.
    if (hasScheme || host.includes(".") || host.includes(":") || host === "localhost") {
      hosts.add(host);
    }
  } catch {
    // not a parseable target; left to downstream validation
  }
  return [...hosts];
}

function valueToText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  try {
    const serialized = JSON.stringify(value);
    return serialized === undefined ? "" : serialized;
  } catch {
    return "";
  }
}

/** Whether a host is outside the internal domain allowlist. */
export function isExternalDomain(host: string, internalDomains?: string[]): boolean {
  const lower = normalizeHost(host);
  if (["localhost", "127.0.0.1", "::1", "0.0.0.0"].includes(lower)) return false;
  if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(lower)) return false;
  if (!internalDomains?.length) return true;
  return !internalDomains.some((domain) => matchesDomainPattern(lower, domain));
}

/** Whether a host is a cloud metadata or link-local endpoint (never reachable). */
export function isCloudMetadataOrLinkLocalHost(host: string): boolean {
  const lower = normalizeHost(host).replace(/%25[^:]+$/i, "");
  const ipv4 = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const octets = ipv4.slice(1).map(Number);
    if (octets.every((octet) => octet <= 255)) {
      if (octets[0] === 169 && octets[1] === 254) return true;
      if ([
        "100.100.100.200",
        "192.0.0.192",
        "168.63.129.16",
      ].includes(lower)) return true;
    }
  }
  if (/^fe[89ab][0-9a-f]:/i.test(lower)) return true;
  if (lower === "fd00:ec2::254") return true;
  if (lower.startsWith("::ffff:")) {
    return isCloudMetadataOrLinkLocalHost(lower.slice("::ffff:".length));
  }
  return [
    "metadata.google.internal",
    "metadata.goog",
    "instance-data.ec2.internal",
    "metadata.azure.internal",
  ].some((metadataHost) => lower === metadataHost || lower.endsWith(`.${metadataHost}`));
}

/**
 * Find external email/URL destinations in recognized sink fields. Sink fields
 * are matched by normalized alias, so a URL in an ordinary body is ignored.
 */
export function findExternalDestinations(
  args: Record<string, unknown>,
  internalDomains?: string[],
): ExternalDestination[] {
  return findDestinations(args).filter((destination) =>
    isExternalDomain(destination.target, internalDomains));
}

/** Find every recognized email/URL destination, regardless of trust policy. */
export function findDestinations(
  args: Record<string, unknown>,
): NetworkDestination[] {
  const destinations: ExternalDestination[] = [];
  for (const leaf of argumentLeaves(args)) {
    const field = normalizeFieldName(leaf.field);
    if (EMAIL_RECIPIENT_FIELD_ALIASES.has(field)) {
      for (const domain of extractEmailDomains(leaf.value)) {
        destinations.push({ field: leaf.path, target: domain, kind: "email" });
      }
    }
    if (URL_TARGET_FIELD_ALIASES.has(field)) {
      for (const host of extractHosts(leaf.value)) {
        destinations.push({ field: leaf.path, target: host, kind: "url" });
      }
    }
  }
  return destinations;
}
