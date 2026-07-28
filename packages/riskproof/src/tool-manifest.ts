// ============================================================================
// RiskProof — scoped ToolKey identities and signed pinned manifests
// ============================================================================
//
// A bare MCP tool name is not a globally meaningful identity. This module
// scopes tool identity to provider + server + tool and binds that ToolKey to a
// complete descriptor digest in a versioned, persistable manifest.
//
// Signed envelopes support two deliberately different trust models:
//   - Ed25519: verifies possession of the private key corresponding to an
//     operator-pinned public key. The operator remains responsible for binding
//     that key to a publisher/provider identity.
//   - HMAC-SHA256: verifies integrity and membership in a shared-secret trust
//     domain. Any secret holder can forge an envelope; it is not publisher
//     attribution or non-repudiation.
//
// Parsing is strict and bounded. Untrusted objects must be plain, data-only,
// accessor-free, Proxy-free JSON structures with no unknown fields. Successful
// signature verification returns a snapshot-backed reference object whose
// verifyTool() method fails closed and rechecks manifest expiry on every call.

import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  KeyObject,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
} from "node:crypto";
import { types as utilTypes } from "node:util";

export const TOOL_MANIFEST_VERSION = 1 as const;
export const TOOL_MANIFEST_ENVELOPE_VERSION = 1 as const;
export const TOOL_KEY_CANONICAL_PREFIX = "riskproof-tool-key:v1:";

export const TOOL_MANIFEST_LIMITS = Object.freeze({
  maxProviderIdBytes: 256,
  maxServerIdBytes: 256,
  maxToolNameBytes: 512,
  maxMetadataStringBytes: 2_048,
  maxTools: 512,
  maxManifestBytes: 2 * 1024 * 1024,
  maxEnvelopeBytes: 2 * 1024 * 1024 + 16 * 1024,
  maxTrustAnchors: 64,
  maxDiagnostics: 1_024,
  maxClockSkewMs: 5 * 60 * 1_000,
  maxHmacKeyBytes: 4_096,
});

const SHA256_DIGEST = /^[a-f0-9]{64}$/;
const OCI_SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;
const PACKAGE_ECOSYSTEM = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UTC_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
const SIGNATURE_DOMAIN = "riskproof.signed-pinned-tool-manifest.v1";

export interface ToolKey {
  providerId: string;
  serverId: string;
  toolName: string;
}

export interface ToolPackageMetadata {
  /** Lowercase package ecosystem identifier, for example npm, pypi, or cargo. */
  ecosystem: string;
  name: string;
  version: string;
  /** Optional SHA-256 commitment to the resolved package artifact. */
  artifactDigest?: string;
}

export interface ToolContainerMetadata {
  /** Registry/repository reference without treating a mutable tag as identity. */
  image: string;
  /** Immutable OCI-style digest. Only sha256 is accepted in manifest v1. */
  digest: string;
}

export interface ToolPublisherMetadata {
  /** Publisher identifier asserted by the signed manifest. */
  id: string;
  displayName?: string;
  /** Optional canonical HTTPS information/identity URL. */
  uri?: string;
}

export interface PinnedToolManifestEntryV1 {
  toolKey: ToolKey;
  /** SHA-256 over the complete canonical MCP tool descriptor. */
  descriptorDigest: string;
  package?: ToolPackageMetadata;
  container?: ToolContainerMetadata;
  publisher?: ToolPublisherMetadata;
}

export interface PinnedToolManifestV1 {
  manifestVersion: typeof TOOL_MANIFEST_VERSION;
  issuedAt: string;
  expiresAt: string;
  tools: readonly PinnedToolManifestEntryV1[];
}

export type ToolManifestSignatureAlgorithm = "Ed25519" | "HMAC-SHA256";

export interface SignedPinnedToolManifestEnvelopeV1 {
  envelopeVersion: typeof TOOL_MANIFEST_ENVELOPE_VERSION;
  algorithm: ToolManifestSignatureAlgorithm;
  keyId: string;
  manifestDigest: string;
  manifest: PinnedToolManifestV1;
  /** Canonical unpadded base64url signature/MAC. */
  signature: string;
}

export type Ed25519KeyMaterial = string | Uint8Array | KeyObject;
export type HmacKeyMaterial = Uint8Array | KeyObject;

export interface Ed25519ManifestTrustAnchor {
  algorithm: "Ed25519";
  keyId: string;
  publicKey: Ed25519KeyMaterial;
}

export interface HmacManifestTrustAnchor {
  algorithm: "HMAC-SHA256";
  keyId: string;
  secret: HmacKeyMaterial;
}

export type ManifestTrustAnchor = Ed25519ManifestTrustAnchor | HmacManifestTrustAnchor;

export interface Ed25519ManifestSigner {
  algorithm: "Ed25519";
  keyId: string;
  privateKey: Ed25519KeyMaterial;
}

export interface HmacManifestSigner {
  algorithm: "HMAC-SHA256";
  keyId: string;
  secret: HmacKeyMaterial;
}

export type ManifestSigner = Ed25519ManifestSigner | HmacManifestSigner;

export type ManifestTrustSemantics =
  | "operator-pinned-public-key"
  | "shared-secret-domain";

export type ManifestVerificationCode =
  | "manifest_verified"
  | "malformed_json"
  | "envelope_schema_invalid"
  | "unsupported_envelope_version"
  | "unsupported_manifest_version"
  | "unsupported_signature_algorithm"
  | "manifest_schema_invalid"
  | "manifest_digest_mismatch"
  | "manifest_expired"
  | "manifest_not_yet_valid"
  | "unknown_key_id"
  | "key_algorithm_mismatch"
  | "signature_invalid"
  | "verifier_clock_invalid";

export interface ManifestVerificationDiagnostic {
  sequence: number;
  outcome: "verified" | "denied";
  code: ManifestVerificationCode;
  /** Fixed, non-input-derived explanation. */
  reason: string;
  observedAt?: string;
  algorithm?: ToolManifestSignatureAlgorithm;
  keyId?: string;
  manifestDigest?: string;
  expiresAt?: string;
  toolCount?: number;
  trustSemantics?: ManifestTrustSemantics;
}

export type ToolBindingVerificationCode =
  | "tool_binding_verified"
  | "tool_not_pinned"
  | "tool_descriptor_mismatch"
  | "manifest_expired"
  | "tool_verification_input_invalid"
  | "verifier_clock_invalid";

export interface ToolBindingVerificationResult {
  verified: boolean;
  decision: "allow" | "deny";
  code: ToolBindingVerificationCode;
  toolKeyDigest?: string;
  expectedDescriptorDigest?: string;
  observedDescriptorDigest?: string;
  manifestDigest: string;
}

export interface VerifiedPinnedToolManifestSummary {
  manifestVersion: typeof TOOL_MANIFEST_VERSION;
  algorithm: ToolManifestSignatureAlgorithm;
  keyId: string;
  manifestDigest: string;
  issuedAt: string;
  expiresAt: string;
  toolCount: number;
  trustSemantics: ManifestTrustSemantics;
}

export type SignedManifestVerificationResult =
  | {
      verified: true;
      value: VerifiedPinnedToolManifest;
      diagnostic: ManifestVerificationDiagnostic;
    }
  | {
      verified: false;
      diagnostic: ManifestVerificationDiagnostic;
    };

export interface PinnedToolManifestVerifierOptions {
  /** Trusted host clock. Never source this from the envelope or MCP content. */
  clock?: () => Date;
  maxClockSkewMs?: number;
  maxDiagnostics?: number;
  maxTools?: number;
  maxManifestBytes?: number;
  maxEnvelopeBytes?: number;
}

interface NormalizedParseLimits {
  maxTools: number;
  maxManifestBytes: number;
  maxEnvelopeBytes: number;
}

interface NormalizedVerifierOptions extends NormalizedParseLimits {
  clock: () => Date;
  maxClockSkewMs: number;
  maxDiagnostics: number;
}

interface NormalizedEd25519Anchor {
  algorithm: "Ed25519";
  keyId: string;
  publicKey: KeyObject;
}

interface NormalizedHmacAnchor {
  algorithm: "HMAC-SHA256";
  keyId: string;
  secret: Uint8Array | KeyObject;
}

type NormalizedTrustAnchor = NormalizedEd25519Anchor | NormalizedHmacAnchor;

/**
 * Parse and snapshot a provider/server/tool identity.
 *
 * Identity components are exact, NFC-normalized strings. They are not case
 * folded: providers must define case semantics before issuing a manifest.
 */
export function parseToolKey(raw: unknown): Readonly<ToolKey> {
  const record = ownDataRecord(raw, "ToolKey", "manifest_schema_invalid");
  assertOnlyKeys(record, ["providerId", "serverId", "toolName"], "ToolKey", "manifest_schema_invalid");
  return Object.freeze({
    providerId: identityComponent(
      record.providerId,
      "ToolKey.providerId",
      TOOL_MANIFEST_LIMITS.maxProviderIdBytes,
    ),
    serverId: identityComponent(
      record.serverId,
      "ToolKey.serverId",
      TOOL_MANIFEST_LIMITS.maxServerIdBytes,
    ),
    toolName: identityComponent(
      record.toolName,
      "ToolKey.toolName",
      TOOL_MANIFEST_LIMITS.maxToolNameBytes,
    ),
  });
}

/** Unambiguous, printable canonical identity using canonical base64url parts. */
export function canonicalizeToolKey(raw: unknown): string {
  const key = parseToolKey(raw);
  return `${TOOL_KEY_CANONICAL_PREFIX}${base64urlUtf8(key.providerId)}.${base64urlUtf8(key.serverId)}.${base64urlUtf8(key.toolName)}`;
}

export function parseCanonicalToolKey(value: string): Readonly<ToolKey> {
  if (typeof value !== "string" || !value.startsWith(TOOL_KEY_CANONICAL_PREFIX)) {
    throw new TypeError("canonical ToolKey has an unsupported format or version");
  }
  const parts = value.slice(TOOL_KEY_CANONICAL_PREFIX.length).split(".");
  if (parts.length !== 3) throw new TypeError("canonical ToolKey must contain exactly three components");
  const decoded = parts.map((part, index) => decodeCanonicalBase64url(part, index));
  const key = parseToolKey({
    providerId: decoded[0],
    serverId: decoded[1],
    toolName: decoded[2],
  });
  if (canonicalizeToolKey(key) !== value) throw new TypeError("canonical ToolKey is not canonical");
  return key;
}

export function digestToolKey(raw: unknown): string {
  return sha256(canonicalizeToolKey(raw));
}

/** Parse either JSON text or a strict JSON-like object into an immutable v1 manifest. */
export function parsePinnedToolManifest(
  input: unknown,
  options: Pick<PinnedToolManifestVerifierOptions, "maxTools" | "maxManifestBytes"> = {},
): Readonly<PinnedToolManifestV1> {
  const limits = normalizeParseLimits(options);
  const raw = typeof input === "string"
    ? parseJsonText(input, limits.maxManifestBytes, "manifest")
    : input;
  return normalizeManifest(raw, limits);
}

export function canonicalizePinnedToolManifest(
  input: unknown,
  options: Pick<PinnedToolManifestVerifierOptions, "maxTools" | "maxManifestBytes"> = {},
): string {
  const limits = normalizeParseLimits(options);
  const manifest = parsePinnedToolManifest(input, limits);
  const canonical = stableJson(manifest);
  enforceUtf8ByteLimit(canonical, limits.maxManifestBytes, "manifest", "manifest_schema_invalid");
  return canonical;
}

export function digestPinnedToolManifest(
  input: unknown,
  options: Pick<PinnedToolManifestVerifierOptions, "maxTools" | "maxManifestBytes"> = {},
): string {
  return sha256(canonicalizePinnedToolManifest(input, options));
}

/** Parse a persistable envelope without treating it as trusted. */
export function parseSignedPinnedToolManifestEnvelope(
  input: unknown,
  options: Pick<
    PinnedToolManifestVerifierOptions,
    "maxTools" | "maxManifestBytes" | "maxEnvelopeBytes"
  > = {},
): Readonly<SignedPinnedToolManifestEnvelopeV1> {
  const limits = normalizeParseLimits(options);
  const raw = typeof input === "string"
    ? parseJsonText(input, limits.maxEnvelopeBytes, "envelope")
    : input;
  return normalizeEnvelope(raw, limits);
}

/** Deterministic JSON suitable for writing the signed envelope to disk. */
export function serializeSignedPinnedToolManifestEnvelope(
  input: unknown,
  options: Pick<
    PinnedToolManifestVerifierOptions,
    "maxTools" | "maxManifestBytes" | "maxEnvelopeBytes"
  > = {},
): string {
  const limits = normalizeParseLimits(options);
  const envelope = parseSignedPinnedToolManifestEnvelope(input, limits);
  const canonical = stableJson(envelope);
  enforceUtf8ByteLimit(canonical, limits.maxEnvelopeBytes, "envelope", "envelope_schema_invalid");
  return canonical;
}

/** Create a signed snapshot. Signing does not itself assert that it is unexpired. */
export function signPinnedToolManifest(
  manifestInput: unknown,
  signerInput: ManifestSigner,
  options: Pick<PinnedToolManifestVerifierOptions, "maxTools" | "maxManifestBytes"> = {},
): Readonly<SignedPinnedToolManifestEnvelopeV1> {
  const limits = normalizeParseLimits(options);
  const manifest = parsePinnedToolManifest(manifestInput, limits);
  const manifestDigest = sha256(stableJson(manifest));
  const signer = normalizeSigner(signerInput);
  const payload = signaturePayload(signer.algorithm, signer.keyId, manifestDigest);
  const signatureBytes = signer.algorithm === "Ed25519"
    ? cryptoSign(null, payload, signer.privateKey)
    : createHmac("sha256", signer.secret).update(payload).digest();
  return freezeEnvelope({
    envelopeVersion: TOOL_MANIFEST_ENVELOPE_VERSION,
    algorithm: signer.algorithm,
    keyId: signer.keyId,
    manifestDigest,
    manifest,
    signature: signatureBytes.toString("base64url"),
  });
}

/**
 * The only object authorized to turn a signed manifest into per-tool allows.
 * Construction is guarded at runtime by an unexported module token and only
 * follows successful envelope verification.
 */
export class VerifiedPinnedToolManifest {
  public readonly manifestDigest: string;
  public readonly keyId: string;
  public readonly algorithm: ToolManifestSignatureAlgorithm;
  public readonly trustSemantics: ManifestTrustSemantics;
  public readonly issuedAt: string;
  public readonly expiresAt: string;
  public readonly toolCount: number;

  readonly #expiresAtMs: number;
  readonly #clock: () => Date;
  readonly #entries = new Map<string, PinnedToolManifestEntryV1>();

  /** @internal Only the module-held verification token can authorize construction. */
  constructor(
    envelope: Readonly<SignedPinnedToolManifestEnvelopeV1>,
    clock: () => Date,
    token: symbol,
  ) {
    if (token !== VERIFIED_CONSTRUCTION_TOKEN) {
      throw new TypeError("VerifiedPinnedToolManifest requires successful signature verification");
    }
    this.manifestDigest = envelope.manifestDigest;
    this.keyId = envelope.keyId;
    this.algorithm = envelope.algorithm;
    this.trustSemantics = trustSemantics(envelope.algorithm);
    this.issuedAt = envelope.manifest.issuedAt;
    this.expiresAt = envelope.manifest.expiresAt;
    this.#expiresAtMs = Date.parse(envelope.manifest.expiresAt);
    this.toolCount = envelope.manifest.tools.length;
    this.#clock = clock;
    for (const entry of envelope.manifest.tools) {
      this.#entries.set(canonicalizeToolKey(entry.toolKey), entry);
    }
    Object.freeze(this);
  }

  getSummary(): Readonly<VerifiedPinnedToolManifestSummary> {
    return Object.freeze({
      manifestVersion: TOOL_MANIFEST_VERSION,
      algorithm: this.algorithm,
      keyId: this.keyId,
      manifestDigest: this.manifestDigest,
      issuedAt: this.issuedAt,
      expiresAt: this.expiresAt,
      toolCount: this.toolCount,
      trustSemantics: this.trustSemantics,
    });
  }

  /**
   * Fail-closed exact binding check. Diagnostics contain only digests, never
   * raw provider/server/tool names or package/publisher metadata.
   */
  verifyTool(toolKeyInput: unknown, descriptorDigestInput: unknown): ToolBindingVerificationResult {
    let now: Date;
    try {
      now = validClockValue(this.#clock());
    } catch {
      return this.toolDenial("verifier_clock_invalid");
    }
    if (now.getTime() >= this.#expiresAtMs) return this.toolDenial("manifest_expired");

    let canonicalKey: string;
    let keyDigest: string;
    let observedDigest: string;
    try {
      canonicalKey = canonicalizeToolKey(toolKeyInput);
      keyDigest = sha256(canonicalKey);
      observedDigest = sha256Digest(descriptorDigestInput, "descriptorDigest", "manifest_schema_invalid");
    } catch {
      return this.toolDenial("tool_verification_input_invalid");
    }

    const entry = this.#entries.get(canonicalKey);
    if (!entry) {
      return this.toolDenial("tool_not_pinned", {
        toolKeyDigest: keyDigest,
        observedDescriptorDigest: observedDigest,
      });
    }
    if (entry.descriptorDigest !== observedDigest) {
      return this.toolDenial("tool_descriptor_mismatch", {
        toolKeyDigest: keyDigest,
        expectedDescriptorDigest: entry.descriptorDigest,
        observedDescriptorDigest: observedDigest,
      });
    }
    return {
      verified: true,
      decision: "allow",
      code: "tool_binding_verified",
      toolKeyDigest: keyDigest,
      expectedDescriptorDigest: entry.descriptorDigest,
      observedDescriptorDigest: observedDigest,
      manifestDigest: this.manifestDigest,
    };
  }

  private toolDenial(
    code: Exclude<ToolBindingVerificationCode, "tool_binding_verified">,
    metadata: Pick<
      ToolBindingVerificationResult,
      "toolKeyDigest" | "expectedDescriptorDigest" | "observedDescriptorDigest"
    > = {},
  ): ToolBindingVerificationResult {
    return {
      verified: false,
      decision: "deny",
      code,
      ...metadata,
      manifestDigest: this.manifestDigest,
    };
  }
}

const VERIFIED_CONSTRUCTION_TOKEN = Symbol("verified-pinned-tool-manifest");

/** Stateful verifier with a bounded, metadata-only diagnostic history. */
export class PinnedToolManifestVerifier {
  readonly #anchors = new Map<string, NormalizedTrustAnchor>();
  readonly #options: NormalizedVerifierOptions;
  readonly #diagnostics: ManifestVerificationDiagnostic[] = [];
  #nextSequence = 0;

  constructor(
    anchorsInput: readonly ManifestTrustAnchor[],
    optionsInput: PinnedToolManifestVerifierOptions = {},
  ) {
    this.#options = normalizeVerifierOptions(optionsInput);
    for (const anchor of normalizeTrustAnchors(anchorsInput)) {
      this.#anchors.set(anchor.keyId, anchor);
    }
  }

  /** Verify untrusted JSON/object input. Envelope failures return deny, never allow. */
  verify(input: unknown): SignedManifestVerificationResult {
    let observedAt: string | undefined;
    try {
      observedAt = validClockValue(this.#options.clock()).toISOString();
    } catch {
      return this.denied("verifier_clock_invalid");
    }

    let envelope: Readonly<SignedPinnedToolManifestEnvelopeV1>;
    try {
      envelope = parseSignedPinnedToolManifestEnvelope(input, this.#options);
    } catch (error) {
      return this.denied(inputErrorCode(error), { observedAt });
    }

    const metadata = {
      observedAt,
      algorithm: envelope.algorithm,
      keyId: envelope.keyId,
      manifestDigest: envelope.manifestDigest,
      expiresAt: envelope.manifest.expiresAt,
      toolCount: envelope.manifest.tools.length,
    } as const;
    const actualDigest = sha256(stableJson(envelope.manifest));
    if (!constantTimeTextEqual(actualDigest, envelope.manifestDigest)) {
      return this.denied("manifest_digest_mismatch", metadata);
    }

    const nowMs = Date.parse(observedAt);
    const issuedAtMs = Date.parse(envelope.manifest.issuedAt);
    const expiresAtMs = Date.parse(envelope.manifest.expiresAt);
    if (issuedAtMs > nowMs + this.#options.maxClockSkewMs) {
      return this.denied("manifest_not_yet_valid", metadata);
    }
    if (nowMs >= expiresAtMs) return this.denied("manifest_expired", metadata);

    const anchor = this.#anchors.get(envelope.keyId);
    if (!anchor) return this.denied("unknown_key_id", metadata);
    if (anchor.algorithm !== envelope.algorithm) {
      return this.denied("key_algorithm_mismatch", metadata);
    }

    const payload = signaturePayload(
      envelope.algorithm,
      envelope.keyId,
      envelope.manifestDigest,
    );
    const signature = Buffer.from(envelope.signature, "base64url");
    let signatureValid = false;
    try {
      signatureValid = anchor.algorithm === "Ed25519"
        ? cryptoVerify(null, payload, anchor.publicKey, signature)
        : constantTimeBytesEqual(
            createHmac("sha256", anchor.secret).update(payload).digest(),
            signature,
          );
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) return this.denied("signature_invalid", metadata);

    const trust = trustSemantics(envelope.algorithm);
    const diagnostic = this.record({
      outcome: "verified",
      code: "manifest_verified",
      reason: diagnosticReason("manifest_verified"),
      ...metadata,
      trustSemantics: trust,
    });
    return {
      verified: true,
      value: new VerifiedPinnedToolManifest(
        envelope,
        this.#options.clock,
        VERIFIED_CONSTRUCTION_TOKEN,
      ),
      diagnostic,
    };
  }

  /** Metadata only: no ToolKey strings, package names, images, or publisher data. */
  listDiagnostics(): ManifestVerificationDiagnostic[] {
    return this.#diagnostics.map(cloneDiagnostic);
  }

  private denied(
    code: Exclude<ManifestVerificationCode, "manifest_verified">,
    metadata: Omit<
      ManifestVerificationDiagnostic,
      "sequence" | "outcome" | "code" | "reason"
    > = {},
  ): SignedManifestVerificationResult {
    return {
      verified: false,
      diagnostic: this.record({
        outcome: "denied",
        code,
        reason: diagnosticReason(code),
        ...metadata,
      }),
    };
  }

  private record(
    diagnostic: Omit<ManifestVerificationDiagnostic, "sequence">,
  ): ManifestVerificationDiagnostic {
    const recorded: ManifestVerificationDiagnostic = {
      sequence: ++this.#nextSequence,
      ...diagnostic,
    };
    this.#diagnostics.push(recorded);
    while (this.#diagnostics.length > this.#options.maxDiagnostics) this.#diagnostics.shift();
    return cloneDiagnostic(recorded);
  }
}

/** Stateless convenience wrapper; construct a verifier to retain diagnostics. */
export function verifySignedPinnedToolManifest(
  input: unknown,
  anchors: readonly ManifestTrustAnchor[],
  options: PinnedToolManifestVerifierOptions = {},
): SignedManifestVerificationResult {
  return new PinnedToolManifestVerifier(anchors, options).verify(input);
}

function normalizeManifest(
  raw: unknown,
  limits: NormalizedParseLimits,
): Readonly<PinnedToolManifestV1> {
  const record = ownDataRecord(raw, "PinnedToolManifest", "manifest_schema_invalid");
  assertOnlyKeys(
    record,
    ["manifestVersion", "issuedAt", "expiresAt", "tools"],
    "PinnedToolManifest",
    "manifest_schema_invalid",
  );
  if (record.manifestVersion !== TOOL_MANIFEST_VERSION) {
    throw new SecurityInputError(
      "unsupported_manifest_version",
      `manifestVersion must equal ${TOOL_MANIFEST_VERSION}`,
    );
  }
  const issuedAt = utcDateTime(record.issuedAt, "issuedAt");
  const expiresAt = utcDateTime(record.expiresAt, "expiresAt");
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)) {
    throw new SecurityInputError("manifest_schema_invalid", "expiresAt must be later than issuedAt");
  }
  const toolsRaw = strictArray(record.tools, "tools", "manifest_schema_invalid", limits.maxTools);
  if (toolsRaw.length === 0 || toolsRaw.length > limits.maxTools) {
    throw new SecurityInputError(
      "manifest_schema_invalid",
      `tools must contain between 1 and ${limits.maxTools} entries`,
    );
  }

  const seen = new Set<string>();
  const tools = toolsRaw.map((rawEntry, index) => {
    const entry = normalizeManifestEntry(rawEntry, index);
    const canonicalKey = canonicalizeToolKey(entry.toolKey);
    if (seen.has(canonicalKey)) {
      throw new SecurityInputError("manifest_schema_invalid", "manifest contains a duplicate ToolKey");
    }
    seen.add(canonicalKey);
    return entry;
  }).sort((left, right) => compareCodeUnits(
    canonicalizeToolKey(left.toolKey),
    canonicalizeToolKey(right.toolKey),
  ));

  const manifest = Object.freeze({
    manifestVersion: TOOL_MANIFEST_VERSION,
    issuedAt,
    expiresAt,
    tools: Object.freeze(tools),
  });
  enforceUtf8ByteLimit(
    stableJson(manifest),
    limits.maxManifestBytes,
    "manifest",
    "manifest_schema_invalid",
  );
  return manifest;
}

function normalizeManifestEntry(raw: unknown, index: number): Readonly<PinnedToolManifestEntryV1> {
  const label = `tools[${index}]`;
  const record = ownDataRecord(raw, label, "manifest_schema_invalid");
  assertOnlyKeys(
    record,
    ["toolKey", "descriptorDigest", "package", "container", "publisher"],
    label,
    "manifest_schema_invalid",
  );
  const toolKey = parseToolKey(record.toolKey);
  const descriptorDigest = sha256Digest(
    record.descriptorDigest,
    `${label}.descriptorDigest`,
    "manifest_schema_invalid",
  );
  const packageMetadata = record.package === undefined
    ? undefined
    : normalizePackageMetadata(record.package, `${label}.package`);
  const container = record.container === undefined
    ? undefined
    : normalizeContainerMetadata(record.container, `${label}.container`);
  const publisher = record.publisher === undefined
    ? undefined
    : normalizePublisherMetadata(record.publisher, `${label}.publisher`);
  return Object.freeze({
    toolKey,
    descriptorDigest,
    ...(packageMetadata ? { package: packageMetadata } : {}),
    ...(container ? { container } : {}),
    ...(publisher ? { publisher } : {}),
  });
}

function normalizePackageMetadata(raw: unknown, label: string): Readonly<ToolPackageMetadata> {
  const record = ownDataRecord(raw, label, "manifest_schema_invalid");
  assertOnlyKeys(record, ["ecosystem", "name", "version", "artifactDigest"], label, "manifest_schema_invalid");
  const ecosystem = boundedMetadataString(record.ecosystem, `${label}.ecosystem`, 64);
  if (!PACKAGE_ECOSYSTEM.test(ecosystem)) {
    throw new SecurityInputError("manifest_schema_invalid", `${label}.ecosystem has an invalid format`);
  }
  const name = boundedMetadataString(record.name, `${label}.name`, 512);
  const version = boundedMetadataString(record.version, `${label}.version`, 256);
  const artifactDigest = record.artifactDigest === undefined
    ? undefined
    : sha256Digest(record.artifactDigest, `${label}.artifactDigest`, "manifest_schema_invalid");
  return Object.freeze({
    ecosystem,
    name,
    version,
    ...(artifactDigest ? { artifactDigest } : {}),
  });
}

function normalizeContainerMetadata(raw: unknown, label: string): Readonly<ToolContainerMetadata> {
  const record = ownDataRecord(raw, label, "manifest_schema_invalid");
  assertOnlyKeys(record, ["image", "digest"], label, "manifest_schema_invalid");
  const image = boundedMetadataString(record.image, `${label}.image`, 1_024);
  if (typeof record.digest !== "string" || !OCI_SHA256_DIGEST.test(record.digest)) {
    throw new SecurityInputError(
      "manifest_schema_invalid",
      `${label}.digest must be a lowercase OCI sha256 digest`,
    );
  }
  return Object.freeze({ image, digest: record.digest });
}

function normalizePublisherMetadata(raw: unknown, label: string): Readonly<ToolPublisherMetadata> {
  const record = ownDataRecord(raw, label, "manifest_schema_invalid");
  assertOnlyKeys(record, ["id", "displayName", "uri"], label, "manifest_schema_invalid");
  const id = boundedMetadataString(record.id, `${label}.id`, 512);
  const displayName = record.displayName === undefined
    ? undefined
    : boundedMetadataString(record.displayName, `${label}.displayName`, 512);
  const uri = record.uri === undefined ? undefined : canonicalHttpsUrl(record.uri, `${label}.uri`);
  return Object.freeze({
    id,
    ...(displayName ? { displayName } : {}),
    ...(uri ? { uri } : {}),
  });
}

function normalizeEnvelope(
  raw: unknown,
  limits: NormalizedParseLimits,
): Readonly<SignedPinnedToolManifestEnvelopeV1> {
  const record = ownDataRecord(raw, "SignedPinnedToolManifestEnvelope", "envelope_schema_invalid");
  assertOnlyKeys(
    record,
    ["envelopeVersion", "algorithm", "keyId", "manifestDigest", "manifest", "signature"],
    "SignedPinnedToolManifestEnvelope",
    "envelope_schema_invalid",
  );
  if (record.envelopeVersion !== TOOL_MANIFEST_ENVELOPE_VERSION) {
    throw new SecurityInputError(
      "unsupported_envelope_version",
      `envelopeVersion must equal ${TOOL_MANIFEST_ENVELOPE_VERSION}`,
    );
  }
  const algorithm = signatureAlgorithm(record.algorithm);
  const keyId = signingKeyId(record.keyId);
  const manifestDigest = sha256Digest(
    record.manifestDigest,
    "manifestDigest",
    "envelope_schema_invalid",
  );
  const manifest = normalizeManifest(record.manifest, limits);
  const signature = canonicalSignature(record.signature, algorithm);
  const envelope = freezeEnvelope({
    envelopeVersion: TOOL_MANIFEST_ENVELOPE_VERSION,
    algorithm,
    keyId,
    manifestDigest,
    manifest,
    signature,
  });
  enforceUtf8ByteLimit(
    stableJson(envelope),
    limits.maxEnvelopeBytes,
    "envelope",
    "envelope_schema_invalid",
  );
  return envelope;
}

function normalizeTrustAnchors(raw: readonly ManifestTrustAnchor[]): NormalizedTrustAnchor[] {
  const values = strictArray(
    raw,
    "trust anchors",
    "envelope_schema_invalid",
    TOOL_MANIFEST_LIMITS.maxTrustAnchors,
  );
  if (values.length === 0 || values.length > TOOL_MANIFEST_LIMITS.maxTrustAnchors) {
    throw new RangeError(
      `trust anchors must contain between 1 and ${TOOL_MANIFEST_LIMITS.maxTrustAnchors} entries`,
    );
  }
  const seen = new Set<string>();
  return values.map((value, index) => {
    const label = `trustAnchors[${index}]`;
    const record = ownDataRecord(value, label, "envelope_schema_invalid");
    const algorithm = signatureAlgorithm(record.algorithm);
    const keyId = signingKeyId(record.keyId);
    if (seen.has(keyId)) throw new TypeError(`duplicate trust-anchor keyId: ${keyId}`);
    seen.add(keyId);
    if (algorithm === "Ed25519") {
      assertOnlyKeys(record, ["algorithm", "keyId", "publicKey"], label, "envelope_schema_invalid");
      return Object.freeze({
        algorithm,
        keyId,
        publicKey: normalizeEd25519PublicKey(record.publicKey, `${label}.publicKey`),
      });
    }
    assertOnlyKeys(record, ["algorithm", "keyId", "secret"], label, "envelope_schema_invalid");
    return Object.freeze({
      algorithm,
      keyId,
      secret: normalizeHmacSecret(record.secret, `${label}.secret`),
    });
  });
}

function normalizeSigner(raw: ManifestSigner):
  | { algorithm: "Ed25519"; keyId: string; privateKey: KeyObject }
  | { algorithm: "HMAC-SHA256"; keyId: string; secret: Uint8Array | KeyObject } {
  const record = ownDataRecord(raw, "manifest signer", "envelope_schema_invalid");
  const algorithm = signatureAlgorithm(record.algorithm);
  const keyId = signingKeyId(record.keyId);
  if (algorithm === "Ed25519") {
    assertOnlyKeys(record, ["algorithm", "keyId", "privateKey"], "manifest signer", "envelope_schema_invalid");
    return Object.freeze({
      algorithm,
      keyId,
      privateKey: normalizeEd25519PrivateKey(record.privateKey, "privateKey"),
    });
  }
  assertOnlyKeys(record, ["algorithm", "keyId", "secret"], "manifest signer", "envelope_schema_invalid");
  return Object.freeze({
    algorithm,
    keyId,
    secret: normalizeHmacSecret(record.secret, "secret"),
  });
}

function normalizeVerifierOptions(raw: PinnedToolManifestVerifierOptions): NormalizedVerifierOptions {
  const record = ownDataRecord(raw, "PinnedToolManifestVerifierOptions", "envelope_schema_invalid");
  assertOnlyKeys(
    record,
    ["clock", "maxClockSkewMs", "maxDiagnostics", "maxTools", "maxManifestBytes", "maxEnvelopeBytes"],
    "PinnedToolManifestVerifierOptions",
    "envelope_schema_invalid",
  );
  const parseLimits = normalizeParseLimits(record);
  const clock = record.clock === undefined ? () => new Date() : record.clock;
  if (typeof clock !== "function") throw new TypeError("clock must be a function");
  return {
    ...parseLimits,
    clock: clock as () => Date,
    maxClockSkewMs: boundedInteger(
      record.maxClockSkewMs ?? TOOL_MANIFEST_LIMITS.maxClockSkewMs,
      "maxClockSkewMs",
      0,
      24 * 60 * 60 * 1_000,
    ),
    maxDiagnostics: boundedInteger(
      record.maxDiagnostics ?? TOOL_MANIFEST_LIMITS.maxDiagnostics,
      "maxDiagnostics",
      1,
      16_384,
    ),
  };
}

function normalizeParseLimits(
  raw: Pick<
    PinnedToolManifestVerifierOptions,
    "maxTools" | "maxManifestBytes" | "maxEnvelopeBytes"
  >,
): NormalizedParseLimits {
  return {
    maxTools: boundedInteger(
      raw.maxTools ?? TOOL_MANIFEST_LIMITS.maxTools,
      "maxTools",
      1,
      4_096,
    ),
    maxManifestBytes: boundedInteger(
      raw.maxManifestBytes ?? TOOL_MANIFEST_LIMITS.maxManifestBytes,
      "maxManifestBytes",
      256,
      16 * 1024 * 1024,
    ),
    maxEnvelopeBytes: boundedInteger(
      raw.maxEnvelopeBytes ?? TOOL_MANIFEST_LIMITS.maxEnvelopeBytes,
      "maxEnvelopeBytes",
      512,
      16 * 1024 * 1024 + 64 * 1024,
    ),
  };
}

function signaturePayload(
  algorithm: ToolManifestSignatureAlgorithm,
  keyId: string,
  manifestDigest: string,
): Buffer {
  return Buffer.from(stableJson({
    algorithm,
    domain: SIGNATURE_DOMAIN,
    envelopeVersion: TOOL_MANIFEST_ENVELOPE_VERSION,
    keyId,
    manifestDigest,
  }), "utf-8");
}

function normalizeEd25519PublicKey(raw: unknown, label: string): KeyObject {
  const input = normalizedAsymmetricKeyInput(raw, label);
  let key: KeyObject;
  try {
    key = isKeyObject(input) ? input : createPublicKey(input);
  } catch {
    throw new TypeError(`${label} must be a valid Ed25519 public key`);
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(`${label} must be an Ed25519 public key`);
  }
  return key;
}

function normalizeEd25519PrivateKey(raw: unknown, label: string): KeyObject {
  const input = normalizedAsymmetricKeyInput(raw, label);
  let key: KeyObject;
  try {
    key = isKeyObject(input) ? input : createPrivateKey(input);
  } catch {
    throw new TypeError(`${label} must be a valid Ed25519 private key`);
  }
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(`${label} must be an Ed25519 private key`);
  }
  return key;
}

function normalizedAsymmetricKeyInput(raw: unknown, label: string): string | Buffer | KeyObject {
  if (typeof raw === "string") {
    enforceUtf8ByteLimit(raw, 16 * 1024, label, "envelope_schema_invalid");
    return raw;
  }
  if (raw instanceof Uint8Array) {
    if (raw.byteLength === 0 || raw.byteLength > 16 * 1024) {
      throw new RangeError(`${label} has an invalid byte length`);
    }
    return Buffer.from(raw);
  }
  if (isKeyObject(raw)) return raw;
  throw new TypeError(`${label} must be PEM/DER bytes or a KeyObject`);
}

function normalizeHmacSecret(raw: unknown, label: string): Uint8Array | KeyObject {
  if (isKeyObject(raw)) {
    if (raw.type !== "secret" || (raw.symmetricKeySize ?? 0) < 32) {
      throw new TypeError(`${label} must be a secret KeyObject of at least 32 bytes`);
    }
    if ((raw.symmetricKeySize ?? 0) > TOOL_MANIFEST_LIMITS.maxHmacKeyBytes) {
      throw new RangeError(`${label} exceeds the HMAC key byte limit`);
    }
    return raw;
  }
  if (!(raw instanceof Uint8Array)) {
    throw new TypeError(`${label} must be Uint8Array key material or a secret KeyObject`);
  }
  if (raw.byteLength < 32 || raw.byteLength > TOOL_MANIFEST_LIMITS.maxHmacKeyBytes) {
    throw new RangeError(`${label} must contain between 32 and ${TOOL_MANIFEST_LIMITS.maxHmacKeyBytes} bytes`);
  }
  return Uint8Array.from(raw);
}

function isKeyObject(value: unknown): value is KeyObject {
  return value instanceof KeyObject;
}

function ownDataRecord(
  value: unknown,
  label: string,
  code: ManifestVerificationCode,
): Record<string, unknown> {
  if (
    typeof value !== "object" || value === null || Array.isArray(value) ||
    utilTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new SecurityInputError(code, `${label} must be a plain object`);
  }
  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      throw new SecurityInputError(code, `${label} must not contain symbol properties`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new SecurityInputError(code, `${label} must contain enumerable data properties only`);
    }
    if (descriptor.value === undefined) {
      throw new SecurityInputError(code, `${label} must not contain undefined`);
    }
    result[key] = descriptor.value;
  }
  return result;
}

function strictArray(
  value: unknown,
  label: string,
  code: ManifestVerificationCode,
  maxLength = Number.MAX_SAFE_INTEGER,
): readonly unknown[] {
  if (!Array.isArray(value) || utilTypes.isProxy(value)) {
    throw new SecurityInputError(code, `${label} must be an array`);
  }
  if (value.length > maxLength) {
    throw new SecurityInputError(code, `${label} exceeds the ${maxLength} entry limit`);
  }
  const keys = Reflect.ownKeys(value);
  for (const key of keys) {
    if (key === "length") continue;
    if (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/.test(key)) {
      throw new SecurityInputError(code, `${label} contains a non-JSON property`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new SecurityInputError(code, `${label} must be dense and accessor-free`);
    }
    if (descriptor.value === undefined) {
      throw new SecurityInputError(code, `${label} must not contain undefined`);
    }
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) {
      throw new SecurityInputError(code, `${label} must be dense and accessor-free`);
    }
  }
  return value;
}

function assertOnlyKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
  code: ManifestVerificationCode,
): void {
  const accepted = new Set(allowed);
  if (Object.keys(record).some((key) => !accepted.has(key))) {
    throw new SecurityInputError(code, `${label} contains unsupported field(s)`);
  }
}

function parseJsonText(value: string, maxBytes: number, label: string): unknown {
  enforceUtf8ByteLimit(value, maxBytes, label, "malformed_json");
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new SecurityInputError("malformed_json", `${label} must be valid JSON`);
  }
}

function identityComponent(value: unknown, label: string, maxBytes: number): string {
  if (typeof value !== "string") {
    throw new SecurityInputError("manifest_schema_invalid", `${label} must be a string`);
  }
  if (value.length === 0 || value.trim() !== value) {
    throw new SecurityInputError(
      "manifest_schema_invalid",
      `${label} must be non-empty without surrounding whitespace`,
    );
  }
  assertSafeCanonicalUnicode(value, label, "manifest_schema_invalid");
  enforceUtf8ByteLimit(value, maxBytes, label, "manifest_schema_invalid");
  return value;
}

function boundedMetadataString(value: unknown, label: string, maxBytes: number): string {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw new SecurityInputError(
      "manifest_schema_invalid",
      `${label} must be a non-empty string without surrounding whitespace`,
    );
  }
  assertSafeCanonicalUnicode(value, label, "manifest_schema_invalid");
  enforceUtf8ByteLimit(
    value,
    Math.min(maxBytes, TOOL_MANIFEST_LIMITS.maxMetadataStringBytes),
    label,
    "manifest_schema_invalid",
  );
  return value;
}

function assertSafeCanonicalUnicode(
  value: string,
  label: string,
  code: ManifestVerificationCode,
): void {
  if (value.normalize("NFC") !== value) {
    throw new SecurityInputError(code, `${label} must already be NFC-normalized`);
  }
  if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value) || !hasWellFormedUtf16(value)) {
    throw new SecurityInputError(code, `${label} contains forbidden control/format characters`);
  }
}

function hasWellFormedUtf16(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function canonicalHttpsUrl(value: unknown, label: string): string {
  const raw = boundedMetadataString(value, label, 2_048);
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SecurityInputError("manifest_schema_invalid", `${label} must be a valid HTTPS URL`);
  }
  if (url.protocol !== "https:" || url.username !== "" || url.password !== "") {
    throw new SecurityInputError(
      "manifest_schema_invalid",
      `${label} must be an HTTPS URL without embedded credentials`,
    );
  }
  return url.toString();
}

function utcDateTime(value: unknown, label: string): string {
  if (typeof value !== "string" || !UTC_DATE_TIME.test(value)) {
    throw new SecurityInputError("manifest_schema_invalid", `${label} must be an RFC 3339 UTC date-time`);
  }
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) {
    throw new SecurityInputError("manifest_schema_invalid", `${label} must be a valid date-time`);
  }
  const canonical = new Date(ms).toISOString();
  const acceptedWithoutMilliseconds = canonical.replace(".000Z", "Z");
  if (value !== canonical && value !== acceptedWithoutMilliseconds) {
    throw new SecurityInputError("manifest_schema_invalid", `${label} is not a real canonical date-time`);
  }
  return canonical;
}

function signatureAlgorithm(value: unknown): ToolManifestSignatureAlgorithm {
  if (value !== "Ed25519" && value !== "HMAC-SHA256") {
    throw new SecurityInputError(
      "unsupported_signature_algorithm",
      "signature algorithm must be Ed25519 or HMAC-SHA256",
    );
  }
  return value;
}

function signingKeyId(value: unknown): string {
  if (typeof value !== "string" || !KEY_ID.test(value)) {
    throw new SecurityInputError("envelope_schema_invalid", "keyId has an invalid format");
  }
  return value;
}

function sha256Digest(
  value: unknown,
  label: string,
  code: ManifestVerificationCode,
): string {
  if (typeof value !== "string" || !SHA256_DIGEST.test(value)) {
    throw new SecurityInputError(code, `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function canonicalSignature(
  value: unknown,
  algorithm: ToolManifestSignatureAlgorithm,
): string {
  if (typeof value !== "string" || !BASE64URL.test(value) || value.includes("=")) {
    throw new SecurityInputError("envelope_schema_invalid", "signature must be canonical unpadded base64url");
  }
  let decoded: Buffer;
  try {
    decoded = Buffer.from(value, "base64url");
  } catch {
    throw new SecurityInputError("envelope_schema_invalid", "signature is not valid base64url");
  }
  const expectedBytes = algorithm === "Ed25519" ? 64 : 32;
  if (decoded.length !== expectedBytes || decoded.toString("base64url") !== value) {
    throw new SecurityInputError(
      "envelope_schema_invalid",
      `${algorithm} signature has a non-canonical or invalid length`,
    );
  }
  return value;
}

function base64urlUtf8(value: string): string {
  return Buffer.from(value, "utf-8").toString("base64url");
}

function decodeCanonicalBase64url(value: string, index: number): string {
  if (value.length === 0 || !BASE64URL.test(value) || value.includes("=")) {
    throw new TypeError(`canonical ToolKey component ${index} is not base64url`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.toString("base64url") !== value) {
    throw new TypeError(`canonical ToolKey component ${index} is not canonical base64url`);
  }
  const decoded = bytes.toString("utf-8");
  if (!Buffer.from(decoded, "utf-8").equals(bytes)) {
    throw new TypeError(`canonical ToolKey component ${index} is not valid UTF-8`);
  }
  return decoded;
}

function stableJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("canonical JSON contains a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value !== "object" || value === null) {
    throw new TypeError("canonical JSON contains a non-JSON value");
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort(compareCodeUnits)
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
}

function freezeEnvelope(
  envelope: SignedPinnedToolManifestEnvelopeV1,
): Readonly<SignedPinnedToolManifestEnvelopeV1> {
  return Object.freeze(envelope);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf-8").digest("hex");
}

function constantTimeTextEqual(left: string, right: string): boolean {
  return constantTimeBytesEqual(Buffer.from(left, "utf-8"), Buffer.from(right, "utf-8"));
}

function constantTimeBytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function validClockValue(value: unknown): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new TypeError("manifest verifier clock must return a valid Date");
  }
  return value;
}

function trustSemantics(algorithm: ToolManifestSignatureAlgorithm): ManifestTrustSemantics {
  return algorithm === "Ed25519"
    ? "operator-pinned-public-key"
    : "shared-secret-domain";
}

function compareCodeUnits(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function boundedInteger(
  value: unknown,
  label: string,
  min: number,
  max: number,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) {
    throw new RangeError(`${label} must be an integer between ${min} and ${max}`);
  }
  return value as number;
}

function enforceUtf8ByteLimit(
  value: string,
  maxBytes: number,
  label: string,
  code: ManifestVerificationCode,
): void {
  if (Buffer.byteLength(value, "utf-8") > maxBytes) {
    throw new SecurityInputError(code, `${label} exceeds ${maxBytes} UTF-8 bytes`);
  }
}

function cloneDiagnostic(value: ManifestVerificationDiagnostic): ManifestVerificationDiagnostic {
  return { ...value };
}

function inputErrorCode(error: unknown): Exclude<ManifestVerificationCode, "manifest_verified"> {
  return error instanceof SecurityInputError
    ? error.code as Exclude<ManifestVerificationCode, "manifest_verified">
    : "envelope_schema_invalid";
}

function diagnosticReason(code: ManifestVerificationCode): string {
  switch (code) {
    case "manifest_verified":
      return "签名、keyId、manifest 摘要与有效期均已通过验证";
    case "malformed_json":
      return "签名 manifest envelope 不是有效且有界的 JSON";
    case "envelope_schema_invalid":
      return "签名 envelope 不符合严格的版本化数据结构";
    case "unsupported_envelope_version":
      return "签名 envelope 版本不受当前验证器支持";
    case "unsupported_manifest_version":
      return "pinned manifest 版本不受当前验证器支持";
    case "unsupported_signature_algorithm":
      return "签名算法不在当前允许的算法集合中";
    case "manifest_schema_invalid":
      return "pinned manifest 包含无效、重复、未知或超界的数据";
    case "manifest_digest_mismatch":
      return "manifest 内容与 envelope 声明的摘要不一致";
    case "manifest_expired":
      return "pinned manifest 已过期，不能继续授予工具身份";
    case "manifest_not_yet_valid":
      return "pinned manifest 的签发时间超出允许的时钟偏差";
    case "unknown_key_id":
      return "envelope 引用的 keyId 不在 Host 信任锚中";
    case "key_algorithm_mismatch":
      return "envelope 算法与该 keyId 配置的信任锚类型不一致";
    case "signature_invalid":
      return "envelope 签名或共享密钥 MAC 验证失败";
    case "verifier_clock_invalid":
      return "Host 验证时钟无效，按 fail-closed 规则拒绝 manifest";
  }
}

class SecurityInputError extends TypeError {
  constructor(
    public readonly code: ManifestVerificationCode,
    message: string,
  ) {
    super(message);
    this.name = "SecurityInputError";
  }
}
