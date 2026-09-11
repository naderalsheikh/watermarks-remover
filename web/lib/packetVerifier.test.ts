import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { computeSha256, PACKET_SCHEMA_PINS, verifyReleasePacket, type VerificationFiles } from "./packetVerifier";
import fixture from "./fixtures/packetVerifier.json";
import packetSchema from "../../service/scripts/schemas/release_packet.schema.json";
import legacySchema from "../../service/scripts/schemas/archive/release_packet.v1.schema.json";
import resultSchema from "../../service/scripts/schemas/release_result.schema.json";

// Fixture provenance: tests/test_release_packet_verifier.py's _packet_files,
// _release_result, and _sign_packet_files using a deterministic fixture key.
// All artifacts passed jsonschema and the signed packet passed the Python offline
// verifier before capture. These are synthetic test documents, not client data.
const makePacket = () => structuredClone(fixture.packet);
const makeSignedPacket = () => structuredClone(fixture.signedPacket);
const suppliedFiles = (): VerificationFiles => ({
  original: { name: "original.txt", data: "original fixture bytes" },
  derivative: { name: "out.docx", data: fixture.files["derivative/out.docx"] },
  manifest: { name: "manifest.json", data: fixture.files["manifest.json"] },
  report: { name: "report.json", data: fixture.files["report.json"] },
  certificate: { name: "certificate.html", data: fixture.files["certificate.html"] },
  readme: { name: "README.txt", data: fixture.files["README.txt"] },
});
const check = (report: Awaited<ReturnType<typeof verifyReleasePacket>>, name: string) => report.checks.find((entry) => entry.name === name);
afterEach(() => vi.restoreAllMocks());

describe("packetVerifier", () => {
  it("computes SHA-256 over strings, ArrayBuffers, and bounded typed-array views", async () => {
    expect(await computeSha256("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    const data = new TextEncoder().encode("xhello worldx");
    const slice = data.subarray(1, -1);
    const expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    expect(await computeSha256(slice)).toBe(expected);
    expect(await computeSha256(new TextEncoder().encode("hello world").buffer)).toBe(expected);
  });

  it.each(["not json", "null", "[]", "false", "7", '"text"', null, [], true, 4, {}])("rejects malformed or non-artifact input %j without throwing", async (payload) => {
    const report = await verifyReleasePacket(payload);
    expect(report.status).toBe("INTERNALLY INCONSISTENT");
    expect(report.checks.some((entry) => entry.status === "failed")).toBe(true);
  });

  it("rejects the reviewed fabricated packet with two hex strings and an anchor label", async () => {
    const report = await verifyReleasePacket({
      original_sha256: "a".repeat(64),
      hashes: { derivative: { sha256: "b".repeat(64) } },
      anchor: { type: "rfc3161" },
    });
    expect(report.status).toBe("INTERNALLY INCONSISTENT");
    expect(check(report, "Artifact Schema")?.status).toBe("failed");
    expect(report.checks.filter((entry) => entry.status === "passed")).toHaveLength(0);
  });

  for (const [label, schema, payload] of [["packet", packetSchema, fixture.packet], ["result", resultSchema, fixture.result]] as const) {
    it.each(schema.required)(`rejects a ${label} missing required field %s`, async (key) => {
      const partial: Record<string, unknown> = structuredClone(payload);
      delete partial[key];
      expect((await verifyReleasePacket(partial)).status).toBe("INTERNALLY INCONSISTENT");
    });
  }

  it.each([
    { policy: null }, { policy: [] }, { policy: { id: 42, version: 1, digest: null } },
    { hashes: [] }, { anchor: [] }, { legal_justifications: [null] },
    { legal_justifications: [{ subtype: "comments", action: "keep", legal_justification: { basis: "invented", note: "" } }] },
    { limitations: [42] }, { audit_refs: { bundle_download_seq: 0, certificate_issued_seq: 1 } },
    { audit_refs: { bundle_download_seq: 1.5, certificate_issued_seq: 1 } },
    { original_sha256: "f".repeat(63) }, { original_sha256: "F".repeat(64) },
    { job_id: "" }, { spec_version: 1 }, { status: "approved" },
    { signature: { algorithm: "ed25519" } }, { extra: "unrecognized" },
  ])("rejects incorrect nested shapes and invalid values: %j", async (patch) => {
    const report = await verifyReleasePacket({ ...makePacket(), ...patch });
    expect(check(report, "Artifact Schema")?.status).toBe("failed");
    expect(report.status).toBe("INTERNALLY INCONSISTENT");
  });

  it("makes absent bytes, unsigned packets, and unanchored packets explicit", async () => {
    const report = await verifyReleasePacket(makePacket());
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
    expect(check(report, "Artifact Schema")?.status).toBe("passed");
    for (const name of ["Original", "Derivative", "Manifest", "Report", "Certificate", "README"]) {
      expect(check(report, `${name} Content Digest`)?.status).toBe("not_checked");
    }
    expect(check(report, "Operator Signature")?.status).toBe("unavailable");
    expect(check(report, "External Timestamp")?.status).toBe("unavailable");
    expect(check(report, "Published Schema Pin")?.status).toBe("unavailable");
    expect(report.derivativeVerified).toBe(false);
  });

  it("reports only computed content digests as passed even when all supplied bytes match", async () => {
    const report = await verifyReleasePacket(makePacket(), suppliedFiles());
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
    expect(report.derivativeVerified).toBe(true);
    for (const name of ["Original", "Derivative", "Manifest", "Report", "Certificate", "README"]) {
      expect(check(report, `${name} Content Digest`)?.status).toBe("passed");
    }
    expect(check(report, "Custody and Artifact Cross-checks")?.status).toBe("not_checked");
    expect(report.legalJustifications[0]).toEqual({ subtype: "comments_and_notes", basis: "privilege", note: "Attorney-client comments withheld." });
    expect(report.dispositions.kept).toEqual(["comments_and_notes (keep)"]);
  });

  it.each(["original", "derivative", "manifest", "report", "certificate", "readme"] as const)("fails when supplied %s bytes differ", async (key) => {
    const files = suppliedFiles();
    files[key] = { name: files[key]!.name, data: "tampered bytes" };
    const report = await verifyReleasePacket(makePacket(), files);
    expect(report.status).toBe("INTERNALLY INCONSISTENT");
    expect(report.checks.filter((entry) => entry.status === "failed")).toHaveLength(1);
    if (key === "derivative") expect(report.derivativeVerified).toBe(false);
  });

  it("does not treat a cryptographically valid operator signature as browser-verified", async () => {
    const packet = makeSignedPacket();
    // Independently verify the fixture signature so this regression covers an
    // actual valid signature, not just a correctly sized placeholder.
    const rawKey = Buffer.from("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c", "hex");
    const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), rawKey]), format: "der", type: "spki" });
    const content: Record<string, unknown> = { ...packet };
    delete content.signature;
    const canonical = (value: unknown): string => {
      if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
      if (value !== null && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
      return JSON.stringify(value);
    };
    expect(verify(null, Buffer.from(canonical(content)), key, Buffer.from(packet.signature.value, "hex"))).toBe(true);
    const report = await verifyReleasePacket(packet, suppliedFiles());
    expect(check(report, "Operator Signature")?.status).toBe("not_checked");
    expect(check(report, "External Timestamp")?.status).toBe("unavailable");
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
  });

  it("also leaves a tampered but well-shaped signature unverified", async () => {
    const packet = makeSignedPacket();
    packet.signature.value = "0".repeat(128);
    const report = await verifyReleasePacket(packet, suppliedFiles());
    expect(check(report, "Operator Signature")?.status).toBe("not_checked");
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
  });

  it("accepts the current emitter's schema pin and embedded public key without trusting the key", async () => {
    const packet = makeSignedPacket();
    const report = await verifyReleasePacket({
      ...packet, schema_version: 2, schema_sha256: PACKET_SCHEMA_PINS[2],
      signature: { ...packet.signature, public_key: "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c" },
    });
    expect(check(report, "Artifact Schema")?.status).toBe("passed");
    expect(check(report, "Published Schema Pin")?.status).toBe("passed");
    expect(check(report, "Operator Signature")?.status).toBe("not_checked");
  });

  it("leaves an unsigned operator anchor unavailable and rejects a conflicting actual key reference", async () => {
    const packet = makePacket();
    packet.anchor.type = "ed25519-operator";
    const unsigned = await verifyReleasePacket(packet);
    expect(unsigned.status).toBe("VERIFICATION INCOMPLETE");
    expect(check(unsigned, "Operator Anchor Reference")?.status).toBe("unavailable");
    const signed = makeSignedPacket();
    signed.anchor.reference = "0".repeat(16);
    expect(check(await verifyReleasePacket(signed), "Operator Anchor Reference")?.status).toBe("failed");
  });

  it.each([null, "", "not base64 !!!"])("rejects a timestamp claim missing a usable token reference: %s", async (reference) => {
    const packet = { ...makeSignedPacket(), anchor: { type: "rfc3161-tsa", digest: "0".repeat(64), reference } };
    const report = await verifyReleasePacket(packet);
    expect(check(report, "Timestamp Claim Fields")?.status).toBe("failed");
    expect(report.status).toBe("INTERNALLY INCONSISTENT");
  });

  it("checks the timestamp's signature digest but never infers token validity from base64", async () => {
    const packet = makeSignedPacket();
    const digest = createHash("sha256").update(Buffer.from(packet.signature.value, "hex")).digest("hex");
    const claimed = { ...packet, anchor: { type: "rfc3161-tsa", digest, reference: Buffer.from("not a timestamp token").toString("base64") } };
    const report = await verifyReleasePacket(claimed);
    expect(check(report, "Timestamp Signature Digest")?.status).toBe("passed");
    expect(check(report, "External Timestamp")?.status).toBe("not_checked");
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
    claimed.anchor.digest = "f".repeat(64);
    expect(check(await verifyReleasePacket(claimed), "Timestamp Signature Digest")?.status).toBe("failed");
  });

  it("keeps a real RFC 3161 token unverified in the browser as well", async () => {
    // This token and signature are the offline verifier's real, validated TSA
    // fixture (test_real_token_all_correct_verifies_clean), not a fake base64 blob.
    const token = readFileSync(new URL("../../tests/fixtures/rfc3161_token_a.der", import.meta.url));
    const signature = readFileSync(new URL("../../tests/fixtures/rfc3161_sig_a.bin", import.meta.url));
    const packet = makeSignedPacket();
    const report = await verifyReleasePacket({
      ...packet,
      signature: { ...packet.signature, signed_fields: "release_packet.v1.canonical-excluding-anchor", value: signature.toString("hex") },
      anchor: { type: "rfc3161-tsa", digest: createHash("sha256").update(signature).digest("hex"), reference: token.toString("base64") },
    });
    expect(check(report, "Timestamp Signature Digest")?.status).toBe("passed");
    expect(check(report, "External Timestamp")?.status).toBe("not_checked");
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
  });

  it("does not infer evidence from an unsupported anchor label", async () => {
    const packet = makePacket();
    packet.anchor.type = "rfc3161";
    const report = await verifyReleasePacket(packet);
    expect(check(report, "External Timestamp")?.status).toBe("unavailable");
    expect(report.anchor.detail).not.toContain("present");
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
  });

  it.each(["done", "refused", "failed"])("accepts canonical derivative-free %s release results with explicit scope", async (status) => {
    const result = { ...fixture.result, status, signature_ref: { algorithm: "ed25519", key_id: "a".repeat(16), signed_fields: "release_packet.v1.canonical" } };
    const report = await verifyReleasePacket(result);
    expect(report.artifactType).toBe("release_result");
    expect(report.jobStatus).toBe(status);
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
    expect(report.derivativeDeclared).toBeNull();
    expect(check(report, "Derivative Content Digest")?.status).toBe("unavailable");
    expect(check(report, "Operator Signature")?.status).toBe("unavailable");
    expect(report.anchor.detail).toContain("own bytes");
  });

  it("compares a result's separate certificate digest and never silently checks an undeclared derivative", async () => {
    const report = await verifyReleasePacket(fixture.result, {
      certificate: { name: "certificate.html", data: "<!doctype html><html><body>certificate</body></html>" },
      derivative: { name: "some.docx", data: "some bytes" },
    });
    expect(check(report, "Certificate Content Digest")?.status).toBe("passed");
    expect(check(report, "Derivative Content Digest")?.status).toBe("unavailable");
    expect(check(report, "Derivative Content Digest")?.detail).toContain("some.docx");
    expect(report.derivativeVerified).toBe(false);
  });

  it("allows absent derivatives only for refused or failed packets, never incomplete pairs", async () => {
    const packet = { ...makePacket(), hashes: { ...fixture.packet.hashes, derivative: { filename: null, sha256: null } } };
    expect((await verifyReleasePacket(packet)).status).toBe("INTERNALLY INCONSISTENT");
    for (const status of ["refused", "failed"]) {
      expect((await verifyReleasePacket({ ...packet, status })).status).toBe("VERIFICATION INCOMPLETE");
      expect((await verifyReleasePacket({ ...packet, status, hashes: { ...packet.hashes, derivative: { filename: "file.docx", sha256: null } } })).status).toBe("INTERNALLY INCONSISTENT");
    }
  });

  it("handles unavailable WebCrypto without claiming mismatches or passing unread bytes", async () => {
    vi.spyOn(crypto.subtle, "digest").mockRejectedValue(new Error("unsupported"));
    const report = await verifyReleasePacket(makePacket(), suppliedFiles());
    expect(report.status).toBe("VERIFICATION INCOMPLETE");
    expect(report.derivativeVerified).toBe(false);
    expect(check(report, "Derivative Content Digest")?.status).toBe("unavailable");
  });

  it("checks current and archived schema pins, and distinguishes missing, partial, and unknown pins", async () => {
    for (const version of [1, 2]) {
      const packet = { ...makePacket(), schema_version: version, schema_sha256: PACKET_SCHEMA_PINS[version] };
      expect(check(await verifyReleasePacket(packet), "Published Schema Pin")?.status).toBe("passed");
      expect(check(await verifyReleasePacket({ ...packet, schema_sha256: "0".repeat(64) }), "Published Schema Pin")?.status).toBe("failed");
    }
    expect(check(await verifyReleasePacket({ ...makePacket(), schema_version: 2 }), "Published Schema Pin")?.status).toBe("failed");
    expect(check(await verifyReleasePacket({ ...makePacket(), schema_sha256: PACKET_SCHEMA_PINS[2] }), "Published Schema Pin")?.status).toBe("failed");
    expect(check(await verifyReleasePacket({ ...makePacket(), schema_version: 999, schema_sha256: "0".repeat(64) }), "Published Schema Pin")?.status).toBe("unavailable");
  });
});

describe("published contract drift", () => {
  it.each([[1, "archive/release_packet.v1.schema.json"], [2, "release_packet.schema.json"]] as const)("keeps v%s pin aligned with the published file bytes", (version, path) => {
    const bytes = readFileSync(new URL(`../../service/scripts/schemas/${path}`, import.meta.url));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(PACKET_SCHEMA_PINS[version]);
  });

  it("requires explicit validator support when any bundled schema adds a keyword", () => {
    const supported = new Set(["$schema", "$id", "title", "version", "type", "required", "properties", "additionalProperties", "$defs", "$ref", "const", "enum", "minLength", "maxLength", "pattern", "minimum", "items"]);
    function inspect(schema: Record<string, unknown>) {
      for (const [key, value] of Object.entries(schema)) {
        expect(supported.has(key) || key.startsWith("_comment"), `Unsupported schema keyword: ${key}`).toBe(true);
        if (key === "properties" || key === "$defs") for (const nested of Object.values(value as object)) inspect(nested);
        if (key === "items") inspect(value as Record<string, unknown>);
      }
    }
    for (const schema of [packetSchema, legacySchema, resultSchema]) inspect(schema);
  });
});
