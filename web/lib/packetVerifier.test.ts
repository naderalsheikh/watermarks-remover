import { describe, expect, it } from "vitest";
import { computeSha256, verifyReleasePacket } from "./packetVerifier";

describe("packetVerifier", () => {
  it("computes correct SHA-256 for string and bytes", async () => {
    // SHA-256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    const emptyHash = await computeSha256("");
    expect(emptyHash).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const helloHash = await computeSha256("hello world");
    expect(helloHash).toBe("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
  });

  it("fails gracefully with INTERNALLY INCONSISTENT on invalid JSON", async () => {
    const report = await verifyReleasePacket("invalid json text");
    expect(report.status).toBe("INTERNALLY INCONSISTENT");
    expect(report.checks.some((c) => !c.pass)).toBe(true);
  });

  it("verifies a consistent release packet with matching derivative bytes", async () => {
    const derivativeContent = "cleared derivative text";
    const derivativeHash = await computeSha256(derivativeContent);

    const packet = {
      spec_version: "1.0",
      release_id: "rel_123",
      job_id: "job_456",
      document_id: "doc_789",
      matter_id: "matter_001",
      status: "done",
      policy: { id: "external_sharing", version: 1 },
      original_sha256: "a".repeat(64),
      hashes: {
        derivative: { filename: "clean.pdf", sha256: derivativeHash },
      },
      anchor: { type: "ed25519-operator", signature: "sig123" },
      actions: ["authoring_metadata:strip: 3 fields", "c2pa:keep: retained"],
      legal_justifications: {
        c2pa: { basis: "work_product_protection", note: "Author signature" },
      },
      limitations: ["PDF rasterized metadata untouched"],
    };

    const report = await verifyReleasePacket(packet, {
      derivative: {
        name: "clean.pdf",
        data: new TextEncoder().encode(derivativeContent).buffer,
      },
    });

    expect(report.status).toBe("INTERNALLY CONSISTENT");
    expect(report.derivativeVerified).toBe(true);
    expect(report.anchor.type).toBe("ed25519-operator");
    expect(report.dispositions.stripped.length).toBe(1);
    expect(report.dispositions.kept.length).toBe(1);
    expect(report.legalJustifications).toHaveLength(1);
    expect(report.legalJustifications[0].basis).toBe("work_product_protection");
  });

  it("rejects hollow JSON payloads without required hash bindings", async () => {
    const hollowPayload = { spec_version: "1.0" };
    const report = await verifyReleasePacket(hollowPayload);
    expect(report.status).toBe("INTERNALLY INCONSISTENT");
    const originalCheck = report.checks.find((c) => c.name === "Original Digest Binding");
    expect(originalCheck?.pass).toBe(false);
  });

  it("rejects malformed original_sha256 hex lengths", async () => {
    const packet = {
      spec_version: "1.0",
      release_id: "rel_123",
      original_sha256: "not-a-64-char-hex",
      hashes: {
        derivative: { filename: "clean.pdf", sha256: "b".repeat(64) },
      },
    };
    const report = await verifyReleasePacket(packet);
    expect(report.status).toBe("INTERNALLY INCONSISTENT");
    expect(report.checks.find((c) => c.name === "Original Digest Binding")?.pass).toBe(false);
  });

  it("verifies production release_packet structure with nested legal_justifications", async () => {
    const derivativeContent = "production cleared document content";
    const derivativeHash = await computeSha256(derivativeContent);

    const packet = {
      spec_version: "1.0",
      release_id: "rel_prod_001",
      job_id: "job_001",
      document_id: "doc_001",
      matter_id: "matter_001",
      status: "done",
      policy: { id: "production", version: 1 },
      original_sha256: "a".repeat(64),
      hashes: {
        derivative: { filename: "SPA.external.docx", sha256: derivativeHash },
        manifest_json_sha256: "c".repeat(64),
        report_json_sha256: "d".repeat(64),
        certificate_html_sha256: "e".repeat(64),
      },
      anchor: { type: "rfc3161-tsa" },
      legal_justifications: [
        {
          subtype: "comments_and_notes",
          action: "keep",
          legal_justification: {
            basis: "attorney_client_privilege",
            note: "Drafting comments retained under privilege",
          },
        },
      ],
      limitations: ["No removal path for unknown macro streams"],
    };

    const report = await verifyReleasePacket(packet, {
      derivative: {
        name: "SPA.external.docx",
        data: new TextEncoder().encode(derivativeContent).buffer,
      },
    });

    expect(report.status).toBe("INTERNALLY CONSISTENT");
    expect(report.derivativeVerified).toBe(true);
    expect(report.anchor.type).toBe("rfc3161");
    expect(report.legalJustifications).toHaveLength(1);
    expect(report.legalJustifications[0].subtype).toBe("comments_and_notes");
    expect(report.legalJustifications[0].basis).toBe("attorney_client_privilege");
    expect(report.legalJustifications[0].note).toBe("Drafting comments retained under privilege");
    expect(report.dispositions.kept.length).toBe(1);
  });

  it("handles case-insensitive hash comparisons correctly", async () => {
    const derivativeContent = "case insensitivity test";
    const derivativeHash = await computeSha256(derivativeContent);

    const packet = {
      spec_version: "1.0",
      release_id: "rel_case",
      original_sha256: "F".repeat(64),
      hashes: {
        derivative: { filename: "doc.pdf", sha256: derivativeHash.toUpperCase() },
      },
    };

    const report = await verifyReleasePacket(packet, {
      derivative: {
        name: "doc.pdf",
        data: new TextEncoder().encode(derivativeContent).buffer,
      },
    });

    expect(report.status).toBe("INTERNALLY CONSISTENT");
    expect(report.derivativeVerified).toBe(true);
  });

  it("strictly complies with Doctrine §5 by excluding forbidden affirmative claims", async () => {
    const packet = {
      spec_version: "1.0",
      release_id: "rel_sec",
      original_sha256: "1".repeat(64),
      hashes: {
        derivative: { filename: "clean.pdf", sha256: "2".repeat(64) },
      },
      anchor: { type: "rfc3161-tsa" },
    };

    const report = await verifyReleasePacket(packet);

    // Top-line status must strictly be one of the two evidence-bound values
    expect(["INTERNALLY CONSISTENT", "INTERNALLY INCONSISTENT"]).toContain(report.status);

    // Check all check names and details for forbidden claim words
    const allText = report.checks.map((c) => `${c.name} ${c.detail}`).join(" ").toLowerCase();
    expect(allText).not.toContain("court-proof");
    expect(allText).not.toContain("unforgeable");
    expect(allText).not.toContain("guaranteed clean");
    // Ensure RFC 3161 check does not falsely claim the token was verified in-browser
    expect(allText).not.toContain("timestamp authority token verified");
  });

  it("fails verification when derivative bytes do not match declared hash", async () => {
    const packet = {
      spec_version: "1.0",
      release_id: "rel_123",
      original_sha256: "a".repeat(64),
      hashes: {
        derivative: { filename: "clean.pdf", sha256: "b".repeat(64) },
      },
      anchor: { type: "none" },
    };

    const report = await verifyReleasePacket(packet, {
      derivative: {
        name: "clean.pdf",
        data: new TextEncoder().encode("tampered bytes").buffer,
      },
    });

    expect(report.status).toBe("INTERNALLY INCONSISTENT");
    expect(report.derivativeVerified).toBe(false);
    const hashCheck = report.checks.find((c) => c.name === "Derivative Content Digest");
    expect(hashCheck?.pass).toBe(false);
  });
});
