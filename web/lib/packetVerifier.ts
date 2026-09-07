/**
 * Client-side CounselClear Release Packet Verifier (WebCrypto).
 *
 * Implements browser-based, zero-dependency offline verification matching the
 * core guarantees of tools/counselclear_verify_release_packet.py:
 * - Computes SHA-256 of derivative and sibling files using window.crypto.subtle
 * - Compares computed hashes against declared hashes in release_packet.json / release_result.json
 * - Checks anchor status (ed25519-operator, rfc3161, none)
 * - Summarizes disposition actions and asserted legal justifications
 * - Reports top-line outcome strictly as INTERNALLY CONSISTENT or INTERNALLY INCONSISTENT
 *   per Doctrine §5 (no "court-proof", "unforgeable", or "guaranteed clean" claims).
 */

export type CheckResult = {
  name: string;
  detail: string;
  pass: boolean;
};

export type VerificationReport = {
  status: "INTERNALLY CONSISTENT" | "INTERNALLY INCONSISTENT";
  artifactType: "release_packet" | "release_result" | "unknown";
  releaseId: string | null;
  jobId: string | null;
  documentId: string | null;
  matterId: string | null;
  policyId: string | null;
  jobStatus: string | null;
  generatedAt: string | null;
  originalSha256: string | null;
  derivativeDeclared: {
    filename?: string;
    sha256?: string;
    bytes?: number;
  } | null;
  derivativeVerified: boolean;
  anchor: {
    type: string;
    detail: string;
  };
  checks: CheckResult[];
  dispositions: {
    stripped: string[];
    kept: string[];
    refused: string[];
  };
  legalJustifications: Array<{
    subtype: string;
    basis: string;
    note: string;
  }>;
  limitations: string[];
};

export async function computeSha256(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  let source: BufferSource;
  if (typeof data === "string") {
    source = new TextEncoder().encode(data);
  } else if (data instanceof ArrayBuffer) {
    source = data;
  } else {
    const copy = new Uint8Array(data.byteLength);
    copy.set(data);
    source = copy.buffer;
  }

  const hashBuffer = await crypto.subtle.digest("SHA-256", source);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function parseJsonSafely(text: string): { data?: any; error?: string } {
  try {
    return { data: JSON.parse(text) };
  } catch (err) {
    return { error: err instanceof Error ? err.message : "Invalid JSON syntax" };
  }
}

export async function verifyReleasePacket(
  packetRaw: string | object,
  files: {
    derivative?: { name: string; data: ArrayBuffer };
    manifest?: { name: string; data: ArrayBuffer | string };
    report?: { name: string; data: ArrayBuffer | string };
    certificate?: { name: string; data: ArrayBuffer | string };
  } = {},
): Promise<VerificationReport> {
  const checks: CheckResult[] = [];
  const parsed =
    typeof packetRaw === "string" ? parseJsonSafely(packetRaw) : { data: packetRaw };

  if (parsed.error || !parsed.data) {
    return {
      status: "INTERNALLY INCONSISTENT",
      artifactType: "unknown",
      releaseId: null,
      jobId: null,
      documentId: null,
      matterId: null,
      policyId: null,
      jobStatus: null,
      generatedAt: null,
      originalSha256: null,
      derivativeDeclared: null,
      derivativeVerified: false,
      anchor: { type: "none", detail: "Unverifiable (malformed JSON)" },
      checks: [
        {
          name: "JSON Parsing",
          detail: `Failed to parse release packet: ${parsed.error}`,
          pass: false,
        },
      ],
      dispositions: { stripped: [], kept: [], refused: [] },
      legalJustifications: [],
      limitations: [],
    };
  }

  const p = parsed.data;
  if (!p || typeof p !== "object") {
    return {
      status: "INTERNALLY INCONSISTENT",
      artifactType: "unknown",
      releaseId: null,
      jobId: null,
      documentId: null,
      matterId: null,
      policyId: null,
      jobStatus: null,
      generatedAt: null,
      originalSha256: null,
      derivativeDeclared: null,
      derivativeVerified: false,
      anchor: { type: "none", detail: "Unverifiable (invalid object payload)" },
      checks: [
        {
          name: "Object Validation",
          detail: "Parsed JSON payload is not an object",
          pass: false,
        },
      ],
      dispositions: { stripped: [], kept: [], refused: [] },
      legalJustifications: [],
      limitations: [],
    };
  }

  const isPacket = Boolean(p.hashes && typeof p.hashes === "object");
  const isResult = Boolean((p.manifest_sha256 || p.audit_refs) && !p.hashes);
  const artifactType = isPacket ? "release_packet" : isResult ? "release_result" : "unknown";

  checks.push({
    name: "Artifact Structure",
    detail:
      artifactType !== "unknown"
        ? `Identified as ${artifactType.replace("_", " ")} (spec ${p.spec_version ?? "1.0"})`
        : "Unrecognized artifact schema structure (missing hashes or audit references)",
    pass: artifactType !== "unknown",
  });

  // Extract core identifiers safely
  const releaseId = typeof p.release_id === "string" ? p.release_id : null;
  const jobId = typeof p.job_id === "string" ? p.job_id : typeof p.packet_id === "string" ? p.packet_id : null;
  const documentId = typeof p.document_id === "string" ? p.document_id : null;
  const matterId = typeof p.matter_id === "string" ? p.matter_id : null;
  const policyId =
    typeof p.policy === "object" && p.policy !== null
      ? typeof p.policy.id === "string" ? p.policy.id : null
      : typeof p.policy_id === "string" ? p.policy_id : null;
  const jobStatus = typeof p.status === "string" ? p.status : null;
  const generatedAt = typeof p.generated_at === "string" ? p.generated_at : null;

  // Check original sha256 presence and format
  const originalSha256 = typeof p.original_sha256 === "string" ? p.original_sha256 : null;
  const isOriginalHashValid = originalSha256 !== null && /^[a-f0-9]{64}$/i.test(originalSha256);
  checks.push({
    name: "Original Digest Binding",
    detail: originalSha256
      ? isOriginalHashValid
        ? `Original file SHA-256 recorded (${originalSha256.slice(0, 16)}…)`
        : `Invalid original SHA-256 format: expected 64-character hexadecimal digest`
      : "Missing required original_sha256 digest binding",
    pass: isOriginalHashValid,
  });

  // Extract declared derivative
  let derivativeDeclared: { filename?: string; sha256?: string; bytes?: number } | null = null;
  if (p.hashes && typeof p.hashes === "object" && p.hashes.derivative && typeof p.hashes.derivative === "object") {
    derivativeDeclared = p.hashes.derivative;
  } else if (p.derivative && typeof p.derivative === "object") {
    derivativeDeclared = p.derivative;
  }

  // Check declared derivative sha256
  const declaredDerivativeSha =
    typeof derivativeDeclared?.sha256 === "string" ? derivativeDeclared.sha256 : null;
  const isDerivativeHashValid =
    declaredDerivativeSha !== null && /^[a-f0-9]{64}$/i.test(declaredDerivativeSha);

  const isTerminalFailure = jobStatus === "refused" || jobStatus === "failed";
  if (!isTerminalFailure) {
    checks.push({
      name: "Derivative Hash Declaration",
      detail: declaredDerivativeSha
        ? isDerivativeHashValid
          ? `Declared derivative SHA-256 present (${declaredDerivativeSha.slice(0, 16)}…)`
          : `Invalid declared derivative SHA-256 format`
        : "Missing declared derivative SHA-256 in release packet",
      pass: isDerivativeHashValid,
    });
  }

  // Verify derivative bytes if provided
  let derivativeVerified = false;
  if (files.derivative && isDerivativeHashValid && declaredDerivativeSha) {
    const computed = await computeSha256(files.derivative.data);
    const matches = computed.toLowerCase() === declaredDerivativeSha.toLowerCase();
    derivativeVerified = matches;
    checks.push({
      name: "Derivative Content Digest",
      detail: matches
        ? `SHA-256 matches declared hash (${computed.slice(0, 16)}…)`
        : `Derivative hash mismatch: expected ${declaredDerivativeSha}, computed ${computed}`,
      pass: matches,
    });
  } else if (isDerivativeHashValid && declaredDerivativeSha) {
    checks.push({
      name: "Derivative Content Digest",
      detail: `Declared SHA-256 present (${declaredDerivativeSha.slice(0, 16)}…); upload derivative file to verify bytes`,
      pass: true,
    });
  }

  // Verify manifest sibling if present
  if (files.manifest && p.hashes && typeof p.hashes.manifest_json_sha256 === "string") {
    const computed = await computeSha256(files.manifest.data);
    const matches = computed.toLowerCase() === p.hashes.manifest_json_sha256.toLowerCase();
    checks.push({
      name: "Manifest Digest",
      detail: matches
        ? `manifest.json matches declared digest (${computed.slice(0, 16)}…)`
        : `manifest.json mismatch: expected ${p.hashes.manifest_json_sha256}, computed ${computed}`,
      pass: matches,
    });
  }

  // Verify report sibling if present
  if (files.report && p.hashes && typeof p.hashes.report_json_sha256 === "string") {
    const computed = await computeSha256(files.report.data);
    const matches = computed.toLowerCase() === p.hashes.report_json_sha256.toLowerCase();
    checks.push({
      name: "Report Digest",
      detail: matches
        ? `report.json matches declared digest (${computed.slice(0, 16)}…)`
        : `report.json mismatch: expected ${p.hashes.report_json_sha256}, computed ${computed}`,
      pass: matches,
    });
  }

  // Verify certificate sibling if present
  if (files.certificate && p.hashes && typeof p.hashes.certificate_html_sha256 === "string") {
    const computed = await computeSha256(files.certificate.data);
    const matches = computed.toLowerCase() === p.hashes.certificate_html_sha256.toLowerCase();
    checks.push({
      name: "Certificate Digest",
      detail: matches
        ? `certificate.html matches declared digest (${computed.slice(0, 16)}…)`
        : `certificate.html mismatch: expected ${p.hashes.certificate_html_sha256}, computed ${computed}`,
      pass: matches,
    });
  }

  // Check anchor (Doctrine §5: strict evidence-bound reporting, no false claim of cryptographic proof)
  const rawAnchor = p && typeof p.anchor === "object" && p.anchor !== null ? p.anchor : {};
  const rawType = typeof rawAnchor.type === "string" ? rawAnchor.type : "none";
  let anchorType = rawType;
  let anchorDetail = "Not externally anchored";

  if (rawType === "ed25519-operator" || rawType === "ed25519") {
    anchorType = "ed25519-operator";
    anchorDetail = "Operator cryptographic signature present (Ed25519)";
    const sigStr = typeof rawAnchor.signature === "string" ? rawAnchor.signature : "";
    checks.push({
      name: "Custody Signature Notice",
      detail: `Operator signature structure present (${sigStr.slice(0, 16)}…); cryptographic signature validation is handled server-side/offline`,
      pass: true,
    });
  } else if (rawType === "rfc3161-tsa" || rawType === "rfc3161") {
    anchorType = "rfc3161";
    anchorDetail = "RFC 3161 cryptographic timestamp token present";
    checks.push({
      name: "External Anchor Record",
      detail: "RFC 3161 timestamp token structure present (cryptographic signature not verified in browser)",
      pass: true,
    });
  } else {
    anchorType = "none";
    checks.push({
      name: "External Anchoring Notice",
      detail: "Packet is self-consistent but not anchored to an external timestamp authority",
      pass: true,
    });
  }

  // Parse dispositions from action_records, actions, or legal_justifications
  const dispositions = { stripped: [] as string[], kept: [] as string[], refused: [] as string[] };
  const addAction = (action: string, subtype: string) => {
    const act = action.toLowerCase();
    const label = subtype ? `${subtype} (${action})` : action;
    if (act === "keep" || act === "retained") dispositions.kept.push(label);
    else if (act === "strip" || act === "approve" || act === "removed") dispositions.stripped.push(label);
    else if (act === "refuse" || act === "refused") dispositions.refused.push(label);
  };

  if (Array.isArray(p.action_records)) {
    for (const r of p.action_records) {
      if (r && typeof r === "object") addAction(String(r.action ?? ""), String(r.subtype ?? ""));
    }
  }
  if (Array.isArray(p.actions)) {
    for (const a of p.actions) {
      if (a && typeof a === "object") {
        addAction(String(a.action ?? ""), String(a.subtype ?? ""));
      } else {
        const s = String(a).toLowerCase();
        if (s.includes("strip") || s.includes("removed")) dispositions.stripped.push(String(a));
        else if (s.includes("keep") || s.includes("retained")) dispositions.kept.push(String(a));
        else if (s.includes("refuse")) dispositions.refused.push(String(a));
      }
    }
  }
  if (
    dispositions.stripped.length === 0 &&
    dispositions.kept.length === 0 &&
    Array.isArray(p.legal_justifications)
  ) {
    for (const lj of p.legal_justifications) {
      if (lj && typeof lj === "object") {
        addAction(String(lj.action ?? "keep"), String(lj.subtype ?? ""));
      }
    }
  }

  // Parse legal justifications safely (supporting both nested and flat shapes)
  const legalJustifications: Array<{ subtype: string; basis: string; note: string }> = [];
  if (Array.isArray(p.legal_justifications)) {
    for (const item of p.legal_justifications) {
      if (item && typeof item === "object") {
        const lj =
          item.legal_justification && typeof item.legal_justification === "object"
            ? item.legal_justification
            : null;
        const basis = String(lj?.basis ?? item.basis ?? "unspecified");
        const note = String(lj?.note ?? item.note ?? "");
        legalJustifications.push({
          subtype: String(item.subtype ?? "general"),
          basis,
          note,
        });
      }
    }
  } else if (p.legal_justifications && typeof p.legal_justifications === "object") {
    for (const [subtype, item] of Object.entries(p.legal_justifications)) {
      if (item && typeof item === "object") {
        const raw = item as Record<string, any>;
        const lj =
          raw.legal_justification && typeof raw.legal_justification === "object"
            ? raw.legal_justification
            : null;
        legalJustifications.push({
          subtype,
          basis: String(lj?.basis ?? raw.basis ?? "unspecified"),
          note: String(lj?.note ?? raw.note ?? ""),
        });
      }
    }
  }

  const limitations = Array.isArray(p.limitations) ? p.limitations.map(String) : [];

  const allPassed = checks.every((c) => c.pass);
  const status = allPassed ? "INTERNALLY CONSISTENT" : "INTERNALLY INCONSISTENT";

  return {
    status,
    artifactType,
    releaseId,
    jobId,
    documentId,
    matterId,
    policyId,
    jobStatus,
    generatedAt,
    originalSha256,
    derivativeDeclared,
    derivativeVerified,
    anchor: {
      type: anchorType,
      detail: anchorDetail,
    },
    checks,
    dispositions,
    legalJustifications,
    limitations,
  };
}
