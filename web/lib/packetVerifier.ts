/**
 * Browser-local checks of CounselClear's published artifact schemas and supplied
 * file digests. This is a partial verifier: it does not authenticate signatures,
 * timestamps, audit chains, or archive membership. Missing evidence never passes.
 */
import packetSchema from "../../service/scripts/schemas/release_packet.schema.json";
import legacyPacketSchema from "../../service/scripts/schemas/archive/release_packet.v1.schema.json";
import resultSchema from "../../service/scripts/schemas/release_result.schema.json";

export type CheckStatus = "passed" | "failed" | "not_checked" | "unavailable";
export type CheckResult = { name: string; detail: string; status: CheckStatus };
export type VerificationReport = {
  status: "INTERNALLY INCONSISTENT" | "VERIFICATION INCOMPLETE";
  artifactType: "release_packet" | "release_result" | "unknown";
  releaseId: string | null;
  jobId: string | null;
  documentId: string | null;
  matterId: string | null;
  policyId: string | null;
  jobStatus: string | null;
  generatedAt: string | null;
  originalSha256: string | null;
  derivativeDeclared: { filename: string | null; sha256: string | null } | null;
  derivativeVerified: boolean;
  anchor: { type: string; detail: string };
  checks: CheckResult[];
  dispositions: { stripped: string[]; kept: string[]; refused: string[] };
  legalJustifications: Array<{ subtype: string; basis: string; note: string }>;
  limitations: string[];
};

type LocalFile = { name: string; data: ArrayBuffer | string };
export type VerificationFiles = {
  derivative?: LocalFile;
  original?: LocalFile;
  manifest?: LocalFile;
  report?: LocalFile;
  certificate?: LocalFile;
  readme?: LocalFile;
};

// Digests of the actual published schema bytes, not JSON reserialization.
// The drift regression test recomputes these from those same source files.
export const PACKET_SCHEMA_PINS: Record<number, string> = {
  1: "b30beca62036ce8db4976dd145ad93e12c9564a21871bcc165cacec803146a11",
  2: "d079550073fb80aa93206c85b5d5abe55d6ca1e2932592a77abbeb34d6b04d89",
};

type JsonObject = Record<string, unknown>;
type Schema = {
  $ref?: string;
  $defs?: Record<string, Schema>;
  type?: string | string[];
  const?: unknown;
  enum?: unknown[];
  required?: string[];
  properties?: Record<string, Schema>;
  additionalProperties?: boolean;
  items?: Schema;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minimum?: number;
};

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Only the keywords used by the bundled contracts are implemented. A test
 * rejects new validation keywords so schema evolution cannot silently weaken us. */
function validateShape(value: unknown, schema: Schema, root = schema, path = "$", errors: string[] = []): string[] {
  if (errors.length >= 25) return errors;
  if (schema.$ref) {
    const ref = schema.$ref.split("/");
    const definition = ref[0] === "#" && ref[1] === "$defs" ? root.$defs?.[ref[2]] : undefined;
    if (!definition) errors.push(`${path}: unsupported schema reference`);
    else validateShape(value, definition, root, path, errors);
    return errors;
  }
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const matches = types.some((type) => {
      if (type === "null") return value === null;
      if (type === "object") return isObject(value);
      if (type === "array") return Array.isArray(value);
      if (type === "integer") return typeof value === "number" && Number.isSafeInteger(value);
      return typeof value === type;
    });
    if (!matches) {
      errors.push(`${path}: expected ${types.join(" or ")}`);
      return errors;
    }
  }
  if ("const" in schema && value !== schema.const) errors.push(`${path}: expected ${JSON.stringify(schema.const)}`);
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${path}: unsupported value`);
  if (typeof value === "string") {
    const length = Array.from(value).length;
    if (schema.minLength !== undefined && length < schema.minLength) errors.push(`${path}: must not be empty`);
    if (schema.maxLength !== undefined && length > schema.maxLength) errors.push(`${path}: exceeds ${schema.maxLength} characters`);
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) errors.push(`${path}: invalid format`);
  }
  if (typeof value === "number" && schema.minimum !== undefined && value < schema.minimum) errors.push(`${path}: must be at least ${schema.minimum}`);
  if (Array.isArray(value) && schema.items) {
    for (let i = 0; i < value.length && errors.length < 25; i++) validateShape(value[i], schema.items, root, `${path}[${i}]`, errors);
  }
  if (isObject(value)) {
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(value, key)) errors.push(`${path}.${key}: required field missing`);
    }
    for (const [key, entry] of Object.entries(value)) {
      if (errors.length >= 25) break;
      const property = Object.hasOwn(schema.properties ?? {}, key) ? schema.properties?.[key] : undefined;
      if (property) validateShape(entry, property, root, `${path}.${key}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}.${key}: unexpected field`);
    }
  }
  return errors;
}

export async function computeSha256(data: ArrayBuffer | Uint8Array | string): Promise<string> {
  let source: BufferSource;
  if (typeof data === "string") source = new TextEncoder().encode(data);
  else if (data instanceof ArrayBuffer) source = data;
  else {
    const copy = new Uint8Array(data.byteLength);
    copy.set(data);
    source = copy.buffer;
  }
  const hashBuffer = await crypto.subtle.digest("SHA-256", source);
  return Array.from(new Uint8Array(hashBuffer), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function parseJsonSafely<T = unknown>(text: string): { data?: T; error?: string } {
  try { return { data: JSON.parse(text) as T }; }
  catch { return { error: "Invalid JSON syntax. Use the complete, unmodified JSON artifact." }; }
}

function emptyReport(checks: CheckResult[]): VerificationReport {
  return {
    status: checks.some((check) => check.status === "failed") ? "INTERNALLY INCONSISTENT" : "VERIFICATION INCOMPLETE",
    artifactType: "unknown", releaseId: null, jobId: null, documentId: null,
    matterId: null, policyId: null, jobStatus: null, generatedAt: null,
    originalSha256: null, derivativeDeclared: null, derivativeVerified: false,
    anchor: { type: "unknown", detail: "Anchor evidence has not been checked." },
    checks, dispositions: { stripped: [], kept: [], refused: [] },
    legalJustifications: [], limitations: [],
  };
}

export async function verifyReleasePacket(packetRaw: unknown, files: VerificationFiles = {}): Promise<VerificationReport> {
  const parsed = typeof packetRaw === "string" ? parseJsonSafely(packetRaw) : { data: packetRaw };
  if (parsed.error || !isObject(parsed.data)) {
    return emptyReport([{ name: "JSON Object", detail: parsed.error ?? "The artifact must be a JSON object, not an array, null, or a scalar.", status: "failed" }]);
  }
  const p = parsed.data;
  const isPacket = Object.hasOwn(p, "packet_id") || Object.hasOwn(p, "hashes");
  const isResult = !isPacket && (Object.hasOwn(p, "profile_id") || Object.hasOwn(p, "certificate_html_sha256"));
  if (!isPacket && !isResult) {
    return emptyReport([{ name: "Artifact Schema", detail: "This is not a recognized release_packet.json or release_result.json. Select the complete emitted artifact.", status: "failed" }]);
  }
  const checks: CheckResult[] = [];
  const report = emptyReport(checks);
  report.artifactType = isPacket ? "release_packet" : "release_result";
  const schema = isPacket ? p.schema_version === 1 ? legacyPacketSchema : packetSchema : resultSchema;
  const shapeErrors = validateShape(p, schema);
  checks.push({ name: "Artifact Schema", status: shapeErrors.length ? "failed" : "passed", detail: shapeErrors.length ? shapeErrors.join("; ") : `Required fields, types, allowed values, and nested shapes match ${schema.title}. This checks structure, not authenticity.` });
  if (shapeErrors.length) {
    report.status = "INTERNALLY INCONSISTENT";
    return report;
  }

  // These fields are used only after the entire known artifact shape validates.
  report.releaseId = p.release_id as string | null;
  report.jobId = p.job_id as string;
  report.documentId = p.document_id as string;
  report.matterId = p.matter_id as string;
  report.policyId = isPacket ? (p.policy as JsonObject).id as string | null : p.policy_id as string;
  report.jobStatus = p.status as string;
  report.generatedAt = p.generated_at as string;
  report.originalSha256 = p.original_sha256 as string;
  report.limitations = p.limitations as string[];

  if (isPacket) {
    const version = p.schema_version as number | undefined;
    const digest = p.schema_sha256 as string | undefined;
    if (version === undefined && digest === undefined) {
      checks.push({ name: "Published Schema Pin", status: "unavailable", detail: "No schema pin is recorded. Legacy packets may omit this evidence." });
    } else if (version === undefined || digest === undefined) {
      checks.push({ name: "Published Schema Pin", status: "failed", detail: "A schema pin must contain both schema_version and schema_sha256." });
    } else if (!PACKET_SCHEMA_PINS[version]) {
      checks.push({ name: "Published Schema Pin", status: "unavailable", detail: `Schema version ${version} is not bundled with this browser verifier. Its declared contract cannot be checked here.` });
    } else {
      const matches = digest === PACKET_SCHEMA_PINS[version];
      checks.push({ name: "Published Schema Pin", status: matches ? "passed" : "failed", detail: matches ? `The declared schema digest matches the bundled published v${version} contract.` : "The schema digest does not match the published contract for the declared version." });
    }
  }

  async function checkFile(name: string, expected: string | null, file?: LocalFile) {
    if (!expected) {
      checks.push({ name, status: "unavailable", detail: file ? `Cannot compare ${file.name}: this artifact declares no digest for it.` : "This artifact declares no digest for this file." });
      return false;
    }
    if (!file) {
      checks.push({ name, status: "not_checked", detail: "No file supplied. The recorded digest has not been compared with file bytes." });
      return false;
    }
    try {
      const actual = await computeSha256(file.data);
      const matches = actual === expected;
      checks.push({ name, status: matches ? "passed" : "failed", detail: matches ? `${file.name}: supplied bytes match the declared SHA-256.` : `${file.name}: SHA-256 mismatch. Expected ${expected}; computed ${actual}.` });
      return matches;
    } catch {
      checks.push({ name, status: "unavailable", detail: "The browser could not compute SHA-256. Retry in a browser with WebCrypto over HTTPS or localhost, or use the offline verifier." });
      return false;
    }
  }

  await checkFile("Original Content Digest", report.originalSha256, files.original);
  if (isPacket) {
    const hashes = p.hashes as JsonObject;
    report.derivativeDeclared = hashes.derivative as VerificationReport["derivativeDeclared"];
    const derivative = report.derivativeDeclared!;
    const complete = typeof derivative.filename === "string" && derivative.filename.length > 0 && typeof derivative.sha256 === "string";
    const absent = derivative.filename === null && derivative.sha256 === null;
    if (!complete && (!absent || p.status === "done")) {
      checks.push({ name: "Derivative Declaration", status: "failed", detail: "A completed packet needs a derivative filename and digest; a refused or failed packet may omit both." });
    }
    report.derivativeVerified = await checkFile("Derivative Content Digest", derivative.sha256, files.derivative);
    await checkFile("Manifest Content Digest", hashes.manifest_json_sha256 as string, files.manifest);
    await checkFile("Report Content Digest", hashes.report_json_sha256 as string, files.report);
    await checkFile("Certificate Content Digest", hashes.certificate_html_sha256 as string, files.certificate);
    await checkFile("README Content Digest", hashes.readme_txt_sha256 as string, files.readme);
  } else {
    // A release result never declares a derivative, including when status=done.
    await checkFile("Derivative Content Digest", null, files.derivative);
    await checkFile("Certificate Content Digest", p.certificate_html_sha256 as string, files.certificate);
    for (const key of ["manifest", "report", "readme"] as const) {
      if (files[key]) await checkFile(`${key} Content Digest`, null, files[key]);
    }
  }

  const signature = p.signature as JsonObject | undefined;
  checks.push({ name: "Operator Signature", status: signature ? "not_checked" : "unavailable", detail: signature ? "Signature fields have the expected shape. Ed25519 signature validity and operator identity are not checked in this browser; use the offline verifier with a trusted operator key." : isPacket ? "This packet is unsigned. No operator signature is available to authenticate its declarations." : "A release result is not signed. Any signature_ref points to the separate release packet; it does not authenticate this JSON." });
  const anchor = p.anchor as JsonObject;
  report.anchor.type = anchor.type as string;
  if (anchor.type === "none") {
    report.anchor.detail = isResult ? "No external anchor for this release result's own bytes. The separate packet may carry an anchor." : "No external timestamp anchor is declared.";
    checks.push({ name: "External Timestamp", status: "unavailable", detail: report.anchor.detail });
  } else if (anchor.type === "ed25519-operator") {
    report.anchor.detail = "Operator signature declared; no external timestamp authority is declared.";
    if (!signature || (anchor.reference !== null && anchor.reference !== signature.key_id)) {
      checks.push({ name: "Operator Anchor Reference", status: signature ? "failed" : "unavailable", detail: !signature ? "An operator anchor is declared, but no packet signature is available. The label does not authenticate this unsigned artifact." : "The operator anchor reference does not match signature.key_id." });
    }
    checks.push({ name: "External Timestamp", status: "unavailable", detail: report.anchor.detail });
  } else if (anchor.type === "rfc3161-tsa") {
    const reference = anchor.reference;
    const hasReference = typeof reference === "string" && reference.length > 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(reference);
    const hasDigest = typeof anchor.digest === "string" && /^[0-9a-f]{64}$/.test(anchor.digest);
    report.anchor.detail = "RFC 3161 timestamp claimed; token and authority trust have not been verified.";
    if (!signature || !hasReference || !hasDigest) {
      checks.push({ name: "Timestamp Claim Fields", status: "failed", detail: "An RFC 3161 claim requires a top-level packet signature, a signature digest, and a nonempty base64 token reference." });
    } else {
      try {
        const signatureBytes = Uint8Array.from((signature.value as string).match(/../g)!, (hex) => parseInt(hex, 16));
        const matches = await computeSha256(signatureBytes) === anchor.digest;
        checks.push({ name: "Timestamp Signature Digest", status: matches ? "passed" : "failed", detail: matches ? "The declared anchor digest matches the packet's signature bytes. This does not validate the timestamp token." : "The declared anchor digest does not match the packet's signature bytes." });
      } catch {
        checks.push({ name: "Timestamp Signature Digest", status: "unavailable", detail: "The browser could not compute the signature digest." });
      }
    }
    checks.push({ name: "External Timestamp", status: "not_checked", detail: "Timestamp token parsing, message imprint, cryptographic signature, timestamp, and authority certificate trust require the offline verifier." });
  } else {
    report.anchor.detail = "Unrecognized anchor type; no anchor validation performed.";
    checks.push({ name: "External Timestamp", status: "unavailable", detail: `Unsupported anchor type: ${anchor.type}. No timestamp or signature evidence is inferred from this label.` });
  }

  checks.push({ name: "Custody and Artifact Cross-checks", status: "not_checked", detail: "Audit-chain commitments, agreement between artifacts, and complete archive membership are not checked here. Run the offline verifier on the complete packet for those checks." });
  for (const raw of p.legal_justifications as JsonObject[]) {
    const justification = raw.legal_justification as JsonObject;
    const subtype = raw.subtype as string;
    const action = raw.action as string;
    report.legalJustifications.push({ subtype, basis: justification.basis as string, note: justification.note as string });
    const label = `${subtype} (${action})`;
    if (["strip", "removed"].includes(action.toLowerCase())) report.dispositions.stripped.push(label);
    else if (["keep", "retained"].includes(action.toLowerCase())) report.dispositions.kept.push(label);
    else if (["refuse", "refused"].includes(action.toLowerCase())) report.dispositions.refused.push(label);
  }
  // Even matching supplied bytes cannot authenticate a self-declared packet.
  report.status = checks.some((check) => check.status === "failed") ? "INTERNALLY INCONSISTENT" : "VERIFICATION INCOMPLETE";
  return report;
}
