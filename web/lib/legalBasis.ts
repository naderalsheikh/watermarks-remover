import { LEGAL_BASIS_VALUES, type LegalBasis, type LegalJustifications } from "./types";

// Human-readable labels for the controlled legal-basis vocabulary, same
// deliberate-literal pattern as RECIPIENT_TYPE_LABEL above: a basis added
// server-side without a frontend update still renders as its raw slug
// rather than disappearing.
export const LEGAL_BASIS_LABEL: Record<string, string> = {
  unspecified: "Unspecified",
  privilege: "Privilege",
  work_product: "Work product",
  pii_confidentiality: "PII confidentiality",
  relevance: "Relevance",
  court_order: "Court order",
  client_instruction: "Client instruction",
  litigation_hold: "Litigation hold",
  gdpr_access: "GDPR access request",
  other: "Other",
};

export function legalBasisLabel(basis: string): string {
  return LEGAL_BASIS_LABEL[basis] ?? basis;
}

// The per-subtype basis/note state ReleasePanel tracks alongside the
// existing Approve/Keep decision state. A basis is the evidentiary
// ground for content that SURVIVES the derivative -- an approved
// (stripped) finding has no retained content to justify, so the basis
// select only appears on kept rows in the panel.
export type SubtypeBasisState = {
  basis: LegalBasis;
  note: string;
};

// Build the release payload's legal_justifications from the panel's two
// state maps (decisions: subtype -> approve|keep, bases: subtype ->
// {basis, note}). Rules:
// - Only KEPT subtypes get an entry -- a basis supplied for a row the
//   operator set to "Approve (strip)" is silently unused by the backend
//   (the finding doesn't survive), so it's dropped here rather than sent,
//   keeping the payload honest about what it claims to justify.
// - An explicitly chosen non-"unspecified" basis is sent even with an
//   empty note; "unspecified" (or no row at all) is NOT sent -- there's
//   nothing to record beyond the engine's own fallback.
// - Returns undefined when nothing applies -- the field is omitted from
//   the POST entirely, which must remain a fully supported release.
export function buildLegalJustifications(
  decisions: Record<string, "approve" | "keep">,
  bases: Record<string, SubtypeBasisState>,
): LegalJustifications | undefined {
  const out: LegalJustifications = {};
  for (const [subtype, row] of Object.entries(bases)) {
    if ((decisions[subtype] ?? "keep") !== "keep" || row.basis === "unspecified") {
      continue;
    }
    out[subtype] = { basis: row.basis, note: row.note.slice(0, 1000) };
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

// For the fallback path (no inspect results, so no per-finding review):
// kept approve-default findings carry the engine's "unspecified" fallback.
// There's no basis to offer there (the UI doesn't know which subtypes are
// present), so the disclosure is the whole surface -- the same honesty
// rule the certificate itself renders ("recorded as unspecified, not a
// legal determination").
export const FALLBACK_LEGAL_BASIS_DISCLOSURE =
  "Findings kept without review are recorded with no legal basis (the certificate will " +
  "show them as unspecified, not as a legal determination). Run Inspect first to supply " +
  "a per-finding legal basis for kept findings.";

export const KNOWN_LEGAL_BASES: readonly string[] = LEGAL_BASIS_VALUES;
