import { describe, expect, it } from "vitest";
import {
  buildLegalJustifications,
  KNOWN_LEGAL_BASES,
  LEGAL_BASIS_LABEL,
  legalBasisLabel,
  type SubtypeBasisState,
} from "./legalBasis";
import { LEGAL_BASIS_VALUES } from "./types";

function row(basis: string, note = ""): SubtypeBasisState {
  return { basis: basis as SubtypeBasisState["basis"], note };
}

describe("buildLegalJustifications", () => {
  it("sends a real basis with its note for a kept subtype", () => {
    const out = buildLegalJustifications(
      { comments_and_notes: "keep" },
      { comments_and_notes: row("privilege", "AC-2024 protocol") },
    );
    expect(out).toEqual({
      comments_and_notes: { basis: "privilege", note: "AC-2024 protocol" },
    });
  });

  it("returns undefined when nothing was supplied — the additive contract", () => {
    // No bases at all: field omitted from the POST, release fully valid.
    expect(buildLegalJustifications({}, {})).toBeUndefined();
    // Bases present but every entry is the unspecified fallback: the
    // engine's own fallback needs no help from the UI.
    expect(
      buildLegalJustifications(
        { comments_and_notes: "keep" },
        { comments_and_notes: row("unspecified", "") },
      ),
    ).toBeUndefined();
  });

  it("drops a basis for a subtype the operator approved (stripped) — nothing survives to justify", () => {
    const out = buildLegalJustifications(
      { comments_and_notes: "approve", tracked_changes: "keep" },
      {
        comments_and_notes: row("privilege", "would be silently unused"),
        tracked_changes: row("court_order", "Docket 12"),
      },
    );
    // Only the kept subtype's basis is sent: the payload must not claim a
    // basis for content that was stripped.
    expect(out).toEqual({ tracked_changes: { basis: "court_order", note: "Docket 12" } });
  });

  it("treats an undecided subtype as keep — same default the decision payload itself uses", () => {
    // decisions[st] is absent when the operator never touched the row,
    // which the decision payload already sends as "keep"; the basis
    // must follow the same default, not a stricter one.
    const out = buildLegalJustifications(
      {},
      { comments_and_notes: row("work_product", "prep materials") },
    );
    expect(out).toEqual({ comments_and_notes: { basis: "work_product", note: "prep materials" } });
  });

  it("sends a real basis even with an empty note", () => {
    const out = buildLegalJustifications(
      { hidden_structure: "keep" },
      { hidden_structure: row("litigation_hold", "") },
    );
    expect(out).toEqual({ hidden_structure: { basis: "litigation_hold", note: "" } });
  });

  it("truncates a note to 1000 chars — the backend's own cap", () => {
    const out = buildLegalJustifications(
      { hidden_structure: "keep" },
      { hidden_structure: row("other", "x".repeat(2500)) },
    );
    expect(out?.hidden_structure.note.length).toBe(1000);
  });
});

describe("legal basis vocabulary", () => {
  it("matches LEGAL_BASIS_VALUES from types.ts (the backend's controlled 10-value enum)", () => {
    // The label map must cover exactly the controlled vocabulary —
    // a missing entry would render a raw slug (acceptable fallback), but
    // an EXTRA entry would advertise a basis the backend rejects with a
    // failed job.
    expect(Object.keys(LEGAL_BASIS_LABEL).sort()).toEqual([...LEGAL_BASIS_VALUES].sort());
  });

  it("exposes the known list for the <select> so the two can never drift", () => {
    expect(KNOWN_LEGAL_BASES).toEqual(LEGAL_BASIS_VALUES);
  });

  it("falls back to the raw slug for an unmapped basis", () => {
    expect(legalBasisLabel("future_basis")).toBe("future_basis");
    expect(legalBasisLabel("privilege")).toBe("Privilege");
  });
});
