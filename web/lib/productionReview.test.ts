import { describe, expect, it } from "vitest";
import { computeProductionReviewState, type InspectFetchState } from "./productionReview";
import type { Finding } from "./types";

function finding(overrides: Partial<Finding> & { policy_subtype?: string | null }): Finding {
  return {
    finding_id: "f1",
    category: "revision_history",
    subtype: "office_tracked_changes",
    format: "docx",
    location: { part: null, xpath_or_field: null, page: null, sheet: null, slide: null, offset: null, bbox: null, pane: "markup" },
    field: null,
    value_redacted: null,
    action_recommended: "flag",
    action_allowed_by_policy: ["approve", "keep"],
    content_visible: false,
    risk_level: "medium",
    confidence: "confirmed",
    removal_changes_visible_content: false,
    requires_approval: false,
    requires_attestation: false,
    notes: null,
    ...overrides,
  };
}

const loading: InspectFetchState = { loading: true, error: null, data: null };
const notLoaded: InspectFetchState = { loading: false, error: null, data: null };

function loaded(findings: Finding[]): InspectFetchState {
  return { loading: false, error: null, data: { result: { findings } } };
}

function failed(message: string): InspectFetchState {
  return { loading: false, error: message, data: null };
}

describe("computeProductionReviewState", () => {
  it("offers real per-finding review when inspect detail loaded successfully with approve-default findings", () => {
    const findings = [
      finding({ policy_subtype: "tracked_changes", requires_approval: true }),
      finding({ policy_subtype: "comments_and_notes", requires_approval: true }),
      finding({ policy_subtype: "authoring_props", requires_approval: false }), // strip, not approve
    ];
    const state = computeProductionReviewState(true, true, loaded(findings));
    expect(state.hasPerFindingReview).toBe(true);
    expect(state.needsFallbackGate).toBe(false);
    expect(state.approveSubtypes).toEqual(["comments_and_notes", "tracked_changes"]);
  });

  it("falls back to the acknowledgment gate, not silent pass-through, when the inspect detail fetch fails", () => {
    // The bug this guards: loading:false + error set + data:null used to
    // read as "review available" (hasPerFindingReview computed from
    // !loading alone), which meant approveSubtypes came out empty from
    // null data and the fallback gate never appeared -- Production could
    // be submitted with no per-finding decisions and no explicit
    // acknowledgment at all.
    const state = computeProductionReviewState(true, true, failed("network error"));
    expect(state.hasPerFindingReview).toBe(false);
    expect(state.needsFallbackGate).toBe(true);
    expect(state.approveSubtypes).toEqual([]);
  });

  it("falls back to the acknowledgment gate while the inspect detail fetch is still in flight", () => {
    const state = computeProductionReviewState(true, true, loading);
    expect(state.hasPerFindingReview).toBe(false);
    expect(state.needsFallbackGate).toBe(true);
  });

  it("falls back to the acknowledgment gate when there is no completed inspect job at all", () => {
    const state = computeProductionReviewState(true, false, notLoaded);
    expect(state.hasPerFindingReview).toBe(false);
    expect(state.needsFallbackGate).toBe(true);
    expect(state.approveSubtypes).toEqual([]);
  });

  it("has per-finding review with nothing to decide when inspect detail loaded but no finding needs approval", () => {
    const findings = [finding({ policy_subtype: "authoring_props", requires_approval: false })];
    const state = computeProductionReviewState(true, true, loaded(findings));
    expect(state.hasPerFindingReview).toBe(true);
    expect(state.needsFallbackGate).toBe(false);
    expect(state.approveSubtypes).toEqual([]);
  });

  it("never gates or reviews outside production, regardless of inspect state", () => {
    const findings = [finding({ policy_subtype: "tracked_changes", requires_approval: true })];
    expect(computeProductionReviewState(false, true, loaded(findings)).needsFallbackGate).toBe(
      false,
    );
    expect(computeProductionReviewState(false, true, failed("boom")).needsFallbackGate).toBe(
      false,
    );
  });
});
