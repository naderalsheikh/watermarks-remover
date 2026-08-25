import type { Finding } from "./types";

// The subset of useApiData's return shape this needs — kept minimal and
// structural (not importing useApiData itself) so this stays a plain,
// framework-free function callers can unit test without rendering React.
export type InspectFetchState = {
  loading: boolean;
  error: string | null;
  data: { result?: { findings?: Finding[] } } | null;
};

export type ProductionReviewState = {
  hasPerFindingReview: boolean;
  needsFallbackGate: boolean;
  approveSubtypeCounts: Map<string, number>;
  approveSubtypes: string[];
};

// Extracted from SanitizePanel (web/app/matters/view/page.tsx) so the exact
// bug class it exists to prevent — a failed inspect-detail fetch reading as
// "review available" and silently dropping both the per-finding controls
// and the fallback acknowledgment gate — has a regression test that runs
// without needing a full component render.
//
// hasPerFindingReview requires *loaded* data (data truthy, error falsy,
// not loading), not just "loading finished": loading:false with error set
// and data null is exactly the failure case, and treating that as "review
// available" makes approveSubtypes compute to empty from null data, which
// used to read in the UI as "nothing to decide" — false, and with no
// acknowledgment gate either. The backend's own no-decision disclosure
// still catches the result afterward (policies.py's
// _approve_default_keep_records), but the pre-submit trust gate must not
// disappear just because a GET happened to fail.
export function computeProductionReviewState(
  isProduction: boolean,
  hasLatestInspectJob: boolean,
  inspect: InspectFetchState,
): ProductionReviewState {
  const approveSubtypeCounts = new Map<string, number>();
  for (const f of inspect.data?.result?.findings ?? []) {
    if (f.requires_approval && f.policy_subtype) {
      approveSubtypeCounts.set(
        f.policy_subtype,
        (approveSubtypeCounts.get(f.policy_subtype) ?? 0) + 1,
      );
    }
  }
  const approveSubtypes = [...approveSubtypeCounts.keys()].sort();
  const hasPerFindingReview =
    isProduction && hasLatestInspectJob && !inspect.loading && !inspect.error && !!inspect.data;
  const needsFallbackGate = isProduction && !hasPerFindingReview;
  return { hasPerFindingReview, needsFallbackGate, approveSubtypeCounts, approveSubtypes };
}
