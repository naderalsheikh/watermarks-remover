import type { AttentionItem, AttentionType } from "./types";

// Extracted from web/app/dashboard/page.tsx so the deep-link contract,
// the tab-filtering logic, and the admin-scope disclosure copy are all
// plain functions a unit test can pin down without rendering the page —
// same reasoning as web/lib/productionReview.ts. This is the kind of
// logic that's easy to silently break while touching nearby JSX (a
// renamed anchor id, a flipped comparison in the scope note) with
// nothing catching it until someone notices live.

// Minimal structural contract these link builders actually need. Named
// because GET /v1/jobs rows (CrossMatterJobRow, the cross-matter problem
// list) carry the same fields with `type` = the job's terminal status —
// same link semantics, so they reuse these builders without a cast.
export type AttentionLinkTarget = {
  type: string; // AttentionType, or a JobStatus on the cross-matter list
  matter_id: string;
  job_id?: string;
  document_id?: string;
};

// Precise per-type destinations, not one generic "open the matter" link
// for everything: a job-bearing item (unreviewed/refused/failed) lands on
// that exact job, with unreviewed_findings scrolling straight to the
// warning section (web/app/matters/job/page.tsx's ?highlight= handling);
// stale has no job to point at, so it lands on the matter itself.
export function attentionPrimaryHref(item: AttentionLinkTarget): string {
  if (item.job_id) {
    const base = `/matters/job?matter=${item.matter_id}&job=${item.job_id}`;
    return item.type === "unreviewed_findings" ? `${base}&highlight=unreviewed` : base;
  }
  return `/matters/view?id=${item.matter_id}`;
}

export function attentionMatterHref(item: AttentionLinkTarget): string {
  const base = `/matters/view?id=${item.matter_id}`;
  return item.document_id ? `${base}&doc=${item.document_id}` : base;
}

export type AttentionTab = "all" | AttentionType;

export function filterAttentionByTab(
  attention: AttentionItem[],
  tab: AttentionTab,
): AttentionItem[] {
  return attention.filter((a) => tab === "all" || a.type === tab);
}

// One count per tab, "all" included -- what the dashboard's filter-tab
// row renders as "<label> · <count>".
export function attentionTabCounts(attention: AttentionItem[]): Record<AttentionTab, number> {
  const counts: Record<AttentionTab, number> = {
    all: attention.length,
    unreviewed_findings: 0,
    refused: 0,
    failed: 0,
    stale: 0,
  };
  for (const item of attention) counts[item.type] += 1;
  return counts;
}

// The "NEEDS ATTENTION" section's admin-scope disclosure: null when the
// principal administers every readable matter (nothing to explain --
// full visibility, same as before the read/admin split existed).
// Otherwise names exactly why "stale" items are scoped down, per the
// 2026-08-25 operator decision that stale detection is audit-derived and
// therefore admin-gated the same as GET .../audit.
export function attentionScopeNote(adminMatters: number, totalMatters: number): string | null {
  if (adminMatters >= totalMatters) return null;
  if (adminMatters === 0) {
    return (
      "You have read access only, not admin, on these matters — stale-matter detection " +
      "is hidden (it's derived from audit activity, which requires admin). Refused, " +
      "failed, and unreviewed-findings items below are still shown in full."
    );
  }
  return (
    `Stale-matter detection is shown only for the ${adminMatters} of ` +
    `${totalMatters} matter${totalMatters === 1 ? "" : "s"} you ` +
    "administer — it's derived from audit activity, which requires admin."
  );
}

// The "RECENT ACTIVITY" section's parallel disclosure -- recent[] is an
// audit-event feed the same way GET .../audit is, so it's scoped to
// admin matters entirely, not partially like the attention items above.
export function recentScopeNote(adminMatters: number, totalMatters: number): string | null {
  if (adminMatters >= totalMatters) return null;
  if (adminMatters === 0) {
    return (
      "This feed shows audit activity, which requires admin — you don't administer " +
      "any of your readable matters, so it's empty rather than incomplete."
    );
  }
  return (
    `Limited to the ${adminMatters} of ${totalMatters} matter` +
    `${totalMatters === 1 ? "" : "s"} you administer.`
  );
}

// Distinguishes "genuinely no activity yet" from "activity exists but
// you can't see any of it" -- the two read very differently and
// shouldn't share one empty-state message.
export function recentEmptyStateText(adminMatters: number, totalMatters: number): string {
  return adminMatters === 0 && totalMatters > 0
    ? "No activity visible — you have read access only, not admin, on these matters."
    : "No activity yet.";
}
