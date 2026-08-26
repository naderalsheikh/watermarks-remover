// Matches service/app/main.py bulk_jobs's hard cap ("at most 100
// documents per bulk request") -- kept in sync by eye, not imported,
// since the frontend has no build-time link to the backend's constant;
// tests/test_bulk_jobs.py pins the backend side of this number.
//
// Extracted (web/app/matters/view/page.tsx, 2026-08-25) so the exact
// boundary -- 100 is allowed, 101 is not -- is pinned by a unit test
// instead of only being implicit in a handful of `> BULK_MAX_DOCUMENTS`
// comparisons scattered across the bulk bar and BulkRunPanel.
export const BULK_MAX_DOCUMENTS = 100;

export function isOverBulkCap(selectedCount: number): boolean {
  return selectedCount > BULK_MAX_DOCUMENTS;
}

// How many documents to deselect to get back under the cap -- 0 when
// already at or under it, never negative.
export function bulkCapOverflow(selectedCount: number): number {
  return Math.max(0, selectedCount - BULK_MAX_DOCUMENTS);
}
