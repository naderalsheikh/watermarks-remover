// Extracted from web/app/matters/jobs/page.tsx: the server-side status
// filters the cross-matter jobs list offers, plus the deep-link param
// resolution. Pinned by vitest (crossMatterJobs.test.ts) because the
// filter strings are a wire contract with GET /v1/jobs — a typo'd tab
// value would 400 the endpoint for every operator who clicks that tab,
// and nothing else would catch it.

// The endpoint's full validation set (service/app/main.py
// list_jobs_across_matters) — every filter below must decompose into
// these words or the request fails with 400.
export const JOB_STATUS_ALLOWLIST = ["queued", "running", "done", "failed", "refused"] as const;

// Server-side status filters, each a legal comma-separated allowlist for
// GET /v1/jobs. The default is exactly the dashboard card's destination;
// the two fine-grained tabs mirror the dashboard attention section's own
// refused/failed tab split. Deliberately not a general jobs browser —
// queued/running/done jobs already surface per-matter, and this view
// exists to answer "what needs me" across matters.
export const PROBLEM_JOB_TABS = [
  { value: "refused,failed", label: "Failed / refused" },
  { value: "refused", label: "Refused" },
  { value: "failed", label: "Failed" },
] as const;

export const DEFAULT_PROBLEM_JOB_FILTER = "refused,failed";

// Resolves a ?status= deep-link param to the filter this page will send.
// Only a value the page itself would send is forwarded; anything else
// falls back to the default instead of handing the endpoint a string it
// would 400 on. Empty string is a legal no-param answer, not an error.
export function resolveProblemJobFilter(param: string | null): string {
  if (param !== null && PROBLEM_JOB_TABS.some((t) => t.value === param)) return param;
  return DEFAULT_PROBLEM_JOB_FILTER;
}
