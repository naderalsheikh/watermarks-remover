"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { usePaginatedList } from "@/lib/usePaginatedList";
import { attentionMatterHref, attentionPrimaryHref } from "@/lib/dashboardAttention";
import {
  PROBLEM_JOB_TABS,
  resolveProblemJobFilter,
} from "@/lib/crossMatterJobs";
import type { CrossMatterJobRow } from "@/lib/types";
import { Header } from "@/components/Header";

// Same badge vocabulary the dashboard's ATTENTION_META uses for these two
// types — refused is a correct policy verdict (orange, distinct from
// breakage), failed means something broke before a verdict. The backend's
// `type` is the job's terminal status, so only these two values reach these
// lookups on this page.
const STATUS_BADGE: Record<string, string> = {
  refused: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  failed: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
};

const TYPE_LABEL: Record<string, string> = {
  refused: "Refused job",
  failed: "Failed job",
};

const PAGE_SIZE = 50;

function formatTs(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime())
    ? ts
    : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function JobsListInner() {
  const params = useSearchParams();
  // ?status= deep-link support: resolveProblemJobFilter forwards only a
  // value the page itself would send, so a bad param falls back to the
  // default instead of handing the endpoint a string it would 400 on.
  const [status, setStatus] = useState(() => resolveProblemJobFilter(params.get("status")));

  const {
    items: jobs,
    total,
    error,
    loading,
    loadingMore,
    hasMore,
    loadMore,
  } = usePaginatedList(
    (offset) =>
      api
        .get<{ jobs: CrossMatterJobRow[]; total: number }>(
          `/v1/jobs?status=${encodeURIComponent(status)}&limit=${PAGE_SIZE}&offset=${offset}`,
        )
        .then((r) => ({ items: r.jobs, total: r.total })),
    // The filter is part of the list key: switching tabs resets to page 1
    // of the new server-side result rather than appending to the old one.
    `jobs:${status}`,
  );

  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
      <div className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">Failed / refused jobs</h1>
        <p className="mt-1 text-sm text-muted">
          Across every matter you can read — newest first. Open a job to see why it ended this
          way and re-run it with different choices.
        </p>
      </div>

      <div className="mb-2 flex flex-wrap gap-1.5">
        {PROBLEM_JOB_TABS.map((t) => (
          <button
            key={t.value}
            onClick={() => setStatus(t.value)}
            aria-pressed={status === t.value}
            className={`rounded-md px-2 py-1.5 text-xs ${
              status === t.value
                ? "bg-accent text-white"
                : "border border-border hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {loading && (
        <div className="animate-pulse space-y-2">
          <div className="h-12 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
          <div className="h-12 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
        </div>
      )}
      {error && (
        <p className="rounded-md border border-red-600/30 bg-red-600/5 px-3 py-2 text-sm text-red-600">
          {error}
        </p>
      )}

      {!loading && !error && jobs.length === 0 && (
        <div className="rounded-md border border-dashed border-border px-4 py-8 text-center text-sm text-muted">
          No {PROBLEM_JOB_TABS.find((t) => t.value === status)?.label.toLowerCase()} jobs in your
          readable matters.
        </div>
      )}

      {!loading && !error && jobs.length > 0 && (
        <>
          {total > jobs.length && (
            <p className="mb-2 text-xs text-muted">
              Loaded {jobs.length} of {total} jobs.
            </p>
          )}
          <ul className="divide-y divide-border rounded-md border border-border shadow-card">
            {jobs.map((j) => (
              <li key={j.job_id ?? `${j.matter_id}:${j.created_utc}`} className="px-4 py-3">
                <div className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
                  <Link href={attentionPrimaryHref(j)} className="min-w-0 hover:underline sm:flex-1">
                    <p>
                      <span
                        className={`mr-2 rounded px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[j.type] ?? ""}`}
                      >
                        {TYPE_LABEL[j.type] ?? j.type}
                      </span>
                      <span className="font-medium">{j.matter_name}</span>
                      {j.document_name && (
                        <span className="text-muted"> · {j.document_name}</span>
                      )}
                    </p>
                  </Link>
                  <time className="shrink-0 text-xs text-muted">{formatTs(j.created_utc)}</time>
                </div>
                <p className="mt-0.5 text-sm text-muted">{j.detail}</p>
                <div className="mt-2 flex flex-wrap gap-3 text-xs">
                  <Link
                    href={attentionPrimaryHref(j)}
                    className="font-medium text-accent hover:underline"
                  >
                    Open job
                  </Link>
                  <Link
                    href={attentionMatterHref(j)}
                    className="text-muted hover:text-foreground hover:underline"
                  >
                    Open matter
                  </Link>
                  {/* Admin-gated like the job page's own audit link
                      (hasMatterPerm(perms, "admin")): the audit page
                      403s a read-only principal, so the link is hidden
                      unless the backend row truthfully says this
                      principal holds admin on that job's matter
                      (can_view_audit, MINOR-6 review 2026-08-30) --
                      never a link promising a page it can't open. */}
                  {j.can_view_audit && (
                    <Link
                      href={`/matters/audit?id=${j.matter_id}`}
                      className="text-muted hover:text-foreground hover:underline"
                    >
                      View audit
                    </Link>
                  )}
                </div>
              </li>
            ))}
          </ul>
          {hasMore && (
            <button
              type="button"
              onClick={loadMore}
              disabled={loadingMore}
              className="mt-3 w-full rounded-md border border-border px-3 py-2 text-sm font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
            >
              {loadingMore ? "Loading…" : `Load more (${jobs.length} of ${total})`}
            </button>
          )}
        </>
      )}
    </main>
  );
}

export default function JobsAcrossMattersPage() {
  return (
    <>
      <Header />
      <Suspense fallback={<div className="flex-1 px-6 py-8"><div className="h-8 w-40 animate-pulse rounded-md bg-black/[0.06] dark:bg-white/[0.06]" /></div>}>
        <JobsListInner />
      </Suspense>
    </>
  );
}
