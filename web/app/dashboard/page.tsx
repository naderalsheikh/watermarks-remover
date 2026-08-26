"use client";

import Link from "next/link";
import { api } from "@/lib/api";
import { useApiData } from "@/lib/useApi";
import type { AttentionItem, AttentionType, Dashboard } from "@/lib/types";
import { Header } from "@/components/Header";

const ATTENTION_META: Record<AttentionType, { label: string; badge: string }> = {
  // Production sanitize jobs that shipped with findings kept without an
  // operator decision — the trust-critical queue, so it gets the harshest
  // color of the three "something needs you" states.
  unreviewed_findings: {
    label: "Unreviewed findings",
    badge: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
  },
  refused: {
    label: "Refused job",
    badge: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  },
  failed: {
    label: "Failed job",
    badge: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
  },
  stale: {
    label: "Stale matter",
    badge: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  },
};

const JOB_STATUS_ORDER = ["queued", "running", "done", "failed", "refused"] as const;

const ACTION_LABEL: Record<string, string> = {
  "matter.create": "Created matter",
  "document.upload": "Uploaded document",
  "job.inspect": "Ran inspection",
  "job.sanitize": "Sanitized document",
  "acl.grant": "Granted access",
  "acl.revoke": "Revoked access",
  "bundle.download": "Downloaded bundle",
  "attest.issued": "Issued attestation",
  "attest.used": "Used attestation",
};

function formatTs(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime())
    ? ts
    : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function attentionHref(item: AttentionItem): string {
  const base = `/matters/view?id=${item.matter_id}`;
  return item.document_id ? `${base}&doc=${item.document_id}` : base;
}

export default function DashboardPage() {
  const { data, error, loading, reload } = useApiData<Dashboard>(
    () => api.get("/v1/dashboard"),
    "dashboard",
  );

  return (
    <>
      <Header />
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
        <div className="mb-8 flex items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Operator overview</h1>
            <p className="mt-1 text-sm text-muted">
              Server-computed totals across every matter you can read — not an estimate from
              loaded pages.
            </p>
          </div>
          <button
            onClick={reload}
            disabled={loading}
            className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-black/[0.03] dark:hover:bg-white/[0.03] disabled:opacity-50"
          >
            Refresh
          </button>
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
        {!loading && !error && data && (
          <>
            <section className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Link
                href="/matters"
                className="rounded-md border border-border px-4 py-3 hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
              >
                <p className="text-2xl font-semibold">{data.totals.matters}</p>
                <p className="text-sm text-muted">Matters</p>
              </Link>
              <div className="rounded-md border border-border px-4 py-3">
                <p className="text-2xl font-semibold">{data.totals.documents}</p>
                <p className="text-sm text-muted">Documents</p>
              </div>
              <Link
                href="/matters"
                className="rounded-md border border-red-600/40 px-4 py-3 hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
              >
                <p className="text-2xl font-semibold">
                  {data.totals.jobs.failed + data.totals.jobs.refused}
                </p>
                <p className="text-sm text-muted">Failed / refused jobs</p>
              </Link>
              <div className="rounded-md border border-border px-4 py-3">
                <p className="text-2xl font-semibold">{data.totals.jobs.done}</p>
                <p className="text-sm text-muted">Completed jobs</p>
              </div>
            </section>

            <section className="mb-8">
              <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted">
                JOBS BY STATUS
              </h2>
              <div className="flex flex-wrap gap-2">
                {JOB_STATUS_ORDER.map((status) => (
                  <span
                    key={status}
                    className="rounded-full border border-border px-3 py-1 text-sm"
                  >
                    {status} · {data.totals.jobs[status]}
                  </span>
                ))}
              </div>
            </section>

            <section className="mb-8">
              <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted">
                NEEDS ATTENTION
              </h2>
              {data.attention.length === 0 ? (
                <div className="rounded-md border border-dashed border-border px-4 py-8 text-center text-sm text-muted">
                  Nothing needs attention.
                </div>
              ) : (
                <ul className="divide-y divide-border rounded-md border border-border">
                  {data.attention.map((item) => {
                    const meta = ATTENTION_META[item.type];
                    return (
                      <li key={`${item.type}:${item.job_id ?? item.matter_id}`}>
                        <Link
                          href={attentionHref(item)}
                          className="flex items-center justify-between gap-4 px-4 py-3 hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                        >
                          <div className="min-w-0">
                            <p className="truncate">
                              <span
                                className={`mr-2 rounded px-2 py-0.5 text-xs font-medium ${meta.badge}`}
                              >
                                {meta.label}
                              </span>
                              <span className="font-medium">{item.matter_name}</span>
                              {item.document_name && (
                                <span className="text-muted"> · {item.document_name}</span>
                              )}
                            </p>
                            <p className="mt-0.5 text-sm text-muted">{item.detail}</p>
                          </div>
                          <time className="shrink-0 text-xs text-muted">
                            {formatTs(item.created_utc)}
                          </time>
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>

            <section>
              <h2 className="mb-2 text-sm font-semibold tracking-wide text-muted">
                RECENT ACTIVITY
              </h2>
              {data.recent.length === 0 ? (
                <div className="rounded-md border border-dashed border-border px-4 py-8 text-center text-sm text-muted">
                  No activity yet.
                </div>
              ) : (
                <ul className="divide-y divide-border rounded-md border border-border">
                  {data.recent.map((e, i) => (
                    <li key={`${e.at}:${e.action}:${i}`}>
                      <Link
                        href={`/matters/view?id=${e.matter_id}`}
                        className="flex items-center justify-between gap-4 px-4 py-2.5 text-sm hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                      >
                        <span className="truncate">
                          <span className="font-medium">{ACTION_LABEL[e.action] ?? e.action}</span>
                          <span className="text-muted"> · {e.matter_name}</span>
                        </span>
                        <time className="shrink-0 text-xs text-muted">{formatTs(e.at)}</time>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </>
        )}
      </main>
    </>
  );
}
