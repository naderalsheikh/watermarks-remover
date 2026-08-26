"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import { useApiData } from "@/lib/useApi";
import { usePaginatedList } from "@/lib/usePaginatedList";
import type { Audit, AuditEvent, AuthConfig, Matter } from "@/lib/types";
import { Header } from "@/components/Header";

const PAGE_SIZE = 100;

type AuditMeta = { chain_ok: boolean; chain_detail: string };

function shortHash(h: string): string {
  return h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h;
}

type Category = "matter" | "document" | "job" | "access" | "download";

const CATEGORY_LABEL: Record<Category, string> = {
  matter: "Matter",
  document: "Documents",
  job: "Jobs",
  access: "Access",
  download: "Downloads",
};

// The small, fixed action vocabulary this product's audit chain actually
// emits (service/app/main.py's append_event call sites) — grouped for the
// filter chips below, not re-derived from a guess at naming conventions.
function categoryOf(action: string): Category {
  if (action.startsWith("matter.")) return "matter";
  if (action.startsWith("document.")) return "document";
  if (action.startsWith("acl.")) return "access";
  if (action.startsWith("bundle.")) return "download";
  return "job"; // job.inspect, job.sanitize, attest.issued, attest.used
}

function jobIdFromPayload(payload: Record<string, unknown> | null): string | null {
  const id = payload?.job_id;
  return typeof id === "string" ? id : null;
}

function documentIdFromPayload(payload: Record<string, unknown> | null): string | null {
  const id = payload?.document_id;
  return typeof id === "string" ? id : null;
}

// GENESIS in service/app/audit.py — duplicated here (not imported: this is
// a frontend TS file, that's a Python module) so the browser can verify
// row-to-row hash continuity itself instead of only trusting the server's
// own chain_ok verdict. A tampered row would still show chain_ok: false
// from the server, but this also shows *which* link broke.
const GENESIS = "0".repeat(64);

function chainContinuity(events: AuditEvent[]): Map<string, boolean> {
  const linked = new Map<string, boolean>();
  let prevRowHash = GENESIS;
  for (const ev of events) {
    linked.set(ev.id, ev.prev_hash === prevRowHash);
    prevRowHash = ev.row_hash;
  }
  return linked;
}

function PayloadCell({ payload }: { payload: Record<string, unknown> | null }) {
  if (!payload || Object.keys(payload).length === 0) {
    return <span className="text-muted">—</span>;
  }
  return (
    <code
      className="block max-w-md truncate text-xs text-muted"
      title={JSON.stringify(payload, null, 2)}
    >
      {JSON.stringify(payload)}
    </code>
  );
}

function EventRow({
  ev,
  matterId,
  linked,
  isLocalOperator,
}: {
  ev: AuditEvent;
  matterId: string;
  linked: boolean;
  isLocalOperator: boolean;
}) {
  const jobId = jobIdFromPayload(ev.payload);
  const docId = documentIdFromPayload(ev.payload);
  return (
    <tr className="border-b border-border align-top last:border-0">
      <td className="px-3 py-2 font-mono text-xs text-muted">{ev.seq}</td>
      <td className="px-3 py-2 font-mono text-xs">{formatTimestamp(ev.at)}</td>
      <td className="px-3 py-2 text-sm font-medium">
        <span className="mr-1.5 inline-block rounded bg-black/[0.05] px-1.5 py-0.5 text-xs font-normal capitalize text-muted dark:bg-white/[0.08]">
          {CATEGORY_LABEL[categoryOf(ev.action)]}
        </span>
        {jobId ? (
          <Link href={`/matters/job?matter=${matterId}&job=${jobId}`} className="hover:underline">
            {ev.action}
          </Link>
        ) : docId ? (
          <Link
            href={`/matters/view?id=${matterId}&doc=${docId}`}
            className="hover:underline"
          >
            {ev.action}
          </Link>
        ) : (
          ev.action
        )}
      </td>
      <td className="px-3 py-2 font-mono text-xs">
        {ev.actor_id}
        {isLocalOperator && (
          <span
            className="ml-1 text-muted"
            title="Shared local-password identity, not a distinguishable individual — see the Access panel."
          >
            (shared)
          </span>
        )}
      </td>
      <td className="px-3 py-2">
        <PayloadCell payload={ev.payload} />
      </td>
      <td className="px-3 py-2 font-mono text-xs text-muted" title={ev.prev_hash}>
        {shortHash(ev.prev_hash)}
      </td>
      <td className="px-3 py-2 font-mono text-xs text-muted" title={ev.row_hash}>
        {shortHash(ev.row_hash)}
      </td>
      <td className="px-3 py-2 text-center text-xs" title={linked ? "prev_hash matches the row before it" : "prev_hash does NOT match the row before it"}>
        {linked ? (
          <span className="text-emerald-600">✓</span>
        ) : (
          <span className="font-medium text-red-600">✗</span>
        )}
      </td>
    </tr>
  );
}

function AuditView({ matterId }: { matterId: string }) {
  const matterQ = useApiData<Matter>(
    () => api.get(`/v1/matters/${matterId}`),
    `matter:${matterId}`,
  );
  const authQ = useApiData<AuthConfig>(() => api.get("/v1/auth/config"), "auth-config");
  const auditQ = usePaginatedList<AuditEvent, AuditMeta>(
    (offset) =>
      api
        .get<Audit>(`/v1/matters/${matterId}/audit?limit=${PAGE_SIZE}&offset=${offset}`)
        .then((r) => ({
          items: r.events,
          total: r.total,
          meta: { chain_ok: r.chain_ok, chain_detail: r.chain_detail },
        })),
    `audit:${matterId}`,
  );
  const [categoryFilter, setCategoryFilter] = useState<"all" | Category>("all");

  const oidc = authQ.data?.oidc_enabled ?? false;
  // Valid because loading always starts at offset 0 and "Load more" only
  // ever appends the next contiguous page (see usePaginatedList) — the
  // loaded events array is never a gap in the middle of the sequence, so
  // checking it against GENESIS is checking a real prefix of the chain,
  // not an arbitrary window.
  const linked = chainContinuity(auditQ.items);
  const anyLinkBroken = [...linked.values()].some((ok) => !ok);
  const visible = auditQ.items.filter(
    (ev) => categoryFilter === "all" || categoryOf(ev.action) === categoryFilter,
  );

  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
      <Link href={`/matters/view?id=${matterId}`} className="text-sm text-muted hover:text-foreground">
        ← Back to matter
      </Link>
      <h1 className="mb-1 mt-2 text-2xl font-semibold tracking-tight">Audit log</h1>
      <p className="mb-6 text-sm text-muted">
        {matterQ.data?.name ?? (matterQ.loading ? "Loading…" : "Matter")}
      </p>
      {matterQ.error && <p className="mb-6 text-sm text-red-600">{matterQ.error}</p>}

      {!authQ.loading && !oidc && (
        <div className="mb-6 rounded-md border border-amber-600/40 bg-amber-600/10 px-4 py-3 text-sm text-amber-800 dark:text-amber-300">
          Local-password mode: every actor below reading{" "}
          <code className="font-mono">operator</code> is the same shared local identity, not a
          distinguishable individual. See the{" "}
          <Link href={`/matters/access?id=${matterId}`} className="underline hover:text-foreground">
            Access panel
          </Link>{" "}
          for what that means for this matter.
        </div>
      )}

      {auditQ.loading && <p className="text-sm text-muted">Loading audit chain…</p>}
      {auditQ.error && <p className="text-sm text-red-600">{auditQ.error}</p>}

      {!auditQ.loading && !auditQ.error && auditQ.meta && (
        <>
          <div
            className={`mb-3 rounded-md border px-4 py-3 text-sm ${
              auditQ.meta.chain_ok
                ? "border-emerald-600/30 bg-emerald-600/5 text-emerald-700 dark:text-emerald-400"
                : "border-red-600/30 bg-red-600/5 text-red-700 dark:text-red-400"
            }`}
          >
            <span className="font-semibold">
              {auditQ.meta.chain_ok ? "Chain verified" : "Chain broken"}
            </span>
            <span className="text-muted"> — {auditQ.meta.chain_detail}</span>
          </div>
          {/* Independent of chain_ok above (which is the server's own
              recomputation against the FULL chain, not just this page):
              this is the same continuity check run again in the browser
              against the rows the server actually sent, so a compromised
              or bugged server response can't just claim chain_ok: true
              over a list that doesn't actually link up. It only covers
              what's loaded so far — chain_ok above is still the authority
              on the full chain. */}
          {anyLinkBroken && (
            <div className="mb-6 rounded-md border border-red-600/30 bg-red-600/5 px-4 py-3 text-sm text-red-700 dark:text-red-400">
              This browser independently checked row-to-row hash continuity and found at least
              one broken link (✗ column below) — do not treat this timeline as trustworthy until
              that&apos;s resolved.
            </div>
          )}

          {auditQ.items.length === 0 ? (
            <p className="text-sm text-muted">No events recorded for this matter yet.</p>
          ) : (
            <>
              <div className="mb-3 flex flex-wrap gap-1.5">
                <button
                  onClick={() => setCategoryFilter("all")}
                  className={`rounded px-2 py-1 text-xs ${
                    categoryFilter === "all"
                      ? "bg-accent text-white"
                      : "border border-border hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                  }`}
                >
                  All
                </button>
                {(Object.keys(CATEGORY_LABEL) as Category[]).map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setCategoryFilter(cat)}
                    className={`rounded px-2 py-1 text-xs ${
                      categoryFilter === cat
                        ? "bg-accent text-white"
                        : "border border-border hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                    }`}
                  >
                    {CATEGORY_LABEL[cat]}
                  </button>
                ))}
              </div>
              {auditQ.total > auditQ.items.length && (
                <p className="mb-2 text-xs text-muted">
                  Loaded {auditQ.items.length} of {auditQ.total} events.
                </p>
              )}
              {categoryFilter !== "all" && (
                <p className="mb-2 text-xs text-muted">
                  Showing {visible.length} of {auditQ.items.length} loaded events — the full
                  numbered sequence (# column) is preserved even though rows are hidden, so gaps
                  are visible rather than silently renumbered.
                </p>
              )}
              <div className="overflow-x-auto rounded-md border border-border">
                <table className="w-full border-collapse text-left">
                  <thead>
                    <tr className="border-b border-border text-xs uppercase tracking-wide text-muted">
                      <th className="px-3 py-2 font-medium">#</th>
                      <th className="px-3 py-2 font-medium">When</th>
                      <th className="px-3 py-2 font-medium">Action</th>
                      <th className="px-3 py-2 font-medium">Actor</th>
                      <th className="px-3 py-2 font-medium">Payload</th>
                      <th className="px-3 py-2 font-medium">Prev hash</th>
                      <th className="px-3 py-2 font-medium">Row hash</th>
                      <th className="px-3 py-2 font-medium" title="Does this row's prev_hash match the previous row's row_hash?">
                        Linked
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((ev) => (
                      <EventRow
                        key={ev.id}
                        ev={ev}
                        matterId={matterId}
                        linked={linked.get(ev.id) ?? false}
                        isLocalOperator={!oidc && ev.actor_id === "operator"}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
              {auditQ.hasMore && (
                <button
                  type="button"
                  onClick={auditQ.loadMore}
                  disabled={auditQ.loadingMore}
                  className="mt-3 w-full rounded-md border border-border px-3 py-2 text-sm font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
                >
                  {auditQ.loadingMore
                    ? "Loading…"
                    : `Load more (${auditQ.items.length} of ${auditQ.total})`}
                </button>
              )}
            </>
          )}
        </>
      )}
    </main>
  );
}

function AuditInner() {
  const id = useSearchParams().get("id");
  if (!id) {
    return <main className="mx-auto max-w-5xl flex-1 px-6 py-8 text-sm text-red-600">Missing matter id.</main>;
  }
  return <AuditView matterId={id} />;
}

export default function AuditPage() {
  return (
    <>
      <Header />
      <Suspense fallback={<div className="flex-1 px-6 py-8 text-sm text-muted">Loading…</div>}>
        <AuditInner />
      </Suspense>
    </>
  );
}
