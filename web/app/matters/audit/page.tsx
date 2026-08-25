"use client";

import { Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { useApiData } from "@/lib/useApi";
import type { Audit, AuditEvent, Matter } from "@/lib/types";
import { Header } from "@/components/Header";

function shortHash(h: string): string {
  return h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h;
}

function PayloadCell({ payload }: { payload: Record<string, unknown> | null }) {
  if (!payload || Object.keys(payload).length === 0) {
    return <span className="text-muted">—</span>;
  }
  return (
    <code className="block max-w-md truncate text-xs text-muted" title={JSON.stringify(payload, null, 2)}>
      {JSON.stringify(payload)}
    </code>
  );
}

function EventRow({ ev }: { ev: AuditEvent }) {
  return (
    <tr className="border-b border-border align-top last:border-0">
      <td className="px-3 py-2 font-mono text-xs text-muted">{ev.seq}</td>
      <td className="px-3 py-2 font-mono text-xs">{new Date(ev.at).toLocaleString()}</td>
      <td className="px-3 py-2 text-sm font-medium">{ev.action}</td>
      <td className="px-3 py-2 font-mono text-xs">{ev.actor_id}</td>
      <td className="px-3 py-2">
        <PayloadCell payload={ev.payload} />
      </td>
      <td className="px-3 py-2 font-mono text-xs text-muted" title={ev.prev_hash}>
        {shortHash(ev.prev_hash)}
      </td>
      <td className="px-3 py-2 font-mono text-xs text-muted" title={ev.row_hash}>
        {shortHash(ev.row_hash)}
      </td>
    </tr>
  );
}

function AuditView({ matterId }: { matterId: string }) {
  const matterQ = useApiData<Matter>(
    () => api.get(`/v1/matters/${matterId}`),
    `matter:${matterId}`,
  );
  const auditQ = useApiData<Audit>(
    () => api.get(`/v1/matters/${matterId}/audit`),
    `audit:${matterId}`,
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

      {auditQ.loading && <p className="text-sm text-muted">Loading audit chain…</p>}
      {auditQ.error && <p className="text-sm text-red-600">{auditQ.error}</p>}

      {auditQ.data && (
        <>
          <div
            className={`mb-6 rounded-md border px-4 py-3 text-sm ${
              auditQ.data.chain_ok
                ? "border-emerald-600/30 bg-emerald-600/5 text-emerald-700 dark:text-emerald-400"
                : "border-red-600/30 bg-red-600/5 text-red-700 dark:text-red-400"
            }`}
          >
            <span className="font-semibold">
              {auditQ.data.chain_ok ? "Chain verified" : "Chain broken"}
            </span>
            <span className="text-muted"> — {auditQ.data.chain_detail}</span>
          </div>

          {auditQ.data.events.length === 0 ? (
            <p className="text-sm text-muted">No events recorded for this matter yet.</p>
          ) : (
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
                  </tr>
                </thead>
                <tbody>
                  {auditQ.data.events.map((ev) => (
                    <EventRow key={ev.id} ev={ev} />
                  ))}
                </tbody>
              </table>
            </div>
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
