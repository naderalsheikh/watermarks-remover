"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { useApiData } from "@/lib/useApi";
import type { Finding, Job, Manifest } from "@/lib/types";
import { Header } from "@/components/Header";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

const RISK_ORDER: Finding["risk_level"][] = ["critical", "high", "medium", "low", "info"];
const RISK_COLOR: Record<Finding["risk_level"], string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  low: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  info: "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400",
};

function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function FindingRow({ f }: { f: Finding }) {
  return (
    <li className="flex items-start justify-between gap-4 px-4 py-2.5">
      <div className="min-w-0">
        <p className="text-sm font-medium">{titleCase(f.subtype)}</p>
        <p className="text-xs text-muted">
          {f.location.pane}
          {f.location.page != null ? ` · page ${f.location.page}` : ""}
          {f.field ? ` · ${f.field}` : ""}
          {f.notes ? ` · ${f.notes}` : ""}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <span className="text-xs text-muted">{f.action_recommended}</span>
        <span
          className={`rounded px-1.5 py-0.5 text-xs font-medium ${RISK_COLOR[f.risk_level]}`}
        >
          {f.risk_level}
        </span>
      </div>
    </li>
  );
}

function FindingsByCategory({ findings }: { findings: Finding[] }) {
  const byCategory = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byCategory.get(f.category) ?? [];
    list.push(f);
    byCategory.set(f.category, list);
  }
  for (const list of byCategory.values()) {
    list.sort((a, b) => RISK_ORDER.indexOf(a.risk_level) - RISK_ORDER.indexOf(b.risk_level));
  }
  const categories = [...byCategory.keys()].sort();

  if (categories.length === 0) {
    return <p className="text-sm text-muted">No findings.</p>;
  }

  return (
    <div className="space-y-4">
      {categories.map((cat) => (
        <div key={cat} className="rounded-md border border-border">
          <div className="border-b border-border bg-black/[0.02] px-4 py-2 text-sm font-medium dark:bg-white/[0.02]">
            {titleCase(cat)}{" "}
            <span className="text-xs font-normal text-muted">
              ({byCategory.get(cat)!.length})
            </span>
          </div>
          <ul className="divide-y divide-border">
            {byCategory.get(cat)!.map((f) => (
              <FindingRow key={f.finding_id} f={f} />
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

function SanitizeManifestView({ manifest }: { manifest: Manifest }) {
  return (
    <div className="space-y-4">
      <div className="rounded-md border border-border px-4 py-3 text-sm">
        <span className="font-medium">{manifest.derivative.filename}</span>{" "}
        <span className="text-muted">({formatBytes(manifest.derivative.bytes)})</span>
      </div>

      {manifest.findings_before.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-medium">What was found</h3>
          <ul className="list-inside list-disc space-y-1 text-sm text-muted">
            {manifest.findings_before.map((f, i) => (
              <li key={i}>{f}</li>
            ))}
          </ul>
        </div>
      )}

      {manifest.actions.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-medium">Actions taken</h3>
          <ul className="list-inside list-disc space-y-1 text-sm text-muted">
            {manifest.actions.map((a, i) => (
              <li key={i}>{a}</li>
            ))}
          </ul>
        </div>
      )}

      {manifest.verification.checks.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-medium">Verification checks</h3>
          <ul className="divide-y divide-border rounded-md border border-border">
            {manifest.verification.checks.map((c) => (
              <li key={c.name} className="flex items-center justify-between px-3 py-2 text-sm">
                <span>
                  {c.name} <span className="text-muted">— {c.detail}</span>
                </span>
                <span className={c.pass ? "text-emerald-600" : "text-red-600"}>
                  {c.pass ? "pass" : "fail"}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function JobView({ matterId, jobId }: { matterId: string; jobId: string }) {
  const { data: job, error, loading } = useApiData(
    () => api.get<Job>(`/v1/matters/${matterId}/jobs/${jobId}`),
    `job:${matterId}:${jobId}`,
  );
  const manifestReady = job?.kind === "sanitize" && job.status === "done";
  const { data: manifest } = useApiData(
    () =>
      manifestReady
        ? api.get<Manifest>(`/v1/matters/${matterId}/jobs/${jobId}/manifest`)
        : Promise.resolve(null),
    `manifest:${matterId}:${jobId}:${manifestReady}`,
  );
  const [includeOriginal, setIncludeOriginal] = useState(false);

  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
      <Link href={`/matters/view?id=${matterId}`} className="text-sm text-muted hover:text-foreground">
        ← Matter
      </Link>

      {loading && <p className="mt-4 text-sm text-muted">Loading…</p>}
      {error && <p className="mt-4 text-sm text-red-600">{error}</p>}

      {job && (
        <>
          <div className="mt-2 mb-6">
            <h1 className="text-2xl font-semibold tracking-tight capitalize">{job.kind} job</h1>
            <p className="mt-1 text-sm text-muted">
              {job.status}
              {job.kind === "sanitize" ? ` · ${job.policy_id}` : ""} · started{" "}
              {new Date(job.created_utc).toLocaleString()}
            </p>
            {job.error && <p className="mt-2 text-sm text-red-600">{job.error}</p>}
            {job.result?.verification_pass !== undefined && (
              <p className="mt-2 text-sm">
                Verification:{" "}
                <span className={job.result.verification_pass ? "text-emerald-600" : "text-red-600"}>
                  {job.result.verification_pass ? "passed" : "failed"}
                </span>
              </p>
            )}
          </div>

          {job.status === "done" && job.kind === "sanitize" && (
            <div className="mb-6 flex items-center gap-3 rounded-md border border-border p-3">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={includeOriginal}
                  onChange={(e) => setIncludeOriginal(e.target.checked)}
                />
                Include original in bundle
              </label>
              <a
                href={`/v1/matters/${matterId}/jobs/${jobId}/bundle${includeOriginal ? "?include_original=true" : ""}`}
                className="ml-auto rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:opacity-90"
              >
                Download bundle
              </a>
            </div>
          )}

          {job.kind === "inspect" && (
            <>
              <h2 className="mb-3 text-lg font-semibold tracking-tight">Findings</h2>
              <FindingsByCategory findings={job.result?.findings ?? []} />
            </>
          )}
          {job.kind === "sanitize" && manifest && (
            <>
              <h2 className="mb-3 text-lg font-semibold tracking-tight">Manifest</h2>
              <SanitizeManifestView manifest={manifest} />
            </>
          )}
        </>
      )}
    </main>
  );
}

function JobPageInner() {
  const params = useSearchParams();
  const matterId = params.get("matter");
  const jobId = params.get("job");
  if (!matterId || !jobId) {
    return (
      <main className="mx-auto max-w-5xl flex-1 px-6 py-8 text-sm text-red-600">
        Missing matter or job id.
      </main>
    );
  }
  return <JobView matterId={matterId} jobId={jobId} />;
}

export default function JobPage() {
  return (
    <>
      <Header />
      <Suspense fallback={<div className="flex-1 px-6 py-8 text-sm text-muted">Loading…</div>}>
        <JobPageInner />
      </Suspense>
    </>
  );
}
