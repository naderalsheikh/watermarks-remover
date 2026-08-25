"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { computeProductionReviewState } from "@/lib/productionReview";
import { useApiData } from "@/lib/useApi";
import type { Document, Job, Matter, Policy } from "@/lib/types";
import { Header } from "@/components/Header";
import { StatusBadge } from "@/components/StatusBadge";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

// Human-readable labels for the policy-engine subtypes a per-finding
// Production decision can apply to (SUBTYPES in policies.py) — only the
// ones with an "approve" default ever appear here.
function subtypeLabel(subtype: string): string {
  return subtype.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function SanitizePanel({
  matterId,
  docId,
  docJobs,
  policies,
  onClose,
  onDone,
}: {
  matterId: string;
  docId: string;
  docJobs: Job[];
  policies: Policy[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [policyId, setPolicyId] = useState(policies[0]?.id ?? "external_sharing");
  const [reason, setReason] = useState("");
  const [attest, setAttest] = useState(false);
  const [noDecisionAck, setNoDecisionAck] = useState(false);
  const [decisions, setDecisions] = useState<Record<string, "approve" | "keep">>({});
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const selected = policies.find((p) => p.id === policyId);
  const isProduction = policyId === "production";
  const isEvidenceOnly = policyId === "evidence_preservation";

  // production is the only policy with approve-default subtypes today. A
  // present approve-default finding is kept, not reviewed, unless it gets
  // an explicit decision. If the document has a completed inspect job, its
  // findings already carry policy_subtype/requires_approval (computed once
  // in worker.py, not duplicated here) -- so we can offer a real per-
  // finding Approve/Keep control instead of only the honest-but-blunt
  // fallback (warn, gate on an acknowledgment, let the manifest disclose
  // whatever got kept). Without an inspect job, there's nothing to show
  // per-finding, so the fallback is what runs.
  const latestInspectJob = docJobs.find((j) => j.kind === "inspect" && j.status === "done");
  const inspectQ = useApiData(
    () =>
      isProduction && latestInspectJob
        ? api.get<Job>(`/v1/matters/${matterId}/jobs/${latestInspectJob.id}`)
        : Promise.resolve(null),
    `inspect-for-decisions:${matterId}:${docId}:${isProduction}:${latestInspectJob?.id ?? ""}`,
  );
  const { hasPerFindingReview, needsFallbackGate, approveSubtypeCounts, approveSubtypes } =
    computeProductionReviewState(isProduction, !!latestInspectJob, inspectQ);

  async function submit() {
    setSubmitting(true);
    setSubmitError(null);
    try {
      const finding_decisions =
        hasPerFindingReview && approveSubtypes.length > 0
          ? Object.fromEntries(approveSubtypes.map((st) => [st, decisions[st] ?? "keep"]))
          : undefined;
      await api.post(`/v1/matters/${matterId}/documents/${docId}/sanitize-jobs`, {
        policy_id: policyId,
        reason,
        signature_break_attestation: attest,
        ...(finding_decisions ? { finding_decisions } : {}),
      });
      onDone();
      onClose();
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Sanitize failed to start");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mt-2 space-y-3 rounded-md border border-border bg-black/[0.02] p-3 dark:bg-white/[0.02]">
      <div>
        <label className="mb-1 block text-xs font-medium">Policy</label>
        <select
          value={policyId}
          onChange={(e) => setPolicyId(e.target.value)}
          className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
        >
          {policies.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
        </select>
        {selected && <p className="mt-1 text-xs text-muted">{selected.description}</p>}
      </div>

      {needsFallbackGate && (
        <div className="rounded-md border border-amber-600/40 bg-amber-600/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
          <p className="font-medium">
            {!latestInspectJob
              ? "No inspect results yet, so per-finding review isn't available."
              : inspectQ.loading
                ? "Loading findings for per-finding review…"
                : "Couldn't load findings for per-finding review."}
          </p>
          {latestInspectJob && !inspectQ.loading && inspectQ.error && (
            <p className="mt-1 font-mono text-red-700 dark:text-red-400">{inspectQ.error}</p>
          )}
          <p className="mt-1">
            Findings this policy marks &quot;approve&quot; (comments, tracked changes, hidden
            content, embedded objects, attachments, links, and more) will be{" "}
            <strong>kept as-is</strong>, not reviewed one by one. Each one will be listed
            explicitly in the resulting manifest — the derivative will not silently look
            cleaner than it is.{" "}
            {latestInspectJob && !inspectQ.loading && inspectQ.error
              ? "Retry loading findings, or proceed only once you accept that below."
              : "Run Inspect first to review findings individually instead."}
          </p>
          <label className="mt-2 flex items-center gap-2">
            <input
              type="checkbox"
              checked={noDecisionAck}
              onChange={(e) => setNoDecisionAck(e.target.checked)}
            />
            I understand undecided approve-default findings will be kept, not reviewed
          </label>
        </div>
      )}
      {hasPerFindingReview && approveSubtypes.length > 0 && (
        <div className="rounded-md border border-border p-3 text-xs">
          <p className="mb-2 font-medium">
            {approveSubtypes.length} finding type{approveSubtypes.length === 1 ? "" : "s"} need a
            decision
          </p>
          <ul className="space-y-2">
            {approveSubtypes.map((st) => {
              const count = approveSubtypeCounts.get(st) ?? 0;
              const value = decisions[st] ?? "keep";
              return (
                <li key={st} className="flex items-center justify-between gap-3">
                  <span>
                    {subtypeLabel(st)}{" "}
                    <span className="text-muted">
                      ({count} finding{count === 1 ? "" : "s"})
                    </span>
                  </span>
                  <select
                    value={value}
                    onChange={(e) =>
                      setDecisions((d) => ({ ...d, [st]: e.target.value as "approve" | "keep" }))
                    }
                    className="rounded border border-border bg-transparent px-1.5 py-1 text-xs outline-none focus:border-accent"
                  >
                    <option value="keep">Keep</option>
                    <option value="approve">Approve (strip)</option>
                  </select>
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {hasPerFindingReview && approveSubtypes.length === 0 && (
        <p className="text-xs text-muted">
          No approve-default findings present in the latest inspection — nothing to decide.
        </p>
      )}
      {isEvidenceOnly && (
        <div className="rounded-md border border-border bg-black/[0.02] px-3 py-2 text-xs text-muted dark:bg-white/[0.02]">
          Evidence preservation only inspects and records — it never produces a sanitized
          derivative.
        </div>
      )}

      <div>
        <label className="mb-1 block text-xs font-medium">Reason (optional)</label>
        <input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
        />
      </div>
      <label className="flex items-center gap-2 text-xs">
        <input type="checkbox" checked={attest} onChange={(e) => setAttest(e.target.checked)} />
        I attest to breaking a digital signature if this job requires it
      </label>
      {submitError && <p className="text-xs text-red-600">{submitError}</p>}
      <div className="flex gap-2">
        <button
          onClick={submit}
          disabled={submitting || (needsFallbackGate && !noDecisionAck)}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {submitting ? "Starting…" : isEvidenceOnly ? "Run inspection" : "Run sanitize"}
        </button>
        <button onClick={onClose} className="px-3 py-1.5 text-xs text-muted hover:text-foreground">
          Cancel
        </button>
      </div>
    </div>
  );
}

type StatusTone = "muted" | "amber" | "emerald" | "red" | "orange";

const STATUS_TONE_CLASS: Record<StatusTone, string> = {
  muted: "text-muted",
  amber: "text-amber-700 dark:text-amber-400",
  emerald: "text-emerald-600",
  red: "text-red-600",
  orange: "text-orange-700 dark:text-orange-400",
};

const STATUS_TONE_LABEL: Record<StatusTone, string> = {
  muted: "Not reviewed",
  amber: "In progress / needs sanitize",
  emerald: "Sanitized",
  red: "Failed",
  orange: "Refused",
};

// The single "where are we, what's next" line for a document — the point
// isn't just showing the latest job's raw status (already visible in the
// job list below), it's translating that into what a reviewer should
// actually do next. "Sanitized with <policy>" is deliberately the
// strongest claim made here: never "clean" or "safe", since a sanitize
// job can still have kept findings without review (see NoDecisionWarning
// on the job page) — this line just points at the job, it doesn't
// re-assert an outcome the job page itself has to qualify.
function documentNextStep(docJobs: Job[]): { tone: StatusTone; label: string; detail: string } {
  if (docJobs.length === 0) {
    return {
      tone: "muted",
      label: "Not yet reviewed",
      detail: "Inspect to see what's inside, or sanitize directly.",
    };
  }
  const latest = docJobs[0];
  if (latest.status === "queued" || latest.status === "running") {
    return {
      tone: "amber",
      label: `${latest.kind === "sanitize" ? "Sanitize" : "Inspect"} in progress`,
      detail: "Checking again automatically.",
    };
  }
  if (latest.status === "failed") {
    return { tone: "red", label: "Last job failed", detail: "See job details below." };
  }
  if (latest.status === "refused") {
    return {
      tone: "orange",
      label: "Refused by policy",
      detail: "No derivative was produced — see job details below.",
    };
  }
  if (latest.kind === "sanitize") {
    return {
      tone: "emerald",
      label: `Sanitized with ${latest.policy_id}`,
      detail: "Open the job for findings, custody, and what was kept.",
    };
  }
  const hasDoneSanitize = docJobs.some((j) => j.kind === "sanitize" && j.status === "done");
  return hasDoneSanitize
    ? {
        tone: "amber",
        label: "Inspected again since last sanitize",
        detail: "The earlier sanitize predates this inspection — review before relying on it.",
      }
    : {
        tone: "amber",
        label: "Inspected — not yet sanitized",
        detail: "Choose a policy and sanitize when ready.",
      };
}

function DocumentRow({
  matterId,
  doc,
  jobs,
  policies,
  onJobStarted,
  highlighted,
}: {
  matterId: string;
  doc: Document;
  jobs: Job[];
  policies: Policy[];
  onJobStarted: () => void;
  highlighted: boolean;
}) {
  const [sanitizing, setSanitizing] = useState(false);
  const [inspecting, setInspecting] = useState(false);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const rowRef = useRef<HTMLLIElement>(null);
  const docJobs = jobs
    .filter((j) => j.document_id === doc.id)
    .sort((a, b) => b.created_utc.localeCompare(a.created_utc));
  const nextStep = documentNextStep(docJobs);

  useEffect(() => {
    if (highlighted) rowRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [highlighted]);

  async function inspect() {
    setInspecting(true);
    setInspectError(null);
    try {
      await api.post(`/v1/matters/${matterId}/documents/${doc.id}/inspect-jobs`);
      onJobStarted();
    } catch (err) {
      setInspectError(err instanceof Error ? err.message : "Inspect failed to start");
    } finally {
      setInspecting(false);
    }
  }

  return (
    <li
      ref={rowRef}
      className={`px-4 py-3 ${highlighted ? "bg-accent/10 ring-1 ring-inset ring-accent" : ""}`}
    >
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="truncate font-medium">{doc.filename}</p>
          <p className="truncate font-mono text-xs text-muted" title={doc.sha256}>
            {formatBytes(doc.bytes)} · sha256:{doc.sha256.slice(0, 16)}…
          </p>
          <p className={`mt-1 text-xs ${STATUS_TONE_CLASS[nextStep.tone]}`}>
            <span className="font-medium">{nextStep.label}</span>
            <span className="text-muted"> — {nextStep.detail}</span>
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <button
            onClick={inspect}
            disabled={inspecting}
            className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
          >
            {inspecting ? "Inspecting…" : "Inspect"}
          </button>
          <button
            onClick={() => setSanitizing((v) => !v)}
            className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
          >
            Sanitize
          </button>
        </div>
      </div>

      {inspectError && <p className="mt-2 text-xs text-red-600">{inspectError}</p>}

      {sanitizing && (
        <SanitizePanel
          matterId={matterId}
          docId={doc.id}
          docJobs={docJobs}
          policies={policies}
          onClose={() => setSanitizing(false)}
          onDone={onJobStarted}
        />
      )}

      {docJobs.length > 0 && (
        <ul className="mt-2 space-y-1.5">
          {docJobs.map((j) => (
            <li key={j.id} className="flex items-center gap-2 text-xs">
              <Link
                href={`/matters/job?matter=${matterId}&job=${j.id}`}
                className="font-medium capitalize hover:underline"
              >
                {j.kind}
              </Link>
              <StatusBadge status={j.status} />
              {j.kind === "sanitize" && <span className="text-muted">{j.policy_id}</span>}
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

function MatterStats({ documents, jobs }: { documents: Document[]; jobs: Job[] }) {
  const done = jobs.filter((j) => j.status === "done").length;
  const running = jobs.filter((j) => j.status === "queued" || j.status === "running").length;
  const failed = jobs.filter((j) => j.status === "failed").length;
  // "refused" (a policy correctly declining to produce a derivative, e.g.
  // a macro-enabled file) previously fell through every bucket here —
  // uncounted, so the summary looked tidier than it actually was.
  const refused = jobs.filter((j) => j.status === "refused").length;
  return (
    <div className="mb-6 flex flex-wrap gap-4 text-sm text-muted">
      <span>
        <span className="font-medium text-foreground">{documents.length}</span> document
        {documents.length === 1 ? "" : "s"}
      </span>
      <span>
        <span className="font-medium text-foreground">{done}</span> job{done === 1 ? "" : "s"}{" "}
        done
      </span>
      {running > 0 && (
        <span className="text-amber-600">
          <span className="font-medium">{running}</span> in progress
        </span>
      )}
      {failed > 0 && (
        <span className="text-red-600">
          <span className="font-medium">{failed}</span> failed
        </span>
      )}
      {refused > 0 && (
        <span className="text-orange-700 dark:text-orange-400">
          <span className="font-medium">{refused}</span> refused by policy
        </span>
      )}
    </div>
  );
}

function MatterView({
  matterId,
  highlightDocId,
}: {
  matterId: string;
  highlightDocId: string | null;
}) {
  const matterQ = useApiData(() => api.get<Matter>(`/v1/matters/${matterId}`), `matter:${matterId}`);
  const docsQ = useApiData(
    () => api.get<{ documents: Document[]; total: number }>(`/v1/matters/${matterId}/documents`),
    `docs:${matterId}`,
  );
  const jobsQ = useApiData(
    () => api.get<{ jobs: Job[]; total: number }>(`/v1/matters/${matterId}/jobs`),
    `jobs:${matterId}`,
  );
  const policiesQ = useApiData(() => api.get<{ policies: Policy[] }>("/v1/policies"), "policies");
  const fileInput = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  async function upload(e: React.FormEvent) {
    e.preventDefault();
    const file = fileInput.current?.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    try {
      const body = new FormData();
      body.append("file", file);
      await api.post(`/v1/matters/${matterId}/documents`, body);
      if (fileInput.current) fileInput.current.value = "";
      docsQ.reload();
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setUploading(false);
    }
  }

  const [docSearch, setDocSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | StatusTone>("all");
  // Both filters run only against the documents/jobs already fetched
  // (server-capped at `limit`) — same "loaded, not the whole matter"
  // scope as the matters-list search.
  const filteredDocs = (docsQ.data?.documents ?? []).filter((doc) => {
    if (docSearch.trim() && !doc.filename.toLowerCase().includes(docSearch.trim().toLowerCase())) {
      return false;
    }
    if (statusFilter !== "all") {
      const docJobs = (jobsQ.data?.jobs ?? [])
        .filter((j) => j.document_id === doc.id)
        .sort((a, b) => b.created_utc.localeCompare(a.created_utc));
      if (documentNextStep(docJobs).tone !== statusFilter) return false;
    }
    return true;
  });

  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
      <div className="flex items-center justify-between">
        <Link href="/matters" className="text-sm text-muted hover:text-foreground">
          ← Matters
        </Link>
        <div className="flex gap-4">
          <Link
            href={`/matters/access?id=${matterId}`}
            className="text-sm text-muted hover:text-foreground"
          >
            Access →
          </Link>
          <Link
            href={`/matters/audit?id=${matterId}`}
            className="text-sm text-muted hover:text-foreground"
          >
            Audit log →
          </Link>
        </div>
      </div>
      <h1 className="mb-1 mt-2 text-2xl font-semibold tracking-tight">
        {matterQ.data?.name ?? (matterQ.loading ? "Loading…" : "Matter")}
      </h1>
      {matterQ.error && <p className="mb-4 text-sm text-red-600">{matterQ.error}</p>}

      {docsQ.data && <MatterStats documents={docsQ.data.documents} jobs={jobsQ.data?.jobs ?? []} />}

      <form onSubmit={upload} className="mb-8 flex items-center gap-2">
        <input
          ref={fileInput}
          type="file"
          required
          className="flex-1 text-sm file:mr-3 file:rounded-md file:border file:border-border file:bg-transparent file:px-3 file:py-1.5 file:text-sm"
        />
        <button
          type="submit"
          disabled={uploading}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {uploading ? "Uploading…" : "Upload"}
        </button>
      </form>
      {uploadError && (
        <p className="mb-4 rounded-md border border-red-600/30 bg-red-600/5 px-3 py-2 text-sm text-red-600">
          {uploadError}
        </p>
      )}

      {docsQ.loading && (
        <div className="animate-pulse space-y-2">
          <div className="h-14 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
          <div className="h-14 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
        </div>
      )}
      {docsQ.error && <p className="text-sm text-red-600">{docsQ.error}</p>}
      {docsQ.data && docsQ.data.documents.length === 0 && (
        <div className="rounded-md border border-dashed border-border px-4 py-8 text-center text-sm text-muted">
          No documents yet — upload one above to inspect or sanitize it.
        </div>
      )}

      {docsQ.data && docsQ.data.documents.length > 0 && (
        <>
          {docsQ.data.total > docsQ.data.documents.length && (
            <p className="mb-2 text-xs text-muted">
              Loaded {docsQ.data.documents.length} of {docsQ.data.total} documents — search and
              filters below only cover what&apos;s loaded.
            </p>
          )}
          <div className="mb-3 space-y-2">
            <input
              value={docSearch}
              onChange={(e) => setDocSearch(e.target.value)}
              placeholder="Search documents by filename…"
              className="w-full rounded-md border border-border bg-transparent px-3 py-1.5 text-sm outline-none focus:border-accent"
            />
            <div className="flex flex-wrap gap-1.5">
              <button
                onClick={() => setStatusFilter("all")}
                className={`rounded px-2 py-1 text-xs ${
                  statusFilter === "all"
                    ? "bg-accent text-white"
                    : "border border-border hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                }`}
              >
                All
              </button>
              {(Object.keys(STATUS_TONE_LABEL) as StatusTone[]).map((tone) => (
                <button
                  key={tone}
                  onClick={() => setStatusFilter(tone)}
                  className={`rounded px-2 py-1 text-xs ${
                    statusFilter === tone
                      ? "bg-accent text-white"
                      : "border border-border hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                  }`}
                >
                  {STATUS_TONE_LABEL[tone]}
                </button>
              ))}
            </div>
          </div>

          {filteredDocs.length === 0 ? (
            <p className="text-sm text-muted">No loaded documents match this search/filter.</p>
          ) : (
            <ul className="divide-y divide-border rounded-md border border-border">
              {filteredDocs.map((doc) => (
                <DocumentRow
                  key={doc.id}
                  matterId={matterId}
                  doc={doc}
                  jobs={jobsQ.data?.jobs ?? []}
                  policies={policiesQ.data?.policies ?? []}
                  onJobStarted={jobsQ.reload}
                  highlighted={doc.id === highlightDocId}
                />
              ))}
            </ul>
          )}
        </>
      )}
    </main>
  );
}

function MatterViewInner() {
  const params = useSearchParams();
  const id = params.get("id");
  if (!id) {
    return <main className="mx-auto max-w-5xl flex-1 px-6 py-8 text-sm text-red-600">Missing matter id.</main>;
  }
  // Audit-log document cross-links (web/app/matters/audit/page.tsx) land
  // here with ?doc= — scrolled to and highlighted in DocumentRow below,
  // since there's no separate per-document page to link to instead.
  return <MatterView matterId={id} highlightDocId={params.get("doc")} />;
}

export default function MatterViewPage() {
  return (
    <>
      <Header />
      <Suspense fallback={<div className="flex-1 px-6 py-8 text-sm text-muted">Loading…</div>}>
        <MatterViewInner />
      </Suspense>
    </>
  );
}
