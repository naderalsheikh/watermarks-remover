"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { computeProductionReviewState } from "@/lib/productionReview";
import { useApiData } from "@/lib/useApi";
import { usePaginatedList } from "@/lib/usePaginatedList";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import type { BulkJobsResponse, Document, Job, Matter, Policy } from "@/lib/types";
import { Header } from "@/components/Header";
import { StatusBadge } from "@/components/StatusBadge";

const PAGE_SIZE = 50;

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
  selected,
  onToggleSelected,
}: {
  matterId: string;
  doc: Document;
  jobs: Job[];
  policies: Policy[];
  onJobStarted: () => void;
  highlighted: boolean;
  selected: boolean;
  onToggleSelected: (id: string, checked: boolean) => void;
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
      <div className="flex items-start gap-3">
        <input
          type="checkbox"
          checked={selected}
          onChange={(e) => onToggleSelected(doc.id, e.target.checked)}
          aria-label={`Select ${doc.filename}`}
          className="mt-1 shrink-0"
        />
        <div className="min-w-0 flex-1">
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

function BulkRunPanel({
  matterId,
  docIds,
  kind,
  policies,
  onClose,
  onDone,
}: {
  matterId: string;
  docIds: string[];
  kind: "inspect" | "sanitize";
  policies: Policy[];
  onClose: () => void;
  onDone: (res: BulkJobsResponse) => void;
}) {
  // Only policies the backend marks bulk-safe are offered: no approve-
  // default subtype cells, so no per-finding decisions are required. The
  // same filter the server enforces — the UI can't even offer production.
  const bulkSafe = policies.filter((p) => p.bulk_safe);
  const [policyId, setPolicyId] = useState(bulkSafe[0]?.id ?? "");
  const [reason, setReason] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const selectedPolicy = bulkSafe.find((p) => p.id === policyId);

  async function submit() {
    setSubmitting(true);
    setSubmitError(null);
    try {
      const body =
        kind === "sanitize"
          ? { document_ids: docIds, kind, policy_id: policyId, reason }
          : { document_ids: docIds, kind };
      const res = await api.post<BulkJobsResponse>(
        `/v1/matters/${matterId}/bulk-jobs`,
        body,
      );
      onDone(res);
      onClose();
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Bulk run failed to start");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mb-4 space-y-3 rounded-md border border-border bg-black/[0.02] p-3 dark:bg-white/[0.02]">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm font-medium">
            {kind === "sanitize" ? "Bulk sanitize" : "Bulk inspect"} — {docIds.length} document
            {docIds.length === 1 ? "" : "s"} selected
          </p>
          {kind === "inspect" ? (
            <p className="mt-1 text-xs text-muted">
              Inspection is read-only: it only reports what&apos;s inside each document. No
              derivative is produced and nothing is modified.
            </p>
          ) : (
            <p className="mt-1 text-xs text-muted">
              Sanitization runs per document; every outcome is reported individually below.
            </p>
          )}
        </div>
        <button onClick={onClose} className="text-sm text-muted hover:text-foreground">
          Cancel
        </button>
      </div>

      {kind === "sanitize" && (
        <>
          <div>
            <label className="mb-1 block text-xs font-medium">Policy</label>
            <select
              value={policyId}
              onChange={(e) => setPolicyId(e.target.value)}
              className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
            >
              {bulkSafe.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
            {selectedPolicy && (
              <p className="mt-1 text-xs text-muted">{selectedPolicy.description}</p>
            )}
          </div>
          <div className="rounded-md border border-amber-600/40 bg-amber-600/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
            <p className="font-medium">Known refusal classes</p>
            <p className="mt-1">
              Documents that hit a policy refusal class — macro-enabled files, digitally signed
              documents without an attestation — are <strong>refused, not skipped</strong>: each
              one shows its own &quot;refused&quot; result with the reason. Bulk runs never use
              per-finding decisions or Layer B rewrites.
            </p>
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">
              Reason (optional, shared across all selected documents)
            </label>
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
            />
          </div>
        </>
      )}

      {submitError && <p className="text-xs text-red-600">{submitError}</p>}
      <div className="flex gap-2">
        <button
          onClick={submit}
          disabled={submitting || (kind === "sanitize" && !policyId)}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {submitting
            ? "Running…"
            : kind === "sanitize"
              ? "Run bulk sanitize"
              : "Run bulk inspect"}
        </button>
      </div>
    </div>
  );
}

// Per-document results of the last bulk run — deliberately a row per
// document (filename, status, error, job link) so a refusal or failure is
// as visible as the successes; never a vague "bulk succeeded".
function BulkResults({
  matterId,
  results,
}: {
  matterId: string;
  results: BulkJobsResponse;
}) {
  const s = results.summary;
  return (
    <div className="mb-4 rounded-md border border-border">
      <div className="border-b border-border px-4 py-2 text-xs text-muted">
        {s.done} done · {s.refused} refused · {s.failed} failed · {s.queued} queued · {s.running}{" "}
        running — per document:
      </div>
      <ul className="divide-y divide-border">
        {results.results.map((r) => (
          <li key={r.job_id} className="flex items-center justify-between gap-3 px-4 py-2 text-sm">
            <div className="min-w-0">
              <p className="truncate font-medium">{r.document_name}</p>
              {r.error && <p className="truncate text-xs text-muted">{r.error}</p>}
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <StatusBadge status={r.status} />
              <Link
                href={`/matters/job?matter=${matterId}&job=${r.job_id}`}
                className="text-xs font-medium hover:underline"
              >
                Open
              </Link>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function MatterStats({
  documents,
  documentsTotal,
  jobs,
  jobsTotal,
}: {
  documents: Document[];
  documentsTotal: number;
  jobs: Job[];
  jobsTotal: number;
}) {
  const done = jobs.filter((j) => j.status === "done").length;
  const running = jobs.filter((j) => j.status === "queued" || j.status === "running").length;
  const failed = jobs.filter((j) => j.status === "failed").length;
  // "refused" (a policy correctly declining to produce a derivative, e.g.
  // a macro-enabled file) previously fell through every bucket here —
  // uncounted, so the summary looked tidier than it actually was.
  const refused = jobs.filter((j) => j.status === "refused").length;
  const jobsPartial = jobsTotal > jobs.length;
  return (
    <div className="mb-1 flex flex-wrap gap-4 text-sm text-muted">
      <span>
        <span className="font-medium text-foreground">{documents.length}</span>
        {documentsTotal > documents.length ? ` of ${documentsTotal}` : ""} document
        {documentsTotal === 1 ? "" : "s"}
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
      {jobsPartial && (
        <span title="Job counts above only reflect jobs loaded so far, not the matter's full job history.">
          (of {jobsTotal} jobs total)
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
  const [docSearch, setDocSearch] = useState("");
  const debouncedDocSearch = useDebouncedValue(docSearch.trim(), 300);
  const docsQ = usePaginatedList<Document>(
    (offset) =>
      api
        .get<{ documents: Document[]; total: number }>(
          `/v1/matters/${matterId}/documents?limit=${PAGE_SIZE}&offset=${offset}` +
            `&q=${encodeURIComponent(debouncedDocSearch)}`,
        )
        .then((r) => ({ items: r.documents, total: r.total })),
    // Search runs on the server (same GET, `q` param) across every
    // document in this matter, not just what's loaded -- changing it
    // resets pagination to page 1 of the new result, like a matter-id
    // change does elsewhere.
    `docs:${matterId}:${debouncedDocSearch}`,
  );
  const jobsQ = usePaginatedList<Job>(
    (offset) =>
      api
        .get<{ jobs: Job[]; total: number }>(
          `/v1/matters/${matterId}/jobs?limit=${PAGE_SIZE}&offset=${offset}`,
        )
        .then((r) => ({ items: r.jobs, total: r.total })),
    `jobs:${matterId}`,
  );
  const policiesQ = useApiData(() => api.get<{ policies: Policy[] }>("/v1/policies"), "policies");
  const fileInput = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  // Bulk selection: ids of loaded documents. Deliberately scoped to what's
  // loaded (same "loaded-so-far" honesty as the search/filter) — the bulk
  // bar labels it as such, and the backend refuses ids that aren't
  // documents of this matter, so a stale selection can't silently no-op.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkAction, setBulkAction] = useState<"inspect" | "sanitize" | null>(null);
  const [bulkResults, setBulkResults] = useState<BulkJobsResponse | null>(null);
  const bulkSafePolicies = (policiesQ.data?.policies ?? []).filter((p) => p.bulk_safe);
  const allLoadedSelected =
    docsQ.items.length > 0 && docsQ.items.every((d) => selected.has(d.id));

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

  const [statusFilter, setStatusFilter] = useState<"all" | StatusTone>("all");
  // docSearch above already narrowed docsQ.items on the server; this filter
  // only applies the status facet, and only over what's loaded so far
  // (accumulated via "Load more") — status isn't a server-side query
  // param, since it's derived from job history, not a stored document
  // field, so it can't honestly claim to cover documents not yet loaded.
  const filteredDocs = docsQ.items.filter((doc) => {
    if (statusFilter !== "all") {
      const docJobs = jobsQ.items
        .filter((j) => j.document_id === doc.id)
        .sort((a, b) => b.created_utc.localeCompare(a.created_utc));
      if (documentNextStep(docJobs).tone !== statusFilter) return false;
    }
    return true;
  });

  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
      {/* flex-wrap on both levels, whitespace-nowrap on every link: with
          4 links total this row has no room to stay on one line on a
          phone-width viewport, and letting the arrow glyph itself wrap
          away from its label (the un-wrapped version) reads as broken
          text rather than a normal multi-line nav. Each link now wraps
          as one intact unit instead. */}
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <Link href="/matters" className="whitespace-nowrap text-sm text-muted hover:text-foreground">
          ← Matters
        </Link>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          <Link
            href={`/matters/access?id=${matterId}`}
            className="whitespace-nowrap text-sm text-muted hover:text-foreground"
          >
            Access →
          </Link>
          <Link
            href={`/matters/audit?id=${matterId}`}
            className="whitespace-nowrap text-sm text-muted hover:text-foreground"
          >
            Audit log →
          </Link>
          {/* Plain <a>, not the api client: a CSV file download, same
              pattern as the job page's bundle download. Exports every job
              in the matter, never just what's loaded on this page. */}
          <a
            href={`/v1/matters/${matterId}/jobs/export`}
            className="whitespace-nowrap text-sm text-muted hover:text-foreground"
          >
            Export jobs CSV →
          </a>
        </div>
      </div>
      <h1 className="mb-1 mt-2 text-2xl font-semibold tracking-tight">
        {matterQ.data?.name ?? (matterQ.loading ? "Loading…" : "Matter")}
      </h1>
      {matterQ.error && <p className="mb-4 text-sm text-red-600">{matterQ.error}</p>}

      {!docsQ.loading && (
        <MatterStats
          documents={docsQ.items}
          documentsTotal={docsQ.total}
          jobs={jobsQ.items}
          jobsTotal={jobsQ.total}
        />
      )}
      {jobsQ.total > jobsQ.items.length && (
        <p className="mb-6 text-xs text-muted">
          <button
            type="button"
            onClick={jobsQ.loadMore}
            disabled={jobsQ.loadingMore}
            className="underline hover:text-foreground disabled:opacity-50"
          >
            {jobsQ.loadingMore
              ? "Loading more jobs…"
              : `Load ${Math.min(PAGE_SIZE, jobsQ.total - jobsQ.items.length)} more jobs (${jobsQ.items.length} of ${jobsQ.total} loaded)`}
          </button>{" "}
          — per-document status below only reflects jobs loaded so far.
        </p>
      )}

      {/* flex-wrap + min-w-0: a native file input has an intrinsic content
          width ("Choose File" + filename) that a plain flex-1 does not
          shrink below (flex children default to min-width:auto), which
          was overflowing the viewport horizontally below phone width. */}
      <form onSubmit={upload} className="mb-8 flex flex-wrap items-center gap-2">
        <input
          ref={fileInput}
          type="file"
          required
          className="min-w-0 flex-1 text-sm file:mr-3 file:rounded-md file:border file:border-border file:bg-transparent file:px-3 file:py-1.5 file:text-sm"
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
      {!docsQ.loading && docsQ.items.length === 0 && (
        <div className="rounded-md border border-dashed border-border px-4 py-8 text-center text-sm text-muted">
          {debouncedDocSearch
            ? `No documents match "${debouncedDocSearch}".`
            : "No documents yet — upload one above to inspect or sanitize it."}
        </div>
      )}

          {!docsQ.loading && docsQ.items.length > 0 && (
            <>
              {docsQ.total > docsQ.items.length && (
                <p className="mb-2 text-xs text-muted">
                  Loaded {docsQ.items.length} of {docsQ.total}
                  {debouncedDocSearch ? " matching" : ""} documents — the status filter below only
                  covers what&apos;s loaded.
                </p>
              )}

              {bulkResults && <BulkResults matterId={matterId} results={bulkResults} />}

              {bulkAction && (
                <BulkRunPanel
                  matterId={matterId}
                  docIds={[...selected]}
                  kind={bulkAction}
                  policies={policiesQ.data?.policies ?? []}
                  onClose={() => setBulkAction(null)}
                  onDone={(res) => {
                    setBulkResults(res);
                    setSelected(new Set());
                    jobsQ.reload();
                    docsQ.reload();
                  }}
                />
              )}

              {selected.size > 0 && !bulkAction && (
                <div className="mb-3 flex flex-wrap items-center gap-3 rounded-md border border-border bg-black/[0.02] px-3 py-2 dark:bg-white/[0.02]">
                  <span className="text-sm font-medium">
                    {selected.size} of {docsQ.items.length} loaded documents selected
                  </span>
                  <button
                    onClick={() => setSelected(new Set())}
                    className="text-xs text-muted hover:text-foreground"
                  >
                    Clear
                  </button>
                  <div className="ml-auto flex gap-2">
                    <button
                      onClick={() => setBulkAction("inspect")}
                      className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                    >
                      Bulk inspect
                    </button>
                    {bulkSafePolicies.length > 0 && (
                      <button
                        onClick={() => setBulkAction("sanitize")}
                        className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                      >
                        Bulk sanitize…
                      </button>
                    )}
                  </div>
                </div>
              )}

              <div className="mb-3 space-y-2">
            <input
              value={docSearch}
              onChange={(e) => setDocSearch(e.target.value)}
              placeholder="Search documents by filename…"
              aria-label="Search documents by filename"
              className="w-full rounded-md border border-border bg-transparent px-3 py-1.5 text-sm outline-none focus:border-accent"
            />
            <p className="text-xs text-muted">
              Searches every document in this matter on the server. The status filter below only
              covers documents already loaded.
            </p>
            <div className="flex flex-wrap gap-1.5">
              <button
                onClick={() => setStatusFilter("all")}
                aria-pressed={statusFilter === "all"}
                className={`rounded px-2 py-1.5 text-xs ${
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
                  aria-pressed={statusFilter === tone}
                  className={`rounded px-2 py-1.5 text-xs ${
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
            <p className="text-sm text-muted">No loaded documents match this status filter.</p>
          ) : (
            <>
              <label className="mb-2 flex items-center gap-2 text-xs text-muted">
                <input
                  type="checkbox"
                  checked={allLoadedSelected}
                  onChange={(e) =>
                    setSelected(
                      e.target.checked
                        ? new Set(docsQ.items.map((d) => d.id))
                        : new Set(),
                    )
                  }
                />
                Select all {docsQ.items.length} loaded documents
              </label>
              <ul className="divide-y divide-border rounded-md border border-border">
                {filteredDocs.map((doc) => (
                  <DocumentRow
                    key={doc.id}
                    matterId={matterId}
                    doc={doc}
                    jobs={jobsQ.items}
                    policies={policiesQ.data?.policies ?? []}
                    onJobStarted={jobsQ.reload}
                    highlighted={doc.id === highlightDocId}
                    selected={selected.has(doc.id)}
                    onToggleSelected={(id, checked) =>
                      setSelected((prev) => {
                        const next = new Set(prev);
                        if (checked) next.add(id);
                        else next.delete(id);
                        return next;
                      })
                    }
                  />
                ))}
              </ul>
            </>
          )}
          {docsQ.hasMore && (
            <button
              type="button"
              onClick={docsQ.loadMore}
              disabled={docsQ.loadingMore}
              className="mt-3 w-full rounded-md border border-border px-3 py-2 text-sm font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
            >
              {docsQ.loadingMore
                ? "Loading…"
                : `Load more (${docsQ.items.length} of ${docsQ.total})`}
            </button>
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
