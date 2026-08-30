"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import { useApiData } from "@/lib/useApi";
import { hasMatterPerm } from "@/lib/matterPermissions";
import type { Finding, Job, Manifest, Matter, Release } from "@/lib/types";
import { Header } from "@/components/Header";
import { StatusBadge } from "@/components/StatusBadge";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

function titleCase(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// PR 48: mirrors service/scripts/policies.py's PDF_CONTENT_REFUSAL_MARKER
// exactly -- a narrow string match, not a structured reason code, because
// job.error is a plain string end-to-end (service/app/runner.py's
// sync_job copies it verbatim from the worker's result.json). Distinguishes
// "the engine has no PDF annotation/attachment/active-content editor yet"
// from a deliberate policy refusal (macros, an unattested signature).
// Known technical debt: a real reason-code field would need a Job
// column/migration to carry it through the worker-subprocess boundary.
// Keep this string in sync with the backend constant.
const PDF_CONTENT_REFUSAL_MARKER = "pdf content removal not implemented";

function isPdfContentCapabilityRefusal(error: string | null): boolean {
  return !!error && error.includes(PDF_CONTENT_REFUSAL_MARKER);
}

function stripCapabilityRefusalPrefix(error: string | null): string {
  if (!error) return "";
  const idx = error.indexOf(PDF_CONTENT_REFUSAL_MARKER);
  if (idx === -1) return error;
  const rest = error.slice(idx + PDF_CONTENT_REFUSAL_MARKER.length).replace(/^:\s*/, "");
  return rest.charAt(0).toUpperCase() + rest.slice(1);
}

// Mirrors service/app/main.py's RELEASE_PROFILES/RECIPIENT_TYPE_LABEL and
// web/app/matters/view/page.tsx's own copy of the latter (PR 44) -- a
// third small literal, not a shared import, same reasoning as every
// other policy/profile constant duplicated across this app's surfaces.
const RELEASE_PROFILE_LABEL: Record<string, string> = {
  counterparty_deal_room: "Counterparty / Deal Room Release",
  public_filing_anonymized: "Public Filing / Anonymized Release",
  ediscovery_production: "E-Discovery / Production Release",
};

function releaseProfileLabel(profileId: string): string {
  return RELEASE_PROFILE_LABEL[profileId] ?? profileId;
}

const RECIPIENT_TYPE_LABEL: Record<string, string> = {
  opposing_counsel: "Opposing counsel",
  court: "Court / tribunal",
  client: "Client",
  regulator: "Regulator",
  internal_reviewer: "Internal reviewer",
  other: "Other",
};

function recipientTypeLabel(recipientType: string): string {
  return RECIPIENT_TYPE_LABEL[recipientType] ?? recipientType;
}

const RISK_ORDER: Finding["risk_level"][] = ["critical", "high", "medium", "low", "info"];
const RISK_COLOR: Record<Finding["risk_level"], string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  low: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  info: "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400",
};
// Click-to-copy full hash — the forensic value of a hash is in the exact
// value, which a truncated display can't offer; copy is the point.
function HashValue({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <p className="text-xs text-muted">{label}</p>
      <button
        onClick={() => {
          navigator.clipboard.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1200);
          });
        }}
        title="Click to copy full hash"
        className="break-all text-left font-mono text-xs hover:text-accent"
      >
        {value}
      </button>
      {copied && <span className="text-xs text-emerald-600"> copied</span>}
    </div>
  );
}

function RiskSummary({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.risk_level] = (counts[f.risk_level] ?? 0) + 1;
  return (
    <div className="mb-4 flex flex-wrap items-center gap-2">
      <span className="text-sm text-muted">
        {findings.length} finding{findings.length === 1 ? "" : "s"}
      </span>
      {RISK_ORDER.filter((r) => counts[r]).map((r) => (
        <span key={r} className={`rounded px-2 py-0.5 text-xs font-medium ${RISK_COLOR[r]}`}>
          {counts[r]} {r}
        </span>
      ))}
    </div>
  );
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
    return (
      <div className="rounded-md border border-emerald-600/30 bg-emerald-600/5 px-4 py-3 text-sm text-emerald-700 dark:text-emerald-400">
        No findings — nothing flagged for review in this document.
      </div>
    );
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

function CustodyCard({ manifest }: { manifest: Manifest }) {
  return (
    <div className="mb-6 rounded-md border border-border p-4">
      <h2 className="mb-3 text-sm font-semibold tracking-tight">Custody</h2>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted">Original</p>
          <p className="text-sm">
            {manifest.original.filename}{" "}
            <span className="text-muted">({formatBytes(manifest.original.bytes)})</span>
          </p>
          <HashValue label="SHA-256" value={manifest.original.sha256} />
        </div>
        <div className="space-y-2">
          <p className="text-xs font-medium uppercase tracking-wide text-muted">Derivative</p>
          <p className="text-sm">
            {manifest.derivative.filename}{" "}
            <span className="text-muted">({formatBytes(manifest.derivative.bytes)})</span>
          </p>
          <HashValue label="SHA-256" value={manifest.derivative.sha256} />
        </div>
      </div>
      <p className="mt-3 text-xs text-muted">
        Policy: {manifest.policy.id} (v{manifest.policy.version}) · original is write-once and
        was never modified — only the derivative was produced
      </p>
    </div>
  );
}

// docs/pdf-deep-image-metadata.md: apply_actions._apply_pdf records this as
// a plain "embedded_image_metadata:<action>: <detail>" manifest action —
// pull it out of the generic list into its own callout so this capability
// (and its one honest limitation) doesn't get lost among a dozen bullets.
function EmbeddedImageNotice({ actions }: { actions: string[] }) {
  const line = actions.find((a) => a.startsWith("embedded_image_metadata:"));
  if (!line) return null;
  const stripped = line.startsWith("embedded_image_metadata:strip:");
  const detail = line.split(": ").slice(1).join(": ");
  return (
    <div
      className={`mb-6 rounded-md border p-4 text-sm ${
        stripped
          ? "border-emerald-600/30 bg-emerald-600/5"
          : "border-amber-600/30 bg-amber-600/5"
      }`}
    >
      <p className={`font-medium ${stripped ? "text-emerald-700 dark:text-emerald-400" : "text-amber-700 dark:text-amber-400"}`}>
        {stripped ? "Embedded-image metadata removed" : "Embedded-image metadata not cleared"}
      </p>
      <p className="mt-1 text-muted">{detail}</p>
    </div>
  );
}

// policies.py: _no_decision_records. An approve-default subtype (e.g.
// comments_and_notes, tracked_changes) that was present but never got an
// operator decision resolves to "keep" — the finding survives in the
// derivative untouched. This is a green "done" job that still contains
// undecided content; it must never look identical to a fully-reviewed one.
// Deliberately rendered above CustodyCard: this is the one disclosure that
// must not be missable, and must hold regardless of whether the job was
// submitted through this UI (which gates it, see ReleasePanel) or
// directly via the API (which doesn't).
const NO_DECISION_MARKER = "no operator decision was supplied";

function NoDecisionWarning({ actions }: { actions: string[] }) {
  const lines = actions.filter((a) => a.includes(NO_DECISION_MARKER));
  if (lines.length === 0) return null;
  const subtypes = lines.map((l) => l.split(":", 1)[0]);
  return (
    <div
      id="unreviewed-findings"
      className="mb-6 rounded-md border border-red-600/40 bg-red-600/10 p-4 text-sm"
    >
      {/* Anchor for the dashboard's "unreviewed findings" deep link
          (?highlight=unreviewed), scrolled to by JobView below — this is
          the one disclosure a dashboard drill-down must land on directly,
          not just "somewhere on this job's page". */}
      <p className="font-medium text-red-700 dark:text-red-400">
        {subtypes.length} finding{subtypes.length === 1 ? "" : "s"} kept without review
      </p>
      <p className="mt-1 text-muted">
        No operator decision was supplied for these approve-default findings, so they were
        kept as-is rather than reviewed: <strong>{titleCase(subtypes.join(", "))}</strong>. This
        derivative is not a full sanitize despite the job status.
      </p>
    </div>
  );
}

function SanitizeManifestView({ manifest }: { manifest: Manifest }) {
  return (
    <div className="space-y-4">
      <NoDecisionWarning actions={manifest.actions} />
      <CustodyCard manifest={manifest} />
      <EmbeddedImageNotice actions={manifest.actions} />

      {manifest.findings_before.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-medium">What was found</h3>
          {/* PR 45: the policy that governs a finding it doesn't strip
              (flag/keep/approve) is a real, deliberate product distinction
              -- not a gap. Made explicit here rather than left for a
              reader to infer by diffing this list against Actions taken. */}
          <p className="mb-2 text-xs text-muted">
            Everything the policy checked for. An item listed here that doesn&apos;t reappear
            under Actions taken below was flagged for review or kept as-is, not silently missed.
          </p>
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

// Itemizes the real zip contents (service/app/main.py's job_bundle route)
// rather than a vague "contains a manifest and the file" line — and points
// each item at what's already shown above instead of re-deriving it, so
// this can't quietly drift out of sync with NoDecisionWarning/
// EmbeddedImageNotice/the verification-checks list.
function BundleContents({
  manifest,
  includeOriginal,
}: {
  manifest: Manifest;
  includeOriginal: boolean;
}) {
  const hasKeptWithoutReview = manifest.actions.some((a) => a.includes(NO_DECISION_MARKER));
  return (
    <div className="mt-3 text-xs text-muted">
      <p className="font-medium text-foreground">What&apos;s in this release packet</p>
      <ul className="mt-1 list-inside list-disc space-y-1">
        <li>
          <code className="font-mono">derivative/{manifest.derivative.filename}</code> — the
          document prepared for release.
        </li>
        <li>
          <code className="font-mono">certificate.html</code> — the same custody certificate
          available on its own above: identity, policy, hashes, verification, and every
          limitation, in one self-contained page.
        </li>
        <li>
          <code className="font-mono">manifest.json</code> — the full custody record shown
          above: policy, every finding, every action taken (including anything kept without
          review), and the verification results.
        </li>
        <li>
          <code className="font-mono">report.json</code> — a smaller extract: verification
          results and the pre-sanitize findings list only, not the full action-by-action record
          (that&apos;s manifest.json).
        </li>
        <li>
          <code className="font-mono">release_packet.json</code> — content hashes for every
          file above plus an Ed25519 signature from this deployment&apos;s custody key over
          the packet&apos;s recorded facts, checkable offline without trusting this page
          (not externally anchored — no independent timestamp).
        </li>
        <li>
          <code className="font-mono">README.txt</code> — names every file above for someone
          opening this packet without this page.
        </li>
        {includeOriginal && (
          <li>
            <code className="font-mono">original/{manifest.original.filename}</code> — the
            write-once original.
          </li>
        )}
      </ul>
      <p className="mt-2">
        Verification{" "}
        <span className={manifest.verification.pass ? "text-emerald-600" : "text-red-600"}>
          {manifest.verification.pass ? "passed" : "failed"}
        </span>
        {hasKeptWithoutReview ? (
          <>
            {" "}
            — but see the findings-kept-without-review notice above:{" "}
            <span className="font-medium text-red-600">
              a passed verification does not mean every finding was reviewed
            </span>
            .
          </>
        ) : (
          "."
        )}{" "}
        Every hash referenced above (original, derivative) is recorded inside
        manifest.json — nothing in this zip depends on trusting this page.
      </p>
    </div>
  );
}

function JobSkeleton() {
  return (
    <div className="animate-pulse space-y-4">
      <div className="h-7 w-48 rounded bg-black/[0.06] dark:bg-white/[0.06]" />
      <div className="h-4 w-64 rounded bg-black/[0.06] dark:bg-white/[0.06]" />
      <div className="h-24 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
      <div className="h-40 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
    </div>
  );
}

function JobView({
  matterId,
  jobId,
  highlight,
}: {
  matterId: string;
  jobId: string;
  highlight: string | null;
}) {
  const { data: job, error, loading, reload } = useApiData(
    () => api.get<Job>(`/v1/matters/${matterId}/jobs/${jobId}`),
    `job:${matterId}:${jobId}`,
  );
  // Only fetched for its perms -- to decide whether "Audit log →" (admin-
  // gated server-side) is worth showing, same reasoning as the matter
  // view page.
  const matterQ = useApiData(
    () => api.get<Matter>(`/v1/matters/${matterId}`),
    `matter:${matterId}`,
  );
  const perms = matterQ.data?.perms;
  const isPending = job?.status === "queued" || job?.status === "running";
  // Job execution is synchronous within the request that starts it (see
  // service/app/main.py's _execute_job), so "running" is rarely observed
  // from the tab that clicked Inspect/Sanitize — it shows up when a
  // second tab, or someone else's session, is looking at the same job
  // mid-flight. Poll rather than leave that tab stuck on stale "running"
  // until a manual reload, which is exactly the gap this page's own copy
  // used to admit.
  useEffect(() => {
    if (!isPending) return;
    const id = setInterval(reload, 3000);
    return () => clearInterval(id);
  }, [isPending, reload]);
  const manifestReady = job?.kind === "sanitize" && job.status === "done";
  const { data: manifest } = useApiData(
    () =>
      manifestReady
        ? api.get<Manifest>(`/v1/matters/${matterId}/jobs/${jobId}/manifest`)
        : Promise.resolve(null),
    `manifest:${matterId}:${jobId}:${manifestReady}`,
  );
  // Release context (PR 44): reuses the existing release-detail route --
  // no new backend surface. Fetched only when job.release_id is present
  // (PR 40's own mechanism for discovering a job's Release at all).
  const { data: release } = useApiData(
    () =>
      job?.release_id
        ? api.get<Release>(`/v1/matters/${matterId}/releases/${job.release_id}`)
        : Promise.resolve(null),
    `release:${matterId}:${job?.release_id ?? ""}`,
  );
  const [includeOriginal, setIncludeOriginal] = useState(false);
  // Dashboard "unreviewed findings" deep link (?highlight=unreviewed):
  // scroll straight to the warning once the manifest that renders it has
  // actually loaded, rather than landing on the top of a long job page
  // and leaving the operator to hunt for what they clicked through for.
  useEffect(() => {
    if (highlight !== "unreviewed" || !manifest) return;
    document.getElementById("unreviewed-findings")?.scrollIntoView({
      behavior: "smooth",
      block: "center",
    });
  }, [highlight, manifest]);

  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
      <div className="flex items-center justify-between">
        <Link href={`/matters/view?id=${matterId}`} className="text-sm text-muted hover:text-foreground">
          ← Matter
        </Link>
        {hasMatterPerm(perms, "admin") && (
          <Link
            href={`/matters/audit?id=${matterId}`}
            className="text-sm text-muted hover:text-foreground"
          >
            Audit log →
          </Link>
        )}
      </div>

      <div className="mt-4">
        {loading && <JobSkeleton />}
        {error && (
          <div className="rounded-md border border-red-600/30 bg-red-600/5 px-4 py-3 text-sm text-red-600">
            Couldn&apos;t load this job: {error}
          </div>
        )}

        {job && (
          <>
            <div className="mb-6">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-2xl font-semibold tracking-tight capitalize">
                  {/* job.kind is always "sanitize" for a release-wrapped
                      job (inspect never gets one) -- "Sanitize job" would
                      undersell what this page is actually about once a
                      Release exists for it. */}
                  {job.release_id ? "Release" : `${job.kind} job`}
                </h1>
                <StatusBadge status={job.status} />
                {/* A done sanitize job has a release packet (below) as its
                    primary output -- the packet already embeds this same
                    certificate, so the header link would be a second,
                    competing "main" action. Every other terminal case
                    (refused/failed -- no derivative, so no packet either;
                    a done inspect -- inspection never produces one) has
                    nothing else to be the primary action, so the
                    certificate stays here, prominent, as the one thing
                    to open. */}
                {(job.status === "refused" ||
                  job.status === "failed" ||
                  (job.status === "done" && job.kind === "inspect")) && (
                  <a
                    href={`/v1/matters/${matterId}/jobs/${jobId}/certificate`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ml-auto rounded-md border border-accent px-3 py-1 text-sm font-medium text-accent hover:bg-accent/10"
                  >
                    Open custody certificate
                  </a>
                )}
              </div>
              <p className="mt-1 text-sm text-muted">
                {job.kind === "sanitize" ? `${job.policy_id} · ` : ""}started{" "}
                {formatTimestamp(job.created_utc)}
                {job.finished_utc && ` · finished ${formatTimestamp(job.finished_utc)}`}
              </p>
              {/* PR 40: the ONLY way this page finds the Release that
                  wraps this job -- release_id travels on the job payload
                  itself, no separate Release detail page or lookup route.
                  release_result.json is produced for every terminal
                  release regardless of outcome, so this link doesn't need
                  to be gated on status the way the full release packet
                  section below is (that one only exists for a done
                  sanitize). Absent entirely for a job with no release_id
                  -- an inspect job, or one created through the
                  still-untouched legacy /sanitize-jobs route. */}
              {job.release_id && (
                <div className="mt-2 rounded-md border border-border bg-black/[0.02] px-3 py-2 text-sm dark:bg-white/[0.02]">
                  {/* PR 44: reuses GET .../releases/{id} (existing since
                      PR 39) -- no new backend route. release_result.json
                      already carried this data; it just wasn't rendered
                      anywhere a human would naturally look. Careful
                      language throughout: "prepared for release", never
                      "sent"/"delivered" -- this system has no way to know
                      whether the packet actually reached anyone. */}
                  {release ? (
                    <>
                      <p>
                        Prepared for release under{" "}
                        <span className="font-medium">{releaseProfileLabel(release.profile_id)}</span>
                        {" "}(<code className="font-mono text-xs">{release.profile_id}</code>)
                      </p>
                      <p className="mt-1 text-muted">
                        Recipient: {recipientTypeLabel(release.recipient_type)}
                        {release.recipient_name ? ` — ${release.recipient_name}` : ""}
                      </p>
                      {release.purpose && <p className="mt-1 text-muted">Purpose: {release.purpose}</p>}
                      <p className="mt-1 text-muted">
                        {release.intended_external
                          ? "Intended to leave the organization"
                          : "Intended to remain internal — not for external release"}
                      </p>
                    </>
                  ) : (
                    <p className="text-muted">Part of a release — loading details…</p>
                  )}
                  <p className="mt-2">
                    <a
                      href={`/v1/matters/${matterId}/releases/${job.release_id}/result`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-medium text-accent hover:underline"
                    >
                      Download release result (JSON)
                    </a>
                  </p>
                  {/* PR 45: this block renders for every terminal outcome
                      (done, refused, failed) -- release_result.json alone
                      is enough for the offline verifier to check, so this
                      is the one place that covers all three, rather than
                      only the done-packet section below. A command, not
                      just a name -- "the tool exists" wasn't discoverable
                      before this pass. */}
                  <p className="mt-2 text-xs text-muted">
                    Verify this file offline, independent of this system&apos;s own UI:
                    <br />
                    <code className="mt-1 block rounded bg-black/[0.04] px-2 py-1 font-mono dark:bg-white/[0.06]">
                      python3 tools/counselclear_verify_release_packet.py &lt;downloaded-file-or-folder&gt;
                    </code>
                    For a full release packet, also hand it the deployment&apos;s public key to
                    check the packet&apos;s Ed25519 signature:
                    <br />
                    <code className="mt-1 block rounded bg-black/[0.04] px-2 py-1 font-mono dark:bg-white/[0.06]">
                      python3 tools/counselclear_verify_release_packet.py --public-key
                      key.pem &lt;packet.zip&gt;
                    </code>
                    (save the key from{" "}
                    <a
                      href="/v1/custody-public-key"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="font-medium text-accent hover:underline"
                    >
                      this deployment&apos;s custody public key
                    </a>{" "}
                    into <code className="font-mono">key.pem</code> first — copy it to the
                    recipient out of band, not from this link).
                  </p>
                </div>
              )}
              {job.status === "failed" && job.error && (
                <div className="mt-3 rounded-md border border-red-600/30 bg-red-600/5 px-4 py-3 text-sm text-red-700 dark:text-red-400">
                  {job.error}
                </div>
              )}
              {job.status === "refused" && (
                <div className="mt-3 rounded-md border border-orange-600/30 bg-orange-600/5 px-4 py-3 text-sm text-orange-800 dark:text-orange-300">
                  {/* PR 47: PR 45's "this is expected, not an error" framing
                      overclaimed -- it's accurate for a deliberate refusal
                      (macros, an unattested signature) but not for a PDF
                      hitting the engine's own not-yet-implemented content-
                      strip paths, which also raises and lands here.
                      PR 48: those two cases are now told apart -- a
                      deliberate policy decision (nothing to ask for) reads
                      differently from a capability gap (the policy asked
                      for a removal the engine can't perform yet). Matched
                      by a narrow string check on job.error, not a
                      structured reason code -- see policies.py's own
                      PDF_CONTENT_REFUSAL_MARKER docstring for why: job.error
                      is a plain string end-to-end today (service/app/
                      runner.py's sync_job copies it verbatim from the
                      worker's result.json), and adding a real code would
                      need a Job column/migration to carry it through that
                      boundary. Keep this constant in sync with policies.py's
                      copy of the same string. */}
                  {isPdfContentCapabilityRefusal(job.error) ? (
                    <>
                      <p className="font-medium">
                        Refused — this policy would require removing PDF content that
                        isn&apos;t implemented yet.
                      </p>
                      <p className="mt-1">
                        {stripCapabilityRefusalPrefix(job.error)} This is a gap in what the
                        engine can currently remove, not a decision that this content should
                        stay.
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="font-medium">Refused by policy — no derivative was produced.</p>
                      <p className="mt-1">
                        The selected policy declined to produce a derivative for this document
                        rather than ship an incomplete or unsafe result.
                        {job.error ? ` ${job.error}` : ""}
                      </p>
                    </>
                  )}
                </div>
              )}
              {(job.status === "running" || job.status === "queued") && (
                <div className="mt-3 rounded-md border border-amber-600/30 bg-amber-600/5 px-4 py-3 text-sm text-amber-700 dark:text-amber-400">
                  {job.status === "running" ? "Running" : "Queued"} — this page checks again
                  automatically every few seconds.
                </div>
              )}
              {job.result?.verification_pass !== undefined && (
                <p className="mt-3 text-sm">
                  Verification:{" "}
                  <span
                    className={
                      job.result.verification_pass ? "text-emerald-600" : "text-red-600"
                    }
                  >
                    {job.result.verification_pass ? "passed" : "failed"}
                  </span>
                </p>
              )}
            </div>

            {job.kind === "inspect" && (
              <>
                <h2 className="mb-3 text-lg font-semibold tracking-tight">Findings</h2>
                <RiskSummary findings={job.result?.findings ?? []} />
                <FindingsByCategory findings={job.result?.findings ?? []} />
              </>
            )}
            {job.kind === "sanitize" && manifest && (
              <>
                <h2 className="mb-3 text-lg font-semibold tracking-tight">Manifest</h2>
                <SanitizeManifestView manifest={manifest} />
              </>
            )}

            {job.status === "done" && job.kind === "sanitize" && (
              <div className="mb-6 rounded-md border-2 border-accent p-4">
                <p className="mb-3 text-sm font-medium">
                  Release packet — the derivative and its verification manifest, together
                </p>
                <div className="flex flex-wrap items-center gap-3">
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={includeOriginal}
                      onChange={(e) => setIncludeOriginal(e.target.checked)}
                    />
                    Include original in packet
                  </label>
                  <a
                    href={`/v1/matters/${matterId}/jobs/${jobId}/bundle${includeOriginal ? "?include_original=true" : ""}`}
                    className="ml-auto rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-white hover:opacity-90"
                  >
                    Download release packet
                  </a>
                </div>
                {/* The packet already embeds this exact certificate
                    (certificate.html) -- this is only for reading it
                    without downloading/unzipping anything, not a second
                    "main" action next to the packet button above. */}
                <p className="mt-2 text-xs text-muted">
                  Includes the derivative, manifest, and custody certificate. Prefer to read
                  the certificate first?{" "}
                  <a
                    href={`/v1/matters/${matterId}/jobs/${jobId}/certificate`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium text-accent hover:underline"
                  >
                    Open it on its own
                  </a>
                  .
                </p>
                {/* PR 37: honest, narrow claim only -- what the packet
                    actually lets a recipient do (recompute hashes offline
                    and confirm nothing was swapped), not what it doesn't
                    yet do. No "unforgeable"/"independently timestamped"/
                    "court-proof"/"unimpeachable" -- see
                    docs/release-packet-verification-and-anchoring-proposal.md
                    §7. PR 57: the packet is now Ed25519-signed by this
                    deployment's custody key (an operator signature, not
                    an external timestamp authority), so the honest
                    limitation is stated as exactly what remains missing:
                    external anchoring. */}
                <p className="mt-1 text-xs text-muted">
                  Also includes <code className="font-mono">release_packet.json</code>, a
                  machine-verifiable manifest — content hashes for every file in this packet
                  plus an Ed25519 signature over them by this deployment&apos;s custody key,
                  checkable offline with{" "}
                  <code className="font-mono">tools/counselclear_verify_release_packet.py</code>.
                  This packet is not externally anchored (no independent timestamp yet).
                </p>
                {manifest && (
                  <BundleContents manifest={manifest} includeOriginal={includeOriginal} />
                )}
              </div>
            )}
          </>
        )}
      </div>
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
  return <JobView matterId={matterId} jobId={jobId} highlight={params.get("highlight")} />;
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
