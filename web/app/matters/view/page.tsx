"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { computeProductionReviewState } from "@/lib/productionReview";
import { useApiData } from "@/lib/useApi";
import { usePaginatedList } from "@/lib/usePaginatedList";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import { hasMatterPerm, permissionGate } from "@/lib/matterPermissions";
import { BULK_MAX_DOCUMENTS, bulkCapOverflow, isOverBulkCap } from "@/lib/bulkCap";
import { isCancelledResult } from "@/lib/batchCancel";
import {
  buildLegalJustifications,
  FALLBACK_LEGAL_BASIS_DISCLOSURE,
  KNOWN_LEGAL_BASES,
  LEGAL_BASIS_LABEL,
} from "@/lib/legalBasis";
import type { SubtypeBasisState } from "@/lib/legalBasis";
import type {
  BatchReleaseResponse,
  BatchResponse,
  Document,
  Job,
  Matter,
  Policy,
  ReleaseCreateResponse,
  ReleaseProfile,
  ReleaseProfilesResponse,
} from "@/lib/types";
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

// GET /v1/release-profiles' recipient_types are raw slugs (controlled
// vocabulary the backend can safely aggregate on, PR 39/40) — this is the
// one place they get a human-readable label. A slug missing from this map
// (a profile added server-side without a frontend update yet) still
// renders, just as its own raw slug, rather than disappearing.
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

// The single-document release action (PR 40): what used to be
// "Sanitize" is now "Prepare Release Packet" -- the user picks a release
// profile (a destination/use-case, RELEASE_PROFILES in main.py), not a
// raw policy_id. The resolved policy_id still drives the same
// per-finding production-review logic below (bulk_safe/production
// behavior didn't change, only how it's selected); it's shown only in
// the "Technical details" disclosure, never as the primary choice.
function ReleasePanel({
  matterId,
  docId,
  docJobs,
  releaseProfiles,
  recipientTypes,
  onClose,
  onDone,
}: {
  matterId: string;
  docId: string;
  docJobs: Job[];
  releaseProfiles: ReleaseProfile[];
  recipientTypes: string[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [profileId, setProfileId] = useState(releaseProfiles[0]?.id ?? "");
  const [recipientType, setRecipientType] = useState(recipientTypes[0] ?? "other");
  const [recipientName, setRecipientName] = useState("");
  const [purpose, setPurpose] = useState("");
  const [intendedExternal, setIntendedExternal] = useState(true);
  const [attest, setAttest] = useState(false);
  const [noDecisionAck, setNoDecisionAck] = useState(false);
  const [decisions, setDecisions] = useState<Record<string, "approve" | "keep">>({});
  // Per-kept-subtype legal basis + note (the PR 55/58 chain reaching the
  // operator): filled in for a row only when its decision is "keep" --
  // a basis is the evidentiary ground for content that SURVIVES the
  // derivative, and an approved (stripped) finding has none.
  const [bases, setBases] = useState<Record<string, SubtypeBasisState>>({});
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const selectedProfile = releaseProfiles.find((p) => p.id === profileId);
  const isProduction = selectedProfile?.policy_id === "production";

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
      // legal_justifications from the per-row basis picks: kept subtypes
      // with a real basis only -- see buildLegalJustifications. undefined
      // (nothing picked) omits the field entirely: a release with no
      // supplied basis is fully valid, never gated.
      const legal_justifications = buildLegalJustifications(decisions, bases);
      await api.post<ReleaseCreateResponse>(`/v1/matters/${matterId}/documents/${docId}/releases`, {
        profile_id: profileId,
        recipient_type: recipientType,
        recipient_name: recipientName,
        // Deliberately one shared field in this UI for two backend
        // fields (Job.reason, an existing audit-trail field, and
        // Release.purpose, new in PR 39) -- keeping them as separate
        // inputs here would be two near-duplicate text boxes for
        // something the operator experiences as one question ("why").
        reason: purpose,
        purpose,
        intended_external: intendedExternal,
        signature_break_attestation: attest,
        ...(finding_decisions ? { finding_decisions } : {}),
        ...(legal_justifications ? { legal_justifications } : {}),
      });
      onDone();
      onClose();
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Release failed to start");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="mt-2 space-y-3 rounded-md border border-border bg-black/[0.02] p-3 dark:bg-white/[0.02]">
      {/* PR 45: a first-time evaluator sees this dropdown with zero
          framing otherwise -- one honest sentence about what the packet
          records, not a claim about what it proves. No "safe"/"clean"/
          "court-proof" language; see docs/release-packet-verification-and
          -anchoring-proposal.md §7 for the forbidden-claims list this
          stays inside of. */}
      <p className="text-xs text-muted">
        A release packet is this system&apos;s record of what was checked, what changed, what
        was kept or refused, and what limitations remain — not a legal opinion or a &quot;safe to
        share&quot; guarantee.
      </p>
      <div>
        <label className="mb-1 block text-xs font-medium">Release profile</label>
        <select
          value={profileId}
          onChange={(e) => setProfileId(e.target.value)}
          className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
        >
          {releaseProfiles.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
        </select>
        {selectedProfile && <p className="mt-1 text-xs text-muted">{selectedProfile.description}</p>}
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="mb-1 block text-xs font-medium">Recipient (required)</label>
          <select
            value={recipientType}
            onChange={(e) => setRecipientType(e.target.value)}
            className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
          >
            {recipientTypes.map((rt) => (
              <option key={rt} value={rt}>
                {recipientTypeLabel(rt)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium">Recipient name (optional)</label>
          <input
            value={recipientName}
            onChange={(e) => setRecipientName(e.target.value)}
            className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
          />
        </div>
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
          {/* Same honesty rule the certificate renders on the other side: kept
              findings with no supplied basis read as "unspecified" there, so
              the pre-submit state says it too -- never a silent downgrade. */}
          <p className="mt-1">{FALLBACK_LEGAL_BASIS_DISCLOSURE}</p>
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
              const basis = bases[st]?.basis ?? "unspecified";
              const note = bases[st]?.note ?? "";
              return (
                <li key={st} className="space-y-1.5">
                  <div className="flex items-center justify-between gap-3">
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
                  </div>
                  {value === "keep" && (
                    <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)] gap-2">
                      {/* Legal basis for RETAINED content only: this row is
                          being kept, so the operator can state the
                          evidentiary ground the certificate will disclose.
                          Defaults to unspecified and is never required --
                          an unselected basis is recorded honestly as
                          unspecified, never blocking the release. */}
                      <select
                        value={basis}
                        onChange={(e) =>
                          setBases((b) => ({
                            ...b,
                            [st]: { basis: e.target.value as SubtypeBasisState["basis"], note },
                          }))
                        }
                        aria-label={`Legal basis for kept ${subtypeLabel(st)}`}
                        className="rounded border border-border bg-transparent px-1.5 py-1 text-xs outline-none focus:border-accent"
                      >
                        {KNOWN_LEGAL_BASES.map((v) => (
                          <option key={v} value={v}>
                            Basis: {LEGAL_BASIS_LABEL[v] ?? v}
                          </option>
                        ))}
                      </select>
                      <input
                        value={note}
                        onChange={(e) =>
                          setBases((b) => ({
                            ...b,
                            [st]: { basis, note: e.target.value },
                          }))
                        }
                        placeholder="Basis note (optional)"
                        aria-label={`Basis note for kept ${subtypeLabel(st)}`}
                        className="rounded border border-border bg-transparent px-1.5 py-1 text-xs outline-none focus:border-accent"
                      />
                    </div>
                  )}
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
      <div>
        <label className="mb-1 block text-xs font-medium">Purpose / reason (optional)</label>
        <input
          value={purpose}
          onChange={(e) => setPurpose(e.target.value)}
          className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
        />
      </div>
      <label className="flex items-center gap-2 text-xs">
        <input
          type="checkbox"
          checked={intendedExternal}
          onChange={(e) => setIntendedExternal(e.target.checked)}
        />
        This release is intended to leave the organization
      </label>
      {/* PR 47: was a top-level checkbox, always rendered regardless of
          whether this document has a signature at all -- there's no way
          to know that in advance without an inspect job (a Release can
          run without one), so it can't be conditionally hidden the way a
          real detection would. Moved into Technical details instead: it's
          genuinely an edge case, not a primary choice, and competing with
          "intended to leave the organization" for a first-time evaluator's
          attention overstated how often it matters. */}
      {selectedProfile && (
        <details className="text-xs text-muted">
          <summary className="cursor-pointer select-none">Technical details</summary>
          <p className="mt-1">
            Resolves to policy <code className="font-mono">{selectedProfile.policy_id}</code>. This
            release&apos;s packet is signed by this deployment&apos;s custody key but not
            externally anchored — see the release packet or release result for what that means.
          </p>
          <label className="mt-2 flex items-center gap-2">
            <input type="checkbox" checked={attest} onChange={(e) => setAttest(e.target.checked)} />
            I attest to breaking a digital signature, if this document has one
          </label>
        </details>
      )}
      {submitError && <p className="text-xs text-red-600">{submitError}</p>}
      <div className="flex gap-2">
        <button
          onClick={submit}
          disabled={submitting || !profileId || (needsFallbackGate && !noDecisionAck)}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {submitting ? "Starting…" : "Prepare release packet"}
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

// documentNextStep() returns the same tone for a done Release as for a
// done legacy sanitize (and for "in progress" either way) -- filtering
// by tone already correctly includes both, but "Sanitized"/"needs
// sanitize" alone implied only the legacy case, which a reader clicking
// the chip had no way to know included Released documents too.
const STATUS_TONE_LABEL: Record<StatusTone, string> = {
  muted: "Not reviewed",
  amber: "In progress / needs release",
  emerald: "Sanitized / Released",
  red: "Failed",
  orange: "Refused",
};

// The single "where are we, what's next" line for a document — the point
// isn't just showing the latest job's raw status (already visible in the
// job history disclosure below), it's translating that into what a
// reviewer should actually do next.
//
// Two paths, deliberately kept separate (PR 40): a job carrying
// release_id (created through POST .../releases) gets Release-aware
// wording; a job with no release_id -- either created before this pass
// shipped, or through the still-untouched legacy /sanitize-jobs route --
// keeps the exact original wording below, unchanged. This is a real data
// boundary, not a copy preference: a matter with pre-existing history has
// no Release rows to describe, and pretending otherwise would render as
// broken or misleading rather than just older.
function documentNextStep(
  docJobs: Job[],
  releaseProfiles: ReleaseProfile[],
): { tone: StatusTone; label: string; detail: string } {
  if (docJobs.length === 0) {
    return {
      tone: "muted",
      label: "Not yet reviewed",
      detail: "Inspect to see what's inside, or prepare a release directly.",
    };
  }
  const latest = docJobs[0];

  if (latest.release_id) {
    if (latest.status === "queued" || latest.status === "running") {
      return { tone: "amber", label: "Release in progress", detail: "Checking again automatically." };
    }
    if (latest.status === "failed") {
      return { tone: "red", label: "Release failed", detail: "See release result below." };
    }
    if (latest.status === "refused") {
      return {
        tone: "orange",
        label: "Release refused",
        detail: "No derivative was produced — see release result below.",
      };
    }
    const profile = releaseProfiles.find((p) => p.id === latest.profile_id);
    return {
      tone: "emerald",
      label: `Released under ${profile?.label ?? latest.profile_id ?? "unknown profile"}`,
      // Deliberately the same restraint the pre-Release wording already
      // had: never "clean" or "safe" -- a release can still have kept
      // findings without review (see NoDecisionWarning on the job page).
      detail: "Open the release for the packet, findings, and custody.",
    };
  }

  // --- legacy path: exact original wording, unchanged ---------------------
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
  // The badge above only looked at the single MOST RECENT job -- if that
  // happens to be a later inspect run, a still-real completed Release
  // earlier in the history must not silently read as legacy "sanitize"
  // wording just because it's no longer the latest job. Release-aware
  // only when that earlier done sanitize actually has one; otherwise
  // exactly the original legacy wording, unchanged.
  const lastDoneSanitize = docJobs.find((j) => j.kind === "sanitize" && j.status === "done");
  if (lastDoneSanitize?.release_id) {
    const profile = releaseProfiles.find((p) => p.id === lastDoneSanitize.profile_id);
    return {
      tone: "amber",
      label: "Inspected again since last release",
      detail: `The earlier release (${profile?.label ?? lastDoneSanitize.profile_id}) predates this inspection — review before relying on it.`,
    };
  }
  return lastDoneSanitize
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
  releaseProfiles,
  recipientTypes,
  onJobStarted,
  highlighted,
  selected,
  onToggleSelected,
  perms,
}: {
  matterId: string;
  doc: Document;
  jobs: Job[];
  releaseProfiles: ReleaseProfile[];
  recipientTypes: string[];
  onJobStarted: () => void;
  highlighted: boolean;
  selected: boolean;
  onToggleSelected: (id: string, checked: boolean) => void;
  perms: string[] | undefined;
}) {
  const [releasing, setReleasing] = useState(false);
  const [inspecting, setInspecting] = useState(false);
  const [inspectError, setInspectError] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const rowRef = useRef<HTMLLIElement>(null);
  const inspectGate = permissionGate(perms, "inspect");
  const sanitizeGate = permissionGate(perms, "sanitize");
  const docJobs = jobs
    .filter((j) => j.document_id === doc.id)
    .sort((a, b) => b.created_utc.localeCompare(a.created_utc));
  const nextStep = documentNextStep(docJobs, releaseProfiles);

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
                disabled={inspecting || !inspectGate.allowed}
                title={inspectGate.title}
                className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
              >
                {inspecting ? "Inspecting…" : "Inspect"}
              </button>
              <button
                onClick={() => setReleasing((v) => !v)}
                disabled={!sanitizeGate.allowed}
                title={sanitizeGate.title}
                className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
              >
                Prepare Release Packet
              </button>
            </div>
          </div>
        </div>
      </div>

      {inspectError && <p className="mt-2 text-xs text-red-600">{inspectError}</p>}

      {releasing && (
        <ReleasePanel
          matterId={matterId}
          docId={doc.id}
          docJobs={docJobs}
          releaseProfiles={releaseProfiles}
          recipientTypes={recipientTypes}
          onClose={() => setReleasing(false)}
          onDone={onJobStarted}
        />
      )}

      {/* Job history is execution detail, not the primary signal -- the
          release-aware badge above already says what matters. Collapsed
          by default (PR 40); still findable by anyone who wants the raw
          job-by-job record. */}
      {docJobs.length > 0 && (
        <details className="mt-2" open={showHistory} onToggle={(e) => setShowHistory(e.currentTarget.open)}>
          <summary className="cursor-pointer select-none text-xs text-muted hover:text-foreground">
            {showHistory ? "Hide" : "Show"} job history ({docJobs.length})
          </summary>
          <ul className="mt-1.5 space-y-1.5">
            {docJobs.map((j) => (
              <li key={j.id} className="flex items-center gap-2 text-xs">
                <Link
                  href={`/matters/job?matter=${matterId}&job=${j.id}`}
                  className="font-medium capitalize hover:underline"
                >
                  {/* PR 47: j.kind is always "sanitize" for a release-wrapped
                      job (inspect never gets one) -- the same reason the job
                      page's own H1 already branches on release_id instead of
                      showing raw kind. This list didn't, so every job-history
                      entry read "Sanitize" regardless of outcome. */}
                  {j.release_id ? "Release" : j.kind}
                </Link>
                <StatusBadge status={j.status} />
                {j.kind === "sanitize" && <span className="text-muted">{j.policy_id}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
    </li>
  );
}

function BulkRunPanel({
  matterId,
  docIds,
  kind,
  releaseProfiles,
  recipientTypes,
  onClose,
  onDone,
}: {
  matterId: string;
  docIds: string[];
  kind: "inspect" | "sanitize";
  releaseProfiles: ReleaseProfile[];
  recipientTypes: string[];
  onClose: () => void;
  onDone: (batch: BatchResponse) => void;
}) {
  // Only profiles whose resolved policy the backend marks bulk-safe are
  // offered here -- the caller (the matter page) already filtered this
  // list the same way create_batch_release enforces server-side, so the
  // UI can't even offer ediscovery_production (-> production) in bulk.
  const [profileId, setProfileId] = useState(releaseProfiles[0]?.id ?? "");
  const [recipientType, setRecipientType] = useState(recipientTypes[0] ?? "other");
  const [purpose, setPurpose] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const selectedProfile = releaseProfiles.find((p) => p.id === profileId);

  async function submit() {
    setSubmitting(true);
    setSubmitError(null);
    try {
      // Async either way: both routes return as soon as the batch and
      // its queued child jobs are recorded, not once every job has
      // finished -- BulkResults below polls the returned batch to
      // completion regardless of which route produced it.
      const batch =
        kind === "sanitize"
          ? (
              await api.post<BatchReleaseResponse>(`/v1/matters/${matterId}/releases`, {
                document_ids: docIds,
                profile_id: profileId,
                recipient_type: recipientType,
                purpose,
                reason: purpose,
              })
            ).batch
          : await api.post<BatchResponse>(`/v1/matters/${matterId}/batches`, {
              document_ids: docIds,
              kind,
            });
      onDone(batch);
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
            {kind === "sanitize" ? "Bulk release" : "Bulk inspect"} — {docIds.length} document
            {docIds.length === 1 ? "" : "s"} selected
          </p>
          {kind === "inspect" ? (
            <p className="mt-1 text-xs text-muted">
              Inspection is read-only: it only reports what&apos;s inside each document. No
              derivative is produced and nothing is modified.
            </p>
          ) : (
            <p className="mt-1 text-xs text-muted">
              Each document is released independently; every outcome — packet or refusal — is
              reported individually below.
            </p>
          )}
        </div>
        <button onClick={onClose} className="text-sm text-muted hover:text-foreground">
          Cancel
        </button>
      </div>

      {/* Defense in depth: the bulk bar already disables the button that
          opens this panel once selection exceeds the cap, but this panel
          is the actual pre-submit confirmation, so it re-checks rather
          than trusting the caller never to render it over the limit. */}
      {isOverBulkCap(docIds.length) && (
        <div className="rounded-md border border-red-600/40 bg-red-600/10 px-3 py-2 text-xs text-red-700 dark:text-red-400">
          {docIds.length} documents selected, but bulk actions are limited to{" "}
          {BULK_MAX_DOCUMENTS} at a time. Close this panel and deselect{" "}
          {bulkCapOverflow(docIds.length)} to continue.
        </div>
      )}

      {kind === "sanitize" && (
        <>
          <div>
            <label className="mb-1 block text-xs font-medium">Release profile</label>
            <select
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
              className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
            >
              {releaseProfiles.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.label}
                </option>
              ))}
            </select>
            {selectedProfile && (
              <p className="mt-1 text-xs text-muted">{selectedProfile.description}</p>
            )}
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium">Recipient</label>
            <select
              value={recipientType}
              onChange={(e) => setRecipientType(e.target.value)}
              className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
            >
              {recipientTypes.map((rt) => (
                <option key={rt} value={rt}>
                  {recipientTypeLabel(rt)}
                </option>
              ))}
            </select>
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
              Purpose / reason (optional, shared across all selected documents)
            </label>
            <input
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm outline-none focus:border-accent"
            />
          </div>
        </>
      )}

      {submitError && <p className="text-xs text-red-600">{submitError}</p>}
      <div className="flex gap-2">
        <button
          onClick={submit}
          disabled={
            submitting || (kind === "sanitize" && !profileId) || isOverBulkCap(docIds.length)
          }
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {submitting
            ? "Running…"
            : kind === "sanitize"
              ? "Release selected documents"
              : "Run bulk inspect"}
        </button>
      </div>
    </div>
  );
}

// Per-document results of the last bulk run — deliberately a row per
// document (filename, status, error, job link) so a refusal or failure is
// as visible as the successes; never a vague "batch succeeded". Polls the
// batch (PR 31: async, so most of a batch's life is spent queued/running
// in the background) every 2s until every child leaves queued/running,
// rendering whatever partial mix is loaded on each tick rather than
// waiting for completion to show anything.
function BulkResults({
  matterId,
  batch,
  onUpdate,
}: {
  matterId: string;
  batch: BatchResponse;
  onUpdate: (batch: BatchResponse) => void;
}) {
  const [cancelling, setCancelling] = useState(false);
  const pending = batch.finished_utc === null;

  useEffect(() => {
    if (!pending) return;
    const id = setInterval(async () => {
      try {
        const fresh = await api.get<BatchResponse>(
          `/v1/matters/${matterId}/batches/${batch.id}`,
        );
        onUpdate(fresh);
      } catch {
        // A transient poll failure just tries again on the next tick --
        // nothing to show the operator for one missed poll.
      }
    }, 2000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending, matterId, batch.id]);

  async function cancel() {
    setCancelling(true);
    try {
      const fresh = await api.post<BatchResponse>(
        `/v1/matters/${matterId}/batches/${batch.id}/cancel`,
      );
      onUpdate(fresh);
    } finally {
      setCancelling(false);
    }
  }

  const s = batch.summary;
  return (
    <div className="mb-4 rounded-md border border-border">
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-2 text-xs text-muted">
        <span>
          {s.done} done · {s.refused} refused · {s.failed} failed · {s.queued} queued ·{" "}
          {s.running} running — per document:
        </span>
        {pending && (
          <button
            onClick={cancel}
            disabled={cancelling}
            className="shrink-0 rounded-md border border-border px-2 py-1 text-xs font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
          >
            {cancelling ? "Cancelling…" : "Cancel remaining"}
          </button>
        )}
      </div>
      <ul className="divide-y divide-border">
        {batch.results.map((r) => {
          const cancelled = isCancelledResult(r);
          return (
            <li
              key={r.job_id}
              className="flex items-center justify-between gap-3 px-4 py-2 text-sm"
            >
              <div className="min-w-0">
                <p className="truncate font-medium">{r.document_name}</p>
                {r.error && !cancelled && (
                  <p className="truncate text-xs text-muted">{r.error}</p>
                )}
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {cancelled ? (
                  <span className="rounded px-2 py-0.5 text-xs font-medium bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                    cancelled
                  </span>
                ) : (
                  <StatusBadge status={r.status} />
                )}
                <Link
                  href={`/matters/job?matter=${matterId}&job=${r.job_id}`}
                  className="text-xs font-medium hover:underline"
                >
                  Open
                </Link>
              </div>
            </li>
          );
        })}
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

// A dedicated, labeled home for every matter-level report/export --
// previously these lived as three unlabeled "→" links crammed into the
// thin top nav row, indistinguishable from each other and from ordinary
// in-app navigation (Access, Audit log). Each item here names its own
// behavior explicitly (standalone HTML report vs. CSV download) rather
// than relying on the reader to infer it, and custody certificates (one
// per job, not one per matter -- there's no single link for "the"
// certificate) get an explicit pointer to where they actually live.
function ReportsAndExports({
  matterId,
  perms,
}: {
  matterId: string;
  perms: string[] | undefined;
}) {
  const linkClass =
    "shrink-0 rounded-md border border-border px-3 py-1.5 text-sm font-medium hover:bg-black/[0.03] dark:hover:bg-white/[0.03]";
  return (
    <div className="mb-4 rounded-md border border-border p-3">
      <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
        Reports &amp; exports
      </h2>
      <div className="flex flex-wrap gap-2">
        {hasMatterPerm(perms, "admin") && (
          <a
            href={`/v1/matters/${matterId}/summary`}
            target="_blank"
            rel="noopener noreferrer"
            className={linkClass}
          >
            Summary report <span className="font-normal text-muted">— HTML, opens in a new tab</span>
          </a>
        )}
        {/* Plain <a>, not the api client: a CSV file download, same pattern
            as the job page's bundle download. Exports every job in the
            matter, never just what's loaded on this page. Read-gated, not
            admin -- always safe to show once this page has loaded at all
            (reaching it already required read). */}
        <a href={`/v1/matters/${matterId}/jobs/export`} className={linkClass}>
          Jobs CSV <span className="font-normal text-muted">— downloads immediately</span>
        </a>
        {hasMatterPerm(perms, "admin") && (
          <a href={`/v1/matters/${matterId}/audit/export`} className={linkClass}>
            Audit CSV <span className="font-normal text-muted">— downloads immediately</span>
          </a>
        )}
      </div>
      <p className="mt-2 text-xs text-muted">
        Custody certificates are per document, not per matter — open any completed inspect or
        release job below and use its <strong>Open custody certificate</strong> link.
      </p>
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
  // Empty (not "everything") while matterQ hasn't resolved yet -- a
  // permission-gated control should never render as usable before we
  // actually know the principal has the perm, only after.
  const perms = matterQ.data?.perms;
  const uploadGate = permissionGate(perms, "upload");
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
  // Release profiles (PR 40): the user-facing destination/use-case list
  // for both the single-document and bulk release actions. policyId
  // stays internal (see ReleasePanel's "Technical details" disclosure) --
  // this fetch is what replaces raw policy selection everywhere it was
  // ever offered as a primary choice.
  const releaseProfilesQ = useApiData(
    () => api.get<ReleaseProfilesResponse>("/v1/release-profiles"),
    "release-profiles",
  );
  const fileInput = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  // Bulk selection: ids of loaded documents. Deliberately scoped to what's
  // loaded (same "loaded-so-far" honesty as the search/filter) — the bulk
  // bar labels it as such, and the backend refuses ids that aren't
  // documents of this matter, so a stale selection can't silently no-op.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkAction, setBulkAction] = useState<"inspect" | "sanitize" | null>(null);
  const [batch, setBatch] = useState<BatchResponse | null>(null);
  // Reload the documents/jobs lists exactly once per batch, the moment it
  // leaves queued/running -- keyed by batch id (a ref, not component
  // lifetime) so it survives BulkResults unmounting/remounting and can't
  // fire twice for the same batch or refire on every poll tick.
  const reloadedForBatch = useRef<string | null>(null);
  useEffect(() => {
    if (!batch || batch.finished_utc === null) return;
    if (reloadedForBatch.current === batch.id) return;
    reloadedForBatch.current = batch.id;
    jobsQ.reload();
    docsQ.reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [batch]);
  const bulkSafePolicies = (policiesQ.data?.policies ?? []).filter((p) => p.bulk_safe);
  // Derived from the same two already-fetched lists, not hardcoded --
  // whichever release profiles resolve to a bulk-safe policy (matches
  // create_batch_release's own server-side check exactly, service/app/main.py).
  const bulkSafePolicyIds = new Set(bulkSafePolicies.map((p) => p.id));
  const bulkSafeReleaseProfiles = (releaseProfilesQ.data?.release_profiles ?? []).filter((p) =>
    bulkSafePolicyIds.has(p.policy_id),
  );
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
      if (documentNextStep(docJobs, releaseProfilesQ.data?.release_profiles ?? []).tone !== statusFilter) return false;
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
          {/* Access/Audit log/Summary report are all admin-gated server-side
              (GET .../acl, .../audit, .../summary) -- hidden rather than
              shown-disabled, since a link either goes somewhere or it
              doesn't; there's no useful "why" to explain for a plain
              navigation link the way there is for an action button below.
              Not rendered at all until matterQ resolves (perms starts
              empty), so nothing flashes visible-then-hidden. */}
          {hasMatterPerm(perms, "admin") && (
            <Link
              href={`/matters/access?id=${matterId}`}
              className="whitespace-nowrap text-sm text-muted hover:text-foreground"
            >
              Access →
            </Link>
          )}
          {hasMatterPerm(perms, "admin") && (
            <Link
              href={`/matters/audit?id=${matterId}`}
              className="whitespace-nowrap text-sm text-muted hover:text-foreground"
            >
              Audit log →
            </Link>
          )}
        </div>
      </div>
      <h1 className="mb-1 mt-2 flex items-center gap-2 text-2xl font-semibold tracking-tight">
        {matterQ.data?.name ?? (matterQ.loading ? "Loading…" : "Matter")}
        {matterQ.data?.is_demo && (
          <span className="rounded border border-border px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide text-muted">
            Demo matter
          </span>
        )}
      </h1>
      {matterQ.data?.is_demo && (
        <p className="mb-2 text-xs text-muted">
          Sample data for evaluating the Release Gate — not a real client matter.
        </p>
      )}
      {matterQ.error && <p className="mb-4 text-sm text-red-600">{matterQ.error}</p>}

      {matterQ.data && <ReportsAndExports matterId={matterId} perms={perms} />}

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
          was overflowing the viewport horizontally below phone width.
          Disabled (not hidden), unlike the nav links above: this is an
          action a reviewer might reasonably expect to have and the
          "why can't I do this" explanation is worth keeping visible,
          same reasoning as the per-document/bulk buttons below. */}
      {/* PR 47: "Load sample matter" reuses the same demo matter forever
          (by name + is_demo) -- an evaluator's own test upload here has no
          reset path and silently makes every future demo session noisier.
          A note, not a block: uploading here is a real, supported action,
          just one worth a second thought on a matter meant to stay a
          clean walkthrough. */}
      {matterQ.data?.is_demo && (
        <p className="mb-1 text-xs text-muted">
          This is the shared demo matter — uploads here stick around for every future
          walkthrough. Create a new matter instead if you want to try your own document.
        </p>
      )}
      <form onSubmit={upload} className="mb-1 flex flex-wrap items-center gap-2">
        <input
          ref={fileInput}
          type="file"
          required
          disabled={!uploadGate.allowed}
          className="min-w-0 flex-1 text-sm file:mr-3 file:rounded-md file:border file:border-border file:bg-transparent file:px-3 file:py-1.5 file:text-sm disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={uploading || !uploadGate.allowed}
          title={uploadGate.title}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {uploading ? "Uploading…" : "Upload"}
        </button>
      </form>
      <p className="mb-8 h-4 text-xs text-muted">
        {!matterQ.loading && uploadGate.title}
      </p>
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
            : "No documents yet — upload one above to inspect or release it."}
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

              {batch && <BulkResults matterId={matterId} batch={batch} onUpdate={setBatch} />}

              {bulkAction && (
                <BulkRunPanel
                  matterId={matterId}
                  docIds={[...selected]}
                  kind={bulkAction}
                  releaseProfiles={bulkSafeReleaseProfiles}
                  recipientTypes={releaseProfilesQ.data?.recipient_types ?? []}
                  onClose={() => setBulkAction(null)}
                  onDone={(newBatch) => {
                    setBatch(newBatch);
                    setSelected(new Set());
                    // The batch's children are now real queued Job rows --
                    // reflect that immediately rather than waiting for the
                    // batch to finish.
                    jobsQ.reload();
                    docsQ.reload();
                  }}
                />
              )}

              {selected.size > 0 && !bulkAction && (
                <div className="mb-3 rounded-md border border-border bg-black/[0.02] px-3 py-2 dark:bg-white/[0.02]">
                  <div className="flex flex-wrap items-center gap-3">
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
                      {hasMatterPerm(perms, "inspect") && (
                        <button
                          onClick={() => setBulkAction("inspect")}
                          disabled={isOverBulkCap(selected.size)}
                          className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
                        >
                          Bulk inspect
                        </button>
                      )}
                      {hasMatterPerm(perms, "sanitize") && bulkSafeReleaseProfiles.length > 0 && (
                        <button
                          onClick={() => setBulkAction("sanitize")}
                          disabled={isOverBulkCap(selected.size)}
                          className="rounded-md border border-border px-3 py-1.5 text-xs font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
                        >
                          Bulk release…
                        </button>
                      )}
                    </div>
                  </div>
                  {/* Disclosed here, before the pre-submit panel even
                      opens, not just inside it -- the backend hard-caps a
                      batch at 100 documents (service/app/main.py
                      create_batch); "select all loaded" across a few
                      pages can exceed that with nothing in the
                      confirmation panel warning about it, so a submit
                      would otherwise only fail with a raw 400 after the
                      user already clicked through. */}
                  {isOverBulkCap(selected.size) && (
                    <p className="mt-2 text-xs text-red-600">
                      Bulk actions are limited to {BULK_MAX_DOCUMENTS} documents at a time.
                      Deselect {bulkCapOverflow(selected.size)} to continue.
                    </p>
                  )}
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
                    releaseProfiles={releaseProfilesQ.data?.release_profiles ?? []}
                    recipientTypes={releaseProfilesQ.data?.recipient_types ?? []}
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
                    perms={perms}
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
