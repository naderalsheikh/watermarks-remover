// documentNextStep, extracted from web/app/matters/view/page.tsx
// (2026-08-29 UX pass): it grew to ~90 lines of branch logic with
// operator-facing wording in every arm, all untestable inside the page
// component. The page now imports this; the vocabulary lives here where
// a unit test can pin it.
//
// Two paths, deliberately kept separate (PR 40): a job carrying
// release_id (created through POST .../releases) gets Release-aware
// wording; a job with no release_id -- either created before that pass
// shipped, or through the still-untouched legacy /sanitize-jobs route
// -- keeps the legacy arm below. This is a real data boundary, not a
// copy preference: a matter with pre-existing history has no Release
// rows to describe, and pretending otherwise would render as broken or
// misleading rather than just older. What changed in this pass is the
// legacy arm's WORDING: it previously said "sanitize" as the verb for
// what the UI now calls preparing a release packet everywhere else --
// three raw "sanitize" strings survived on the main matter page after
// PR 40 renamed the action ("Sanitize in progress", "Inspected — not
// yet sanitized", "Choose a policy and sanitize when ready"). The
// legacy path keeps its own distinct labels (never claims a Release
// exists) but now uses the same verb as every other surface.

import type { Job, ReleaseProfile } from "@/lib/types";

export type StatusTone = "muted" | "amber" | "emerald" | "red" | "orange";

export const STATUS_TONE_CLASS: Record<StatusTone, string> = {
  muted: "text-muted",
  amber: "text-amber-600 dark:text-amber-400",
  emerald: "text-emerald-700 dark:text-emerald-400",
  red: "text-red-600",
  orange: "text-orange-700 dark:text-orange-400",
};

// documentNextStep() returns the same tone for a done Release as for a
// done legacy sanitize (and for "in progress" either way) -- filtering
// by tone already correctly includes both, but the label had
// "Sanitized" alone, which a reader clicking the chip had no way to
// know included Released documents too.
export const STATUS_TONE_LABEL: Record<StatusTone, string> = {
  muted: "Not reviewed",
  amber: "In Progress / Needs Release",
  emerald: "Sanitized / Released",
  red: "Failed",
  orange: "Refused",
};

export function documentNextStep(
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

  // --- legacy path (no release_id) ---------------------------------------
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
  // happens to be a later inspect run, a still-real completed release
  // earlier in the history must not silently read as legacy "sanitize"
  // wording just because it's no longer the latest job. Release-aware
  // only when that earlier done sanitize actually has one; otherwise
  // the legacy wording, now with the release verb.
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
        label: "Inspected — not yet released",
        detail: "Prepare a release packet when ready.",
      };
}
