// rerunRelease, extracted from web/app/matters/job/page.tsx (2026-08-29
// UX pass): the re-run control's prefill/mapping logic, kept out of the
// page component so a unit test can pin it (same reasoning as
// documentNextStep/productionReview -- logic in lib, JSX in the page).
//
// Why this module exists at all: the dashboard's refused-attention item
// promises "re-run with a different policy or attestation" (web/app/
// dashboard/page.tsx) but the job page it deep-links to offered only
// certificate/release-result links for a refused/failed job -- the
// promise dead-ended. This is the control that keeps it.
//
// Route decision (settled by the lead, not re-derived here): the re-run
// ALWAYS goes through POST .../documents/{id}/releases, never the legacy
// /sanitize-jobs route -- the release flow is the only user-facing path
// (PR 40 policy). That includes a legacy refused job (no release_id):
// re-running it as a release is the supported path, with its policy_id
// mapped to whichever release profile resolves to that same policy.

import type { Job, Release, ReleaseProfile } from "@/lib/types";

// The panel's editable state -- the shape the page keeps in useState
// and the shape buildRerunPayload turns into the POST body.
export type RerunState = {
  profileId: string;
  recipientType: string;
  recipientName: string;
  purpose: string;
  intendedExternal: boolean;
  attestation: boolean;
};

// A release-wrapped refused/failed job (job.release_id set) prefills
// from the actual Release row the page already fetches (GET
// /v1/matters/{mid}/releases/{rid}); the attestation comes from the Job
// payload's own bool, because _release_dict doesn't carry it. If that
// Release row is missing (fetch not resolved -- the page only mounts
// the panel once it is, but the mapping shouldn't depend on that -- or
// the fetch errored), the job payload's own profile_id is the same value
// (it's set exactly when a Release wrapper exists), so profile falls back
// to it before falling back to the policy->profile mapping. A legacy job
// (no release wrapper, profile_id null) maps policy_id -> profile below;
// recipient/purpose take the backend's ReleaseBody defaults, which is
// what the operator sees: an empty adjustable field, never a fabricated
// one.
export function initialRerunState(
  job: Pick<Job, "attestation" | "policy_id" | "profile_id">,
  release: Release | null,
  profiles: ReleaseProfile[],
): RerunState {
  const profileId =
    release?.profile_id ?? job.profile_id ?? pickPrefilledProfile(job.policy_id, profiles);
  if (release) {
    return {
      profileId,
      recipientType: release.recipient_type,
      recipientName: release.recipient_name ?? "",
      purpose: release.purpose ?? "",
      intendedExternal: release.intended_external ?? true,
      attestation: job.attestation,
    };
  }
  return {
    profileId,
    recipientType: "other",
    recipientName: "",
    purpose: "",
    intendedExternal: true,
    attestation: job.attestation,
  };
}

// Policy -> release profile for a legacy job (no release_id, so no
// Release row to read a profile_id from). Exact match on policy_id: the
// original job ran under that policy, so the one release profile that
// resolves to it is the same-regulation re-run -- anything else would
// silently change what gets checked. If no profile resolves to it (the
// policy has no user-facing destination, e.g. a pre-PR-40 internal
// policy), fall back to the first profile rather than to an empty
// select the operator can't submit: a visible, changeable default beats
// a dead control, and the profile select makes the substitution clear.
export function pickPrefilledProfile(
  policyId: string,
  profiles: ReleaseProfile[],
): string {
  return profiles.find((p) => p.policy_id === policyId)?.id ?? profiles[0]?.id ?? "";
}

// The POST .../releases body. Mirrors ReleaseBody's own defaults
// (service/app/main.py: recipient_type="other", recipient_name="",
// purpose="", intended_external=True, reason="", signature_break_
// attestation=False) so an untouched field sends exactly what the
// backend would have defaulted it to anyway. reason rides along with
// purpose, the same one-shared-field decision ReleasePanel already
// made (two backend fields, one operator question: "why").
export function buildRerunPayload(state: RerunState): {
  profile_id: string;
  recipient_type: string;
  recipient_name: string;
  purpose: string;
  intended_external: boolean;
  reason: string;
  signature_break_attestation: boolean;
} {
  return {
    profile_id: state.profileId,
    recipient_type: state.recipientType,
    recipient_name: state.recipientName,
    purpose: state.purpose,
    intended_external: state.intendedExternal,
    reason: state.purpose,
    signature_break_attestation: state.attestation,
  };
}

// The subtle hint case: the original job was refused specifically for a
// missing signature-break attestation (policies.py's own refusal string
// -- "digitally signed file: signature-break attestation required
// before planning", carried verbatim into job.error via the worker's
// "plan refused: " prefix), and the checkbox is still unchecked. This is
// exactly the lever the re-run offers, but it's buried at the bottom of
// a form prefilled to repeat the original -- without the hint, the one
// change that would make this run differ is the easiest one to miss.
// Deliberately narrow (exact phrase, not a loose "attestation" grep): a
// macros refusal mentions no attestation because none can save it, and
// hinting there would falsely imply the checkbox helps.
const ATTESTATION_REFUSAL_PHRASE = "signature-break attestation required";

export function isAttestationRefusalHint(
  jobError: string | null,
  attestation: boolean,
): boolean {
  return !attestation && !!jobError && jobError.includes(ATTESTATION_REFUSAL_PHRASE);
}
