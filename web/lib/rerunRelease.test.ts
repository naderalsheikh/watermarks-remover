import { describe, expect, it } from "vitest";
import {
  buildRerunPayload,
  initialRerunState,
  isAttestationRefusalHint,
  pickPrefilledProfile,
} from "./rerunRelease";
import type { Job, Release, ReleaseProfile } from "./types";

const PROFILES: ReleaseProfile[] = [
  {
    id: "counterparty_deal_room",
    label: "Counterparty / Deal Room Release",
    policy_id: "counterparty",
    description: "",
  },
  {
    id: "ediscovery_production",
    label: "E-Discovery / Production Release",
    policy_id: "production",
    description: "",
  },
];

// A release-wrapped refused release job, minimally.
function job(partial: Partial<Job>): Job {
  return {
    id: "j1",
    matter_id: "m1",
    document_id: "d1",
    kind: "sanitize",
    policy_id: "production",
    status: "refused",
    error: null,
    attestation: false,
    worker_image: "",
    created_utc: "2026-08-01T00:00:00Z",
    finished_utc: "2026-08-01T00:01:00Z",
    release_id: "r1",
    profile_id: "ediscovery_production",
    ...partial,
  } as Job;
}

function release(partial: Partial<Release> = {}): Release {
  return {
    id: "r1",
    matter_id: "m1",
    document_id: "d1",
    batch_id: null,
    job_id: "j1",
    policy_id: "production",
    profile_id: "ediscovery_production",
    recipient_type: "opposing_counsel",
    recipient_name: "Jane Roe",
    purpose: "Production set 3",
    intended_external: false,
    requested_by: "u1",
    status: "refused",
    created_utc: "2026-08-01T00:00:00Z",
    finished_utc: "2026-08-01T00:01:00Z",
    predecessor_release_id: null,
    ...partial,
  } as Release;
}

describe("pickPrefilledProfile (legacy policy -> profile mapping)", () => {
  it("maps a legacy job's policy_id to the release profile that resolves to it", () => {
    expect(pickPrefilledProfile("production", PROFILES)).toBe("ediscovery_production");
    expect(pickPrefilledProfile("counterparty", PROFILES)).toBe("counterparty_deal_room");
  });

  it("falls back to the first profile when no profile resolves to the policy", () => {
    // e.g. a pre-PR-40 internal policy with no user-facing destination:
    // an empty select would be a dead control, a changeable default isn't.
    expect(pickPrefilledProfile("internal_only", PROFILES)).toBe("counterparty_deal_room");
  });

  it("falls back to an empty string (a disabled submit) when there are no profiles at all", () => {
    expect(pickPrefilledProfile("production", [])).toBe("");
  });
});

describe("initialRerunState", () => {
  it("prefills every editable field from the actual Release row for a release-wrapped job", () => {
    const state = initialRerunState(job({ attestation: true }), release(), PROFILES);
    expect(state).toEqual({
      profileId: "ediscovery_production",
      recipientType: "opposing_counsel",
      recipientName: "Jane Roe",
      purpose: "Production set 3",
      intendedExternal: false,
      attestation: true,
      predecessorId: "r1",
    });
  });

  it("carries the Job row's attestation bool even though the Release row doesn't have one", () => {
    // _release_dict has no attestation field -- the job payload's own
    // bool is the source of truth, so a signature-attested original
    // must not silently read as unattested on the re-run.
    const attested = initialRerunState(job({ attestation: true }), release(), PROFILES);
    expect(attested.attestation).toBe(true);
    const unattested = initialRerunState(job({ attestation: false }), release(), PROFILES);
    expect(unattested.attestation).toBe(false);
  });

  it("falls back to the job payload's own profile_id when the Release row is missing but the job has one", () => {
    // The job payload carries profile_id exactly when a Release wrapper
    // exists (PR 40), so if the Release fetch errors the panel still
    // prefills the SAME profile -- never silently substitutes the first
    // one for a job whose real profile is known.
    const state = initialRerunState(job({ attestation: false }), null, PROFILES);
    expect(state.profileId).toBe("ediscovery_production");
    expect(state.recipientType).toBe("other"); // ReleaseBody default, not fabricated
  });

  it("maps a legacy job's policy to a profile and takes ReleaseBody's defaults for the rest", () => {
    const state = initialRerunState(
      job({ release_id: null, profile_id: null, policy_id: "counterparty", attestation: false }),
      null,
      PROFILES,
    );
    expect(state).toEqual({
      profileId: "counterparty_deal_room",
      recipientType: "other",
      recipientName: "",
      purpose: "",
      intendedExternal: true,
      attestation: false,
      predecessorId: null,
    });
  });

  it("exposes the original's recipient name and purpose as editable state, not hidden values", () => {
    // buildRerunPayload sends recipient_name/purpose verbatim from state;
    // the original Release's values land in that state (prev test), so the
    // re-run form MUST render both fields (the page does, matching the
    // matter view's own inputs). The contract this pins: no prefilled
    // field may be POSTed that the operator couldn't see or change — a
    // custody record must not silently carry values nobody reviewed.
    const state = initialRerunState(job({ attestation: false }), release(), PROFILES);
    expect(state.recipientName).toBe("Jane Roe");
    expect(state.purpose).toBe("Production set 3");
    const payload = buildRerunPayload(state);
    expect(payload.recipient_name).toBe("Jane Roe");
    expect(payload.purpose).toBe("Production set 3");
  });

  it("agrees with itself across the pre-Release and post-Release states on the fields the Job carries", () => {
    // The panel can render before the release fetch resolves (release
    // is null while loading). The Job payload's own attestation is
    // available either way, so that field must not flip between the two
    // states; profile/recipient/purpose legitimately differ (the Release
    // row is the source of truth once it arrives).
    const before = initialRerunState(job({ attestation: false }), null, PROFILES);
    const after = initialRerunState(job({ attestation: false }), release(), PROFILES);
    expect(before.attestation).toBe(after.attestation);
    expect(after.profileId).toBe("ediscovery_production");
    expect(after.recipientType).toBe("opposing_counsel");
    expect(after.recipientName).toBe("Jane Roe");
    expect(after.purpose).toBe("Production set 3");
  });
});

describe("buildRerunPayload", () => {
  it("sends every prefilled field, attestation included, for a release-wrapped prefill", () => {
    const state = initialRerunState(job({ attestation: true }), release(), PROFILES);
    expect(buildRerunPayload(state)).toEqual({
      profile_id: "ediscovery_production",
      recipient_type: "opposing_counsel",
      recipient_name: "Jane Roe",
      purpose: "Production set 3",
      intended_external: false,
      reason: "Production set 3",
      signature_break_attestation: true,
      predecessor_release_id: "r1",
    });
  });

  it("names the immediate predecessor, never a transitive one", () => {
    // Re-running a re-run (A refused -> B re-run -> this panel re-runs
    // B): the new release must point at B -- the release it actually
    // supersedes -- not inherit B's own link back to A. The custody
    // record's supersession chain is one hop per release, by design.
    const rerunOfRerun = release({
      id: "r2",
      predecessor_release_id: "r1",
    });
    const state = initialRerunState(job({ attestation: false }), rerunOfRerun, PROFILES);
    expect(state.predecessorId).toBe("r2");
    expect(buildRerunPayload(state).predecessor_release_id).toBe("r2");
  });

  it("omits predecessor_release_id entirely for a legacy job (no Release row to name)", () => {
    // No Release row exists -> the re-run of a legacy job IS a first
    // release from the custody record's point of view. "no field" is
    // the backend's own first-release shape; sending null would be a
    // distinct third shape nothing consumes.
    const state = initialRerunState(
      job({ release_id: null, profile_id: null, policy_id: "counterparty" }),
      null,
      PROFILES,
    );
    const payload = buildRerunPayload(state);
    expect("predecessor_release_id" in payload).toBe(false);
  });

  it("sends ReleaseBody's own defaults when nothing was prefilled", () => {
    // recipient_type defaults to "other" and intended_external to true
    // (service/app/main.py ReleaseBody) -- an untouched re-run must send
    // exactly what the backend would have defaulted it to, never a
    // stricter or looser silent substitution.
    const payload = buildRerunPayload({
      profileId: "ediscovery_production",
      recipientType: "other",
      recipientName: "",
      purpose: "",
      intendedExternal: true,
      attestation: false,
      predecessorId: null,
    });
    expect(payload.recipient_type).toBe("other");
    expect(payload.intended_external).toBe(true);
    expect(payload.profile_id).toBe("ediscovery_production");
    expect(payload.signature_break_attestation).toBe(false);
  });

  it("keeps reason mirroring purpose (one operator question, two backend fields)", () => {
    const payload = buildRerunPayload({
      profileId: "ediscovery_production",
      recipientType: "other",
      recipientName: "",
      purpose: "Re-run after refusal",
      intendedExternal: true,
      attestation: false,
      predecessorId: "r1",
    });
    expect(payload.reason).toBe(payload.purpose);
    expect(payload.reason).toBe("Re-run after refusal");
  });
});

describe("isAttestationRefusalHint", () => {
  const SIGNATURE_REFUSAL =
    "plan refused: digitally signed file: signature-break attestation required before planning";

  it("hints only for the signature-attestation refusal with the checkbox unchecked", () => {
    expect(isAttestationRefusalHint(SIGNATURE_REFUSAL, false)).toBe(true);
  });

  it("does not hint once the checkbox is checked, or when the refusal was about something else", () => {
    expect(isAttestationRefusalHint(SIGNATURE_REFUSAL, true)).toBe(false);
    // Macros refusal: no attestation can save it, so hinting would imply
    // the checkbox helps when it can't.
    expect(isAttestationRefusalHint("plan refused: macro-enabled file refused by policy (no derivative path)", false)).toBe(false);
    expect(isAttestationRefusalHint("worker crashed mid-run", false)).toBe(false);
    expect(isAttestationRefusalHint(null, false)).toBe(false);
  });
});
