import { describe, expect, it } from "vitest";
import { documentNextStep, STATUS_TONE_LABEL } from "./documentNextStep";
import type { Job, ReleaseProfile } from "./types";

const PROFILES: ReleaseProfile[] = [
  { id: "ediscovery_production", label: "E-Discovery / Production Release", policy_id: "production", description: "" },
];

function job(partial: Partial<Job>): Job {
  return {
    id: "j1",
    document_id: "d1",
    matter_id: "m1",
    kind: "inspect",
    status: "done",
    created_utc: "2026-08-01T00:00:00Z",
    finished_utc: "2026-08-01T00:01:00Z",
    release_id: null,
    ...partial,
  } as Job;
}

describe("documentNextStep vocabulary", () => {
  it("uses release wording, never bare 'sanitize', for a done release-wrapped job", () => {
    const out = documentNextStep(
      [job({ kind: "sanitize", status: "done", release_id: "r1", profile_id: "ediscovery_production" })],
      PROFILES,
    );
    expect(out.tone).toBe("emerald");
    expect(out.label).toContain("Released under");
    expect(out.label).not.toMatch(/\bsanitize\b/i);
  });

  it("keeps 'Sanitize in progress' for a legacy in-flight sanitize, but reads as in-progress either way", () => {
    const out = documentNextStep([job({ kind: "sanitize", status: "running" })], PROFILES);
    expect(out.tone).toBe("amber");
    expect(out.label).toContain("in progress");
  });

  it("says 'prepare a release packet' in the legacy not-yet-released state, not 'choose a policy and sanitize'", () => {
    const out = documentNextStep([job({ kind: "inspect", status: "done" })], PROFILES);
    expect(out.tone).toBe("amber");
    expect(out.label).toBe("Inspected — not yet released");
    expect(out.detail).toBe("Prepare a release packet when ready.");
  });

  it("never claims a Release exists in the legacy path (no release_id)", () => {
    const states = [
      [job({ kind: "inspect", status: "done" })], // fresh inspect
      [job({ kind: "sanitize", status: "done" })], // done legacy sanitize
      [job({ kind: "inspect", status: "done" }), job({ kind: "sanitize", status: "done" })], // inspect after legacy sanitize
    ];
    for (const docJobs of states) {
      const out = documentNextStep(docJobs, PROFILES);
      expect(out.label).not.toContain("Released under");
      expect(out.detail).not.toContain("release result");
    }
  });

  it("surfaces an earlier done release as 'inspected again since last release' when a later inspect is latest", () => {
    const out = documentNextStep(
      [
        job({ kind: "inspect", status: "done", id: "j2", created_utc: "2026-08-02T00:00:00Z" }),
        job({
          kind: "sanitize",
          status: "done",
          id: "j1",
          release_id: "r1",
          profile_id: "ediscovery_production",
        }),
      ],
      PROFILES,
    );
    expect(out.label).toBe("Inspected again since last release");
    expect(out.tone).toBe("amber");
  });

  it("refused release vs refused legacy sanitize stay distinct and tone-matched", () => {
    const rel = documentNextStep([job({ kind: "sanitize", status: "refused", release_id: "r1" })], PROFILES);
    expect(rel.label).toBe("Release refused");
    expect(rel.detail).toContain("release result");
    const legacy = documentNextStep([job({ kind: "sanitize", status: "refused" })], PROFILES);
    expect(legacy.label).toBe("Refused by policy");
    expect(legacy.detail).toContain("job details");
    expect(legacy.tone).toBe("orange");
  });

  it("tone labels render the shared dual 'Sanitized / Released' label for the emerald tone", () => {
    expect(STATUS_TONE_LABEL.emerald).toBe("Sanitized / Released");
    expect(STATUS_TONE_LABEL.amber).toBe("In Progress / Needs Release");
    expect(STATUS_TONE_LABEL.muted).toBe("Not reviewed");
    expect(Object.keys(STATUS_TONE_LABEL).sort()).toEqual([
      "amber",
      "emerald",
      "muted",
      "orange",
      "red",
    ]);
    // First letter capitalized: the status-filter buttons read as
    // fragments, not raw lowercase enum values.
    for (const label of Object.values(STATUS_TONE_LABEL)) {
      expect(label[0]).toMatch(/[A-Z]/);
    }
  });
});
