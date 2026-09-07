import { describe, expect, it } from "vitest";
import { documentResultLink } from "./documentResultLink";
import type { Job } from "./types";

type ResultJob = Pick<Job, "id" | "kind" | "status" | "release_id">;
const released: ResultJob = { id: "earlier", kind: "sanitize", status: "done", release_id: "r" };

describe("direct document result links", () => {
  it("offers no result before a job exists", () => {
    expect(documentResultLink([])).toBeNull();
  });

  it("takes the reviewer straight to an existing release", () => {
    expect(documentResultLink([released])).toEqual({ jobId: "earlier", label: "Review release" });
  });

  it.each([
    ["failed", "Review failure"],
    ["refused", "Review refusal"],
    ["queued", "View progress"],
    ["running", "View progress"],
  ] as const)("does not hide a newer %s behind an older success", (status, label) => {
    expect(documentResultLink([{ ...released, id: "latest", status }, released])).toEqual({
      jobId: "latest", label,
    });
  });

  it("links to the later inspection instead of the superseded release", () => {
    expect(documentResultLink([
      { id: "inspection", kind: "inspect", status: "done", release_id: null }, released,
    ])).toEqual({ jobId: "inspection", label: "View inspection" });
  });

  it("does not imply a legacy sanitize job has a release record", () => {
    expect(documentResultLink([{ ...released, release_id: null }])?.label).toBe("View result");
  });
});
