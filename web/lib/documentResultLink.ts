import type { Job } from "./types";

/** Uses the same newest-first loaded history as documentNextStep. Never
 * substitute an older success for the latest failure or inspection. */
export function documentResultLink(
  jobs: readonly Pick<Job, "id" | "kind" | "status" | "release_id">[],
): { jobId: string; label: string } | null {
  const latest = jobs[0];
  if (!latest) return null;
  let label = "View result";
  if (latest.status === "queued" || latest.status === "running") label = "View progress";
  else if (latest.status === "refused") label = "Review refusal";
  else if (latest.status === "failed") label = "Review failure";
  else if (latest.release_id) label = "Review release";
  else if (latest.kind === "inspect") label = "View inspection";
  return { jobId: latest.id, label };
}
