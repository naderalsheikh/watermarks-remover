import type { BulkJobResult } from "./types";

// service/app/main.py's cancel_batch sets this exact error string on a
// queued child it cancels (never on a real worker failure) -- mirrored
// here (not imported; the frontend has no build-time link to the
// backend) so a cancelled child can be labeled distinctly from a real
// failure instead of both collapsing into the same opaque "failed" badge.
export const CANCELLED_ERROR = "cancelled by operator";

export function isCancelledResult(r: Pick<BulkJobResult, "status" | "error">): boolean {
  return r.status === "failed" && r.error === CANCELLED_ERROR;
}
