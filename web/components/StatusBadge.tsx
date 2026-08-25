import type { JobStatus } from "@/lib/types";

const STATUS_STYLE: Record<JobStatus, string> = {
  queued: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  running: "bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-300",
  done: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300",
  failed: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300",
  // Distinct from "failed" on purpose: a refusal is the policy engine
  // correctly declining to ship a derivative (e.g. a macro-enabled file),
  // not something broken — coloring it identically to a real failure
  // would misrepresent a working safety behavior as an error.
  refused: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
};

export function StatusBadge({ status }: { status: JobStatus }) {
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_STYLE[status]}`}>
      {status}
    </span>
  );
}
