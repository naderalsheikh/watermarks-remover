import type { Job } from "./types";

/** Poll bounded groups without overlapping requests; ignore every late response after disposal. */
export function startJobPolling(
  ids: string[],
  fetchJob: (id: string, signal: AbortSignal) => Promise<Job>,
  update: (jobs: Job[], error: string | null) => void,
) {
  const controller = new AbortController();
  const pending = [...ids];
  let timer: ReturnType<typeof setTimeout>;
  async function poll() {
    const group = pending.splice(0, 10);
    const settled = await Promise.allSettled(group.map(id => fetchJob(id, controller.signal)));
    if (controller.signal.aborted) return;
    const jobs: Job[] = [];
    let failed = false;
    settled.forEach((result, index) => {
      if (result.status === "rejected") {
        failed = true;
        pending.push(group[index]);
      } else {
        jobs.push(result.value);
        if (["queued", "running"].includes(result.value.status)) pending.push(group[index]);
      }
    });
    update(jobs, failed ? "Job status could not be refreshed. Work continues on the server; this page will retry." : null);
    if (pending.length) timer = setTimeout(poll, 3000);
  }
  timer = setTimeout(poll, 0);
  return () => { controller.abort(); clearTimeout(timer); };
}
