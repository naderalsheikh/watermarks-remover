import { afterEach, expect, it, vi } from "vitest";
import { startJobPolling } from "./jobPolling";
import type { Job } from "./types";

function job(id: string, status: "running" | "done"): Job { return { id, status } as Job; }
afterEach(() => vi.useRealTimers());

it("polls bounded groups and retries failed reads without resubmitting work", async () => {
  vi.useFakeTimers();
  const fetch = vi.fn().mockImplementation(async (id: string) => {
    if (id === "j0" && fetch.mock.calls.length === 1) throw new Error("offline");
    return job(id, "done");
  });
  const update = vi.fn();
  const stop = startJobPolling(Array.from({ length: 12 }, (_, i) => `j${i}`), fetch, update);
  await vi.advanceTimersByTimeAsync(0);
  expect(fetch).toHaveBeenCalledTimes(10);
  expect(update.mock.calls[0][0]).toHaveLength(9);
  expect(update.mock.calls[0][1]).toContain("could not be refreshed");
  await vi.advanceTimersByTimeAsync(3000);
  expect(fetch).toHaveBeenCalledTimes(13);
  expect(update.mock.calls[1][1]).toBeNull();
  await vi.advanceTimersByTimeAsync(30000);
  expect(fetch).toHaveBeenCalledTimes(13);
  stop();
});

it("aborts and ignores late responses after navigation", async () => {
  vi.useFakeTimers();
  let resolve!: (job: Job) => void;
  let signal!: AbortSignal;
  const fetch = vi.fn((_id: string, s: AbortSignal) => {
    signal = s;
    return new Promise<Job>(done => { resolve = done; });
  });
  const update = vi.fn();
  const stop = startJobPolling(["j"], fetch, update);
  await vi.advanceTimersByTimeAsync(0);
  stop();
  expect(signal.aborted).toBe(true);
  resolve(job("j", "running"));
  await vi.advanceTimersByTimeAsync(30000);
  expect(update).not.toHaveBeenCalled();
  expect(fetch).toHaveBeenCalledTimes(1);
});
