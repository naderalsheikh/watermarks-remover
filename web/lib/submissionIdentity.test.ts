import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

function response(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  const values = new Map<string, string>();
  vi.stubGlobal("sessionStorage", {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  });
});
afterEach(() => vi.unstubAllGlobals());

describe("durable browser submission", () => {
  it("reuses the key after an uncertain response and asks for asynchronous admission", async () => {
    const fetch = vi.fn().mockRejectedValueOnce(new TypeError("connection closed"))
      .mockResolvedValueOnce(response(202, { id: "existing-job", status: "queued" }))
      .mockResolvedValueOnce(response(202, { id: "new-job", status: "queued" }));
    vi.stubGlobal("fetch", fetch);
    const path = "/v1/matters/retry/documents/d/inspect-jobs";
    await expect(api.submit(path)).rejects.toThrow("Retry with the same details");
    expect(await api.submit(path)).toMatchObject({ id: "existing-job" });
    expect(fetch.mock.calls[0][1].headers["Idempotency-Key"]).toBe(fetch.mock.calls[1][1].headers["Idempotency-Key"]);
    expect(fetch.mock.calls[1][1].headers.Prefer).toBe("respond-async");
    await api.submit(path);
    expect(fetch.mock.calls[2][1].headers["Idempotency-Key"]).not.toBe(fetch.mock.calls[1][1].headers["Idempotency-Key"]);
  });

  it("coalesces concurrent clicks and equivalent reordered form fields", async () => {
    const fetch = vi.fn().mockResolvedValue(response(202, { id: "j" }));
    vi.stubGlobal("fetch", fetch);
    const path = "/v1/matters/race/documents/d/releases";
    const [first, second] = await Promise.all([
      api.submit(path, { purpose: "Synthetic", profile_id: "external" }),
      api.submit(path, { profile_id: "external", purpose: "Synthetic" }),
    ]);
    expect(first).toEqual(second);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("stores no raw request content and retains identity across module reload", async () => {
    const set = vi.spyOn(sessionStorage, "setItem");
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("offline")));
    const path = "/v1/matters/reload/documents/d/releases";
    const body = { purpose: "Private synthetic purpose" };
    await expect(api.submit(path, body)).rejects.toThrow();
    const firstKey = set.mock.calls.at(-1)![1];
    expect(JSON.stringify(set.mock.calls)).not.toContain(body.purpose);
    expect(JSON.stringify(set.mock.calls)).not.toContain(path);
    vi.resetModules();
    const { api: restored } = await import("./api");
    const fetch = vi.fn().mockResolvedValue(response(202, { id: "original" }));
    vi.stubGlobal("fetch", fetch);
    await restored.submit(path, body);
    expect(fetch.mock.calls[0][1].headers["Idempotency-Key"]).toBe(firstKey);
  });
});
