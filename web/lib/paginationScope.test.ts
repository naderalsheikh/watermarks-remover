import { describe, expect, it, vi } from "vitest";
import { createPaginationScope } from "./paginationScope";

type Page = { items: string[]; total: number };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function callbacks() {
  return { onStart: vi.fn(), onPage: vi.fn(), onError: vi.fn(), onSettled: vi.fn() };
}

describe("pagination request scopes", () => {
  it("allows one request at a time, including while the first page loads", async () => {
    const scope = createPaginationScope<Page>("matter:0");
    const first = deferred<Page>();
    const fetchPage = vi.fn(() => first.promise);
    const events = callbacks();
    const pending = scope.run(0, fetchPage, events);
    await scope.run(0, fetchPage, events);
    await scope.run(20, fetchPage, events);
    expect(fetchPage).toHaveBeenCalledTimes(1);
    expect(events.onStart).toHaveBeenCalledTimes(1);
    first.resolve({ items: ["one"], total: 2 });
    await pending;
    expect(events.onPage).toHaveBeenCalledTimes(1);
    expect(events.onSettled).toHaveBeenCalledTimes(1);
  });

  it("rejects an already completed offset even before the caller updates its view", async () => {
    const scope = createPaginationScope<Page>("matter:0");
    const events = callbacks();
    const fetchPage = vi.fn(async () => ({ items: ["one"], total: 2 }));
    await scope.run(0, fetchPage, events);
    await scope.run(0, fetchPage, events);
    expect(fetchPage).toHaveBeenCalledTimes(1);
    await scope.run(1, fetchPage, events);
    expect(fetchPage.mock.calls).toEqual([[0], [1]]);
  });

  it("allows retry at the same offset after a failed page", async () => {
    const scope = createPaginationScope<Page>("matter:0");
    const events = callbacks();
    await scope.run(0, async () => ({ items: ["one"], total: 2 }), events);
    const error = new Error("Connection lost");
    await scope.run(1, async () => { throw error; }, events);
    expect(events.onError).toHaveBeenCalledWith(error);
    const fetchPage = vi.fn(async () => ({ items: ["two"], total: 2 }));
    await scope.run(1, fetchPage, events);
    expect(fetchPage).toHaveBeenCalledWith(1);
    expect(events.onPage).toHaveBeenLastCalledWith({ items: ["two"], total: 2 });
    expect(events.onSettled).toHaveBeenCalledTimes(3);
  });

  it.each(["other-query:0", "matter:1"])(
    "ignores an old load-more result after replacing the scope with %s",
    async (nextKey) => {
      let visible = ["old first page"];
      let loadingMore = false;
      const oldScope = createPaginationScope<Page>("matter:0");
      await oldScope.run(0, async () => ({ items: visible, total: 2 }), callbacks());
      const oldPage = deferred<Page>();
      const oldPending = oldScope.run(1, () => oldPage.promise, {
        onStart: () => { loadingMore = true; },
        onPage: (page) => { visible.push(...page.items); },
        onError: vi.fn(),
        onSettled: () => { loadingMore = false; },
      });
      oldScope.cancel();
      const nextScope = createPaginationScope<Page>(nextKey);
      await nextScope.run(0, async () => ({ items: ["new first page"], total: 2 }), {
        onPage: (page) => { visible = page.items; },
        onError: vi.fn(),
      });
      const nextPage = deferred<Page>();
      const nextPending = nextScope.run(1, () => nextPage.promise, {
        onStart: () => { loadingMore = true; },
        onPage: (page) => { visible.push(...page.items); },
        onError: vi.fn(),
        onSettled: () => { loadingMore = false; },
      });
      oldPage.resolve({ items: ["wrong query"], total: 2 });
      await oldPending;
      expect(visible).toEqual(["new first page"]);
      expect(loadingMore).toBe(true);
      nextPage.resolve({ items: ["new second page"], total: 2 });
      await nextPending;
      expect(visible).toEqual(["new first page", "new second page"]);
      expect(loadingMore).toBe(false);
    },
  );

  it("ignores a late error after cancellation, including error-triggered navigation", async () => {
    const scope = createPaginationScope<Page>("matter:0");
    const events = callbacks();
    const response = deferred<Page>();
    const pending = scope.run(0, () => response.promise, events);
    scope.cancel();
    response.reject(new Error("Session expired"));
    await pending;
    expect(events.onError).not.toHaveBeenCalled();
    expect(events.onPage).not.toHaveBeenCalled();
    expect(events.onSettled).not.toHaveBeenCalled();
  });

  it("ignores success after unmount cleanup and refuses further requests", async () => {
    const scope = createPaginationScope<Page>("matter:0");
    const events = callbacks();
    const response = deferred<Page>();
    const fetchPage = vi.fn(() => response.promise);
    const pending = scope.run(0, fetchPage, events);
    scope.cancel();
    response.resolve({ items: ["too late"], total: 1 });
    await pending;
    await scope.run(0, fetchPage, events);
    expect(fetchPage).toHaveBeenCalledTimes(1);
    expect(events.onPage).not.toHaveBeenCalled();
    expect(events.onSettled).not.toHaveBeenCalled();
  });
});
