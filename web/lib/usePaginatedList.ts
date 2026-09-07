"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError } from "./api";
import { createPaginationScope } from "./paginationScope";

export type Page<T, M = undefined> = { items: T[]; total: number; meta?: M };

type State<T, M> = {
  requestKey: string;
  items: T[];
  total: number;
  meta: M | undefined;
  error: string | null;
};

/** Accumulating pagination on top of an offset/limit list endpoint —
 * "Load more" appends a page rather than replacing the view, so scroll
 * position and any client-side search/filter over what's loaded survive
 * a load. Deliberately separate from useApiData rather than a variant of
 * it: accumulation only makes sense for list endpoints, and folding it
 * into the single-resource hook every other page relies on would risk
 * that hook's much wider blast radius for a need only four pages have.
 *
 * Same React-Compiler-safe shape as useApiData: `loading` (first page)
 * is derived from a requestKey comparison, not stored; `fetchPage` is
 * read through a ref, updated in its own effect, so a fresh closure each
 * render doesn't need to be an effect dependency; every setState call is
 * inside an async callback, never synchronously in the effect body.
 *
 * `key` identifies the whole list (e.g. a matter id) — changing it resets
 * to page 1. `reload()` forces a fresh page 1 without a key change (e.g.
 * after uploading a document or starting a job). `meta` carries anything
 * outside the paged items that every page response still repeats (the
 * audit endpoint's chain_ok/chain_detail, which reflect full-chain
 * verification and are the same on every page) — undefined for endpoints
 * that don't have one. */
export function usePaginatedList<T, M = undefined>(
  fetchPage: (offset: number) => Promise<Page<T, M>>,
  key: string,
) {
  const router = useRouter();
  const [tick, setTick] = useState(0);
  const requestKey = `${key}:${tick}`;
  const [state, setState] = useState<State<T, M>>({
    requestKey: "",
    items: [],
    total: 0,
    meta: undefined,
    error: null,
  });
  const [loadingMoreKey, setLoadingMoreKey] = useState<string | null>(null);
  const scopeRef = useRef<ReturnType<
    typeof createPaginationScope<Page<T, M>>
  > | null>(null);

  const fetchPageRef = useRef(fetchPage);
  useEffect(() => {
    fetchPageRef.current = fetchPage;
  });

  useEffect(() => {
    const scope = createPaginationScope<Page<T, M>>(requestKey);
    scopeRef.current = scope;
    void scope.run(0, fetchPageRef.current, {
      onPage: (page) => {
        setState({
          requestKey,
          items: page.items,
          total: page.total,
          meta: page.meta,
          error: null,
        });
      },
      onError: (e: unknown) => {
        if (e instanceof ApiError && e.status === 401) {
          router.replace("/login");
          return;
        }
        setState({
          requestKey,
          items: [],
          total: 0,
          meta: undefined,
          error: e instanceof Error ? e.message : String(e),
        });
      },
      onSettled: () => setLoadingMoreKey((current) => current === requestKey ? null : current),
    });
    return () => scope.cancel();
  }, [requestKey, router]);

  const loading = state.requestKey !== requestKey;
  const loadingMore = loadingMoreKey === requestKey;

  async function loadMore() {
    const scope = scopeRef.current;
    if (loading || state.items.length >= state.total || scope?.requestKey !== requestKey) return;
    const offset = state.items.length;
    await scope.run(offset, fetchPageRef.current, {
      onStart: () => setLoadingMoreKey(requestKey),
      onPage: (page) => {
        setState((s) => s.requestKey === requestKey && s.items.length === offset ? {
          requestKey,
          items: [...s.items, ...page.items],
          total: page.total,
          meta: page.meta,
          error: null,
        } : s);
      },
      onError: (e: unknown) => {
        if (e instanceof ApiError && e.status === 401) {
          router.replace("/login");
          return;
        }
        setState((s) => s.requestKey === requestKey ? {
          ...s, error: e instanceof Error ? e.message : String(e),
        } : s);
      },
      onSettled: () => setLoadingMoreKey((current) => current === requestKey ? null : current),
    });
  }

  return {
    items: state.items,
    total: state.total,
    meta: state.meta,
    error: state.error,
    loading,
    loadingMore,
    hasMore: !loading && state.items.length < state.total,
    loadMore,
    reload: () => {
      // Invalidate immediately: an old page may settle before the next effect.
      scopeRef.current?.cancel();
      setTick((t) => t + 1);
    },
  };
}
