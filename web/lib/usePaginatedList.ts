"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError } from "./api";

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
  const [loadingMore, setLoadingMore] = useState(false);

  const fetchPageRef = useRef(fetchPage);
  useEffect(() => {
    fetchPageRef.current = fetchPage;
  });

  useEffect(() => {
    let cancelled = false;
    setLoadingMore(true);
    fetchPageRef
      .current(0)
      .then((page) => {
        if (cancelled) return;
        setState({
          requestKey,
          items: page.items,
          total: page.total,
          meta: page.meta,
          error: null,
        });
      })
      .catch((e: unknown) => {
        if (cancelled) return;
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
      })
      .finally(() => {
        if (!cancelled) setLoadingMore(false);
      });
    return () => {
      cancelled = true;
    };
  }, [requestKey, router]);

  const loading = state.requestKey !== requestKey;

  async function loadMore() {
    setLoadingMore(true);
    try {
      const page = await fetchPageRef.current(state.items.length);
      setState((s) => ({
        requestKey: s.requestKey,
        items: [...s.items, ...page.items],
        total: page.total,
        meta: page.meta,
        error: null,
      }));
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        router.replace("/login");
        return;
      }
      setState((s) => ({ ...s, error: e instanceof Error ? e.message : String(e) }));
    } finally {
      setLoadingMore(false);
    }
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
    reload: () => setTick((t) => t + 1),
  };
}
