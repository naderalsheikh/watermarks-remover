"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ApiError } from "./api";

type Result<T> = { requestKey: string; data: T | null; error: string | null };

/** Fetch + loading/error state for one client page, with a shared rule: a
 * 401 from any protected endpoint means the session is gone (static export
 * has no server to check the cookie before render), so every page bounces
 * to /login the same way instead of each one reimplementing it.
 *
 * `key` identifies what's being fetched (e.g. a matter id) — the effect
 * re-runs when it changes, and `reload()` forces a re-run without a key
 * change. `loading` is derived (whether the latest result matches the
 * current request), not stored: the fetch effect makes exactly one
 * setState call, and only from inside the async `.then`/`.catch`
 * callbacks — never synchronously in the effect body — per this Next
 * version's stricter react-hooks/set-state-in-effect rule. `fetcher` is
 * read through a ref, updated in its own effect (never mutated during
 * render, per react-hooks/refs) so a fresh closure each render doesn't
 * need to be an effect dependency. */
export function useApiData<T>(fetcher: () => Promise<T>, key: string) {
  const router = useRouter();
  const [tick, setTick] = useState(0);
  const requestKey = `${key}:${tick}`;
  const [result, setResult] = useState<Result<T>>({
    requestKey: "",
    data: null,
    error: null,
  });

  const fetcherRef = useRef(fetcher);
  useEffect(() => {
    fetcherRef.current = fetcher;
  });

  useEffect(() => {
    let cancelled = false;
    fetcherRef
      .current()
      .then((d) => {
        if (!cancelled) setResult({ requestKey, data: d, error: null });
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        if (e instanceof ApiError && e.status === 401) {
          router.replace("/login");
          return;
        }
        setResult({
          requestKey,
          data: null,
          error: e instanceof Error ? e.message : String(e),
        });
      });
    return () => {
      cancelled = true;
    };
  }, [requestKey, router]);

  return {
    data: result.data,
    error: result.error,
    loading: result.requestKey !== requestKey,
    reload: () => setTick((t) => t + 1),
  };
}
