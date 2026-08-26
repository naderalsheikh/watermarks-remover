"use client";

import { useEffect, useState } from "react";

/** Delays reflecting `value` by `delayMs` — for a search box wired to a
 * server query, so every keystroke doesn't fire its own request. Returns
 * the immediately-updated `value` unchanged; only the debounced echo is
 * delayed, so callers can still show what the user typed instantly while
 * using the debounced value to decide when to actually query. */
export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}
