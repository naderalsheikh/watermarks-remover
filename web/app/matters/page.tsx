"use client";

import { useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { usePaginatedList } from "@/lib/usePaginatedList";
import type { Matter } from "@/lib/types";
import { Header } from "@/components/Header";

const PAGE_SIZE = 50;

export default function MattersPage() {
  const {
    items: matters,
    total,
    error,
    loading,
    loadingMore,
    hasMore,
    loadMore,
    reload,
  } = usePaginatedList(
    (offset) =>
      api
        .get<{ matters: Matter[]; total: number }>(
          `/v1/matters?limit=${PAGE_SIZE}&offset=${offset}`,
        )
        .then((r) => ({ items: r.matters, total: r.total })),
    "matters",
  );
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  // Filters only the matters loaded so far (accumulated via "Load more")
  // — not a server-side search across every matter. The load-more control
  // below still applies on top of this, so the two don't silently combine
  // into a claim of completeness neither one makes on its own.
  const filtered = matters.filter((m) =>
    m.name.toLowerCase().includes(search.trim().toLowerCase()),
  );

  async function createMatter(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    setCreateError(null);
    try {
      await api.post("/v1/matters", { name: name.trim() });
      setName("");
      reload();
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : "Couldn't create the matter");
    } finally {
      setCreating(false);
    }
  }

  return (
    <>
      <Header />
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
        <div className="mb-8 flex items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Matters</h1>
            <p className="mt-1 text-sm text-muted">
              Each matter is an isolated review workspace with its own custody chain.
            </p>
          </div>
        </div>

        <form onSubmit={createMatter} className="mb-6 flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="New matter name"
            className="flex-1 rounded-md border border-border bg-transparent px-3 py-2 text-sm outline-none focus:border-accent"
          />
          <button
            type="submit"
            disabled={creating || !name.trim()}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            {creating ? "Creating…" : "New matter"}
          </button>
        </form>
        {createError && (
          <p className="mb-6 rounded-md border border-red-600/30 bg-red-600/5 px-3 py-2 text-sm text-red-600">
            {createError}
          </p>
        )}

        {loading && (
          <div className="animate-pulse space-y-2">
            <div className="h-12 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
            <div className="h-12 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
          </div>
        )}
        {error && (
          <p className="rounded-md border border-red-600/30 bg-red-600/5 px-3 py-2 text-sm text-red-600">
            {error}
          </p>
        )}
        {!loading && matters.length === 0 && (
          <div className="rounded-md border border-dashed border-border px-4 py-8 text-center text-sm text-muted">
            No matters yet — create one above to get started.
          </div>
        )}

        {!loading && matters.length > 0 && (
          <>
            {total > matters.length && (
              <p className="mb-2 text-xs text-muted">
                Loaded {matters.length} of {total} matters — search below only covers
                what&apos;s loaded.
              </p>
            )}
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search matters by name…"
              className="mb-3 w-full rounded-md border border-border bg-transparent px-3 py-1.5 text-sm outline-none focus:border-accent"
            />
            {filtered.length === 0 ? (
              <p className="text-sm text-muted">No matters match &quot;{search}&quot;.</p>
            ) : (
              <>
                {search.trim() && filtered.length < matters.length && (
                  <p className="mb-2 text-xs text-muted">
                    {filtered.length} of {matters.length} loaded matters match.
                  </p>
                )}
                <ul className="divide-y divide-border rounded-md border border-border">
                  {filtered.map((m) => (
                    <li key={m.id}>
                      <Link
                        href={`/matters/view?id=${m.id}`}
                        className="flex items-center justify-between px-4 py-3 hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                      >
                        <span className="font-medium">{m.name}</span>
                        <span className="text-xs text-muted">
                          {new Date(m.created_utc).toLocaleDateString()}
                        </span>
                      </Link>
                    </li>
                  ))}
                </ul>
              </>
            )}
            {hasMore && (
              <button
                type="button"
                onClick={loadMore}
                disabled={loadingMore}
                className="mt-3 w-full rounded-md border border-border px-3 py-2 text-sm font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
              >
                {loadingMore ? "Loading…" : `Load more (${matters.length} of ${total})`}
              </button>
            )}
          </>
        )}
      </main>
    </>
  );
}
