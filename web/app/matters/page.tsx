"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import { useApiData } from "@/lib/useApi";
import { usePaginatedList } from "@/lib/usePaginatedList";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import type { AuthConfig, Matter } from "@/lib/types";
import { Header } from "@/components/Header";

const PAGE_SIZE = 50;

export default function MattersPage() {
  const router = useRouter();
  const [status, setStatus] = useState("");
  const [client, setClient] = useState("");
  const [number, setNumber] = useState("");
  const [details, setDetails] = useState(false);
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebouncedValue(search.trim(), 300);
  // PR 45: gates the "Load sample matter" button on the same bit the
  // backend route itself enforces (local-password mode only) -- fetched
  // fresh here rather than assumed, so the button simply doesn't render
  // on an OIDC deployment instead of rendering and then 403ing.
  const authConfigQ = useApiData(() => api.get<AuthConfig>("/v1/auth/config"), "auth-config");
  const [seeding, setSeeding] = useState(false);
  const [seedError, setSeedError] = useState<string | null>(null);

  async function loadSampleMatter() {
    setSeeding(true);
    setSeedError(null);
    try {
      const matter = await api.post<Matter>("/v1/matters/demo-seed");
      router.push(`/matters/view?id=${matter.id}`);
    } catch (err) {
      setSeedError(err instanceof Error ? err.message : "Couldn't load the sample matter");
      setSeeding(false);
    }
  }

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
          `/v1/matters?limit=${PAGE_SIZE}&offset=${offset}&q=${encodeURIComponent(debouncedSearch)}&status=${status}`,
        )
        .then((r) => ({ items: r.matters, total: r.total })),
    // The key includes the debounced search text: changing it resets
    // pagination to page 1 of the new server-side result, same as a
    // matter-id change does elsewhere. The search itself runs on the
    // server (GET /v1/matters?q=...) across every matter this principal
    // can read, not just what's already loaded.
    `matters:${debouncedSearch}:${status}`,
  );
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  async function createMatter(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    setCreateError(null);
    try {
      await api.post("/v1/matters", { name: name.trim(), client_name: client.trim(), matter_number: number.trim() });
      setName("");
      setClient("");
      setNumber("");
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
            <h1 className="font-serif text-2xl font-semibold tracking-tight">Matters</h1>
            <p className="mt-1 text-sm text-muted">
              Each matter is an isolated review workspace with its own custody chain.
            </p>
          </div>
        </div>

        <form onSubmit={createMatter} className="mb-6 space-y-3">
          <div className="flex flex-wrap gap-2">
          <input
            maxLength={200}
            disabled={creating}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="New matter name"
            aria-label="New matter name"
            className="min-w-0 flex-1 rounded-md border border-border bg-transparent px-3 py-2 text-sm focus-visible:border-accent"
          />
          <button
            type="submit"
            disabled={creating || !name.trim()}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
          >
            {creating ? "Creating…" : "New matter"}
          </button>
          </div>
          <button type="button" className="text-sm underline underline-offset-4" aria-expanded={details} onClick={() => setDetails(!details)}>Client and matter number (optional)</button>
          {details && <fieldset disabled={creating} className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-sm" htmlFor="new-client"><span>Client name</span><input id="new-client" className="w-full rounded-md border border-border bg-transparent px-3 py-2" maxLength={200} value={client} onChange={e => setClient(e.target.value)} /></label>
            <label className="space-y-1 text-sm" htmlFor="new-number"><span>Matter number</span><input id="new-number" className="w-full rounded-md border border-border bg-transparent px-3 py-2" maxLength={80} value={number} onChange={e => setNumber(e.target.value)} /></label>
          </fieldset>}
        </form>
        {createError && (
          <p className="mb-6 rounded-md border border-red-600/30 bg-red-600/5 px-3 py-2 text-sm text-red-600">
            {createError}
          </p>
        )}

        {/* PR 45: a secondary, visually subordinate alternative to typing a
            name and finding your own test file -- local-password/dev mode
            only (auth_config's demo_seed_enabled), since a multi-tenant
            OIDC deployment has no single "the operator" to seed a shared
            sample matter for, and the backend route itself refuses there. */}
        {authConfigQ.data?.demo_seed_enabled && (
          <div className="mb-6 flex items-center gap-2 text-sm">
            <span className="text-muted">New here?</span>
            <button
              type="button"
              onClick={loadSampleMatter}
              disabled={seeding}
              className="rounded-md border border-border px-3 py-1.5 font-medium hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]"
            >
              {seeding ? "Loading sample matter…" : "Load sample matter"}
            </button>
            <span className="text-xs text-muted">
              Seeds a clearly-labeled demo matter with three sample documents already released —
              a released packet, a refused release, and a release with a kept finding.
            </span>
          </div>
        )}
        {seedError && (
          <p className="mb-6 rounded-md border border-red-600/30 bg-red-600/5 px-3 py-2 text-sm text-red-600">
            {seedError}
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
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search name, client, or matter number…"
          aria-label="Search matters by name, client, or matter number"
          className="mb-1 w-full rounded-md border border-border bg-transparent px-3 py-1.5 text-sm focus-visible:border-accent"
        />
        <p className="mb-3 text-xs text-muted">
          Searches every matter you can read on the server — not just what&apos;s loaded below.
        </p>

        <label className="mb-5 flex items-center gap-3 text-sm" htmlFor="matter-status-filter">Matter status
          <select id="matter-status-filter" className="rounded-md border border-border bg-transparent px-3 py-2" value={status} onChange={e => setStatus(e.target.value)}>
            <option value="">All matters</option><option value="active">Active</option><option value="closed">Closed</option>
          </select>
        </label>
        {!loading && matters.length === 0 && (
          <div className="rounded-md border border-dashed border-border px-4 py-8 text-center text-sm text-muted">
            {debouncedSearch
              ? `No matters match "${debouncedSearch}".`
              : status ? `No ${status} matters.` : "No matters yet — create one above to get started."}
          </div>
        )}

        {!loading && matters.length > 0 && (
          <>
            {total > matters.length && (
              <p className="mb-2 text-xs text-muted">
                Loaded {matters.length} of {total}
                {debouncedSearch ? " matching" : ""} matters.
              </p>
            )}
            <ul className="divide-y divide-border rounded-md border border-border shadow-card">
              {matters.map((m) => (
                <li key={m.id}>
                  <Link
                    href={`/matters/view?id=${m.id}`}
                    className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block break-words font-medium">{m.name}</span>
                      {(m.client_name || m.matter_number) && <span className="mt-1 block break-words text-sm text-muted">{[m.client_name, m.matter_number].filter(Boolean).join(" · ")}</span>}
                      {m.status === "closed" && <span className="mt-1 block text-xs text-muted">Closed</span>}
                      {m.is_demo && (
                        <span className="rounded border border-border px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted">
                          Demo
                        </span>
                      )}
                    </span>
                    <span className="text-xs text-muted">
                      {new Date(m.created_utc).toLocaleDateString()}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
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
