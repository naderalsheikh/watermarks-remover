"use client";

import { useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { useApiData } from "@/lib/useApi";
import type { Matter } from "@/lib/types";
import { Header } from "@/components/Header";

export default function MattersPage() {
  const { data, error, loading, reload } = useApiData(
    () => api.get<{ matters: Matter[] }>("/v1/matters"),
    "matters",
  );
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);

  async function createMatter(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    try {
      await api.post("/v1/matters", { name: name.trim() });
      setName("");
      reload();
    } finally {
      setCreating(false);
    }
  }

  return (
    <>
      <Header />
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
        <div className="mb-8 flex items-end justify-between gap-4">
          <h1 className="text-2xl font-semibold tracking-tight">Matters</h1>
        </div>

        <form onSubmit={createMatter} className="mb-8 flex gap-2">
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

        {loading && <p className="text-sm text-muted">Loading…</p>}
        {error && <p className="text-sm text-red-600">{error}</p>}
        {data && data.matters.length === 0 && (
          <p className="text-sm text-muted">No matters yet. Create one above.</p>
        )}

        <ul className="divide-y divide-border rounded-md border border-border">
          {data?.matters.map((m) => (
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
      </main>
    </>
  );
}
