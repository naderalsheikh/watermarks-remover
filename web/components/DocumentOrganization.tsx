"use client";

import { useId, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { useApiData } from "@/lib/useApi";
import { usePaginatedList } from "@/lib/usePaginatedList";
import { useDebouncedValue } from "@/lib/useDebouncedValue";
import type { Document, Matter } from "@/lib/types";

const field = "w-full rounded-md border border-border bg-transparent px-3 py-2 text-sm";
const button = "rounded-md border border-border px-3 py-2 text-sm hover:bg-black/[0.03] disabled:opacity-50 dark:hover:bg-white/[0.03]";

export function MatterOrganization({ matter, onSaved }: { matter: Matter; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  return <section className="my-4 border-y border-border py-4" aria-label="Matter details">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="min-w-0 text-sm">
        <p className="break-words">{matter.client_name || "Client not set"}{matter.matter_number ? ` · ${matter.matter_number}` : ""}</p>
        <p className="mt-1 text-muted">{matter.status === "closed" ? "Closed" : "Active"} matter</p>
      </div>
      {matter.perms?.includes("admin") && <button className={button} onClick={() => setEditing(!editing)} aria-expanded={editing}>{editing ? "Cancel editing" : "Edit matter details"}</button>}
    </div>
    {matter.status === "closed" && <p className="mt-2 text-sm text-muted">Closed is an organization label. Access, processing, and records remain available.</p>}
    {editing && <MatterForm key={matter.organization_version} matter={matter} onSaved={() => { setEditing(false); onSaved(); }} />}
  </section>;
}

function MatterForm({ matter, onSaved }: { matter: Matter; onSaved: () => void }) {
  const id = useId();
  const [client, setClient] = useState(matter.client_name ?? "");
  const [number, setNumber] = useState(matter.matter_number ?? "");
  const [status, setStatus] = useState(matter.status ?? "active");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function save(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError("");
    try {
      await api.put(`/v1/matters/${matter.id}/organization`, { client_name: client.trim(), matter_number: number.trim(), status, expected_version: matter.organization_version ?? 0 });
      onSaved();
    } catch (e) { setError(e instanceof Error ? e.message : "Couldn't save matter details."); }
    finally { setBusy(false); }
  }
  return <form onSubmit={save} className="mt-4 space-y-3">
    <fieldset disabled={busy} className="grid gap-3 sm:grid-cols-3">
      <label className="space-y-1 text-sm" htmlFor={`${id}-client`}><span>Client name</span><input id={`${id}-client`} className={field} value={client} onChange={e => setClient(e.target.value)} maxLength={200} /></label>
      <label className="space-y-1 text-sm" htmlFor={`${id}-number`}><span>Matter number</span><input id={`${id}-number`} className={field} value={number} onChange={e => setNumber(e.target.value)} maxLength={80} /></label>
      <label className="space-y-1 text-sm" htmlFor={`${id}-status`}><span>Status</span><select id={`${id}-status`} className={field} value={status} onChange={e => setStatus(e.target.value as "active" | "closed")}><option value="active">Active</option><option value="closed">Closed</option></select></label>
    </fieldset>
    <p className="text-xs text-muted">Details help organize this matter. Closing it does not revoke access or stop jobs. Reopen it by choosing Active.</p>
    {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
    <button className={button} disabled={busy}>{busy ? "Saving…" : "Save matter details"}</button>
  </form>;
}

export function DocumentOrganization({ doc, canEdit, onSaved }: { doc: Document; canEdit: boolean; onSaved: () => void }) {
  const [open, setOpen] = useState(false);
  return <div className="mt-3">
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
      <span className="text-muted">{doc.category || "Uncategorized"}{doc.previous_revision_id ? " · Earlier revision linked" : ""}</span>
      <button className="rounded py-1 text-foreground underline underline-offset-4" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? "Hide document details" : "Category and revisions"}</button>
    </div>
    {open && <DocumentDetails key={`${doc.id}:${doc.organization_version}`} doc={doc} canEdit={canEdit} onSaved={onSaved} />}
  </div>;
}

function DocumentDetails({ doc, canEdit, onSaved }: { doc: Document; canEdit: boolean; onSaved: () => void }) {
  const [offset, setOffset] = useState(0);
  const revisions = useApiData(() => api.get<{ previous: Document | null; next: Document[]; total: number }>(`/v1/matters/${doc.matter_id}/documents/${doc.id}/revisions?offset=${offset}&limit=10`), `revisions:${doc.id}:${offset}`);
  const [editing, setEditing] = useState(false);
  function revisionLink(d: Document) { return <Link className="break-all underline underline-offset-4" href={`/matters/view?id=${d.matter_id}&doc=${d.id}`}>{d.filename} <span className="text-muted">({d.id.slice(0, 6)})</span></Link>; }
  return <div className="mt-2 space-y-3 border-t border-border pt-3 text-sm">
    <p className="text-xs text-muted">Revision links are recorded by an administrator. Each upload keeps its own original, findings, and releases.</p>
    {revisions.loading ? <p role="status">Loading revision links…</p> : revisions.error ? <p role="alert" className="text-red-600">{revisions.error}</p> : <>
      <p>Earlier revision: {revisions.data?.previous ? revisionLink(revisions.data.previous) : "None linked"}</p>
      <div><p className="mb-1">Later linked uploads ({revisions.data?.total ?? 0})</p>
        <ul className="space-y-1">{revisions.data?.next.map(d => <li key={d.id}>{revisionLink(d)}</li>)}</ul>
        {(offset > 0 || (revisions.data?.total ?? 0) > 10) && <div className="mt-2 flex gap-2"><button className={button} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 10))}>Previous links</button><button className={button} disabled={offset + 10 >= (revisions.data?.total ?? 0)} onClick={() => setOffset(offset + 10)}>Next links</button></div>}
      </div>
    </>}
    {canEdit && <button className={button} onClick={() => setEditing(!editing)} aria-expanded={editing}>{editing ? "Cancel editing" : "Edit category or revision link"}</button>}
    {editing && <DocumentForm doc={doc} onSaved={onSaved} />}
  </div>;
}

function DocumentForm({ doc, onSaved }: { doc: Document; onSaved: () => void }) {
  const id = useId();
  const [category, setCategory] = useState(doc.category ?? "");
  const [previous, setPrevious] = useState<string | null>(doc.previous_revision_id ?? null);
  const [search, setSearch] = useState("");
  const query = useDebouncedValue(search.trim(), 250);
  const candidates = usePaginatedList<Document>(offset => api.get<{ documents: Document[]; total: number }>(`/v1/matters/${doc.matter_id}/documents?q=${encodeURIComponent(query)}&offset=${offset}&limit=20`).then(r => ({ items: r.documents, total: r.total })), `revision-picker:${doc.id}:${query}`);
  const categories = useApiData(() => api.get<{ categories: string[] }>(`/v1/matters/${doc.matter_id}/document-categories`), `category-options:${doc.matter_id}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function save(e: React.FormEvent) {
    e.preventDefault(); setBusy(true); setError("");
    try {
      await api.put(`/v1/matters/${doc.matter_id}/documents/${doc.id}/organization`, { category: category.trim(), previous_revision_id: previous, expected_version: doc.organization_version ?? 0 });
      onSaved();
    } catch (e) { setError(e instanceof Error ? e.message : "Couldn't save document details."); }
    finally { setBusy(false); }
  }
  return <form onSubmit={save} className="space-y-3">
    <fieldset disabled={busy} className="space-y-3">
      <label className="block space-y-1" htmlFor={`${id}-category`}><span>Category</span><input id={`${id}-category`} className={field} list={`${id}-categories`} maxLength={80} value={category} onChange={e => setCategory(e.target.value)} placeholder="For example, Agreements" /></label>
      <datalist id={`${id}-categories`}>{categories.data?.categories.filter(Boolean).map(c => <option key={c} value={c} />)}</datalist>
      <fieldset className="space-y-2">
        <legend className="mb-2">Earlier revision</legend>
        <p className="text-xs text-muted">Selected: {previous ? (candidates.items.find(d => d.id === previous)?.filename ?? `Document ${previous}`) : "No earlier revision"}</p>
        <label className="flex items-center gap-2"><input type="radio" name={`${id}-revision`} checked={previous === null} onChange={() => setPrevious(null)} />No earlier revision</label>
        <label className="block space-y-1" htmlFor={`${id}-search`}><span>Find an earlier upload in this matter</span><input id={`${id}-search`} className={field} value={search} onChange={e => setSearch(e.target.value)} type="search" /></label>
        {candidates.loading || search.trim() !== query ? <p role="status">Finding documents…</p> : <ul className="max-h-52 space-y-2 overflow-y-auto">{candidates.items.filter(d => d.id !== doc.id).map(d => <li key={d.id}><label className="flex items-start gap-2"><input className="mt-1" type="radio" name={`${id}-revision`} checked={previous === d.id} onChange={() => setPrevious(d.id)} /><span className="break-all">{d.filename}<span className="block text-xs text-muted">{new Date(d.created_utc).toLocaleString()} · {d.id.slice(0, 6)}</span></span></label></li>)}</ul>}
        {!candidates.loading && !candidates.error && candidates.items.filter(d => d.id !== doc.id).length === 0 && <p className="text-muted">No other uploads found{candidates.hasMore ? " on this page" : ""}.</p>}
        {candidates.error && <p role="alert" className="text-red-600">{candidates.error}</p>}
        {candidates.hasMore && <button type="button" className={button} disabled={candidates.loadingMore} onClick={candidates.loadMore}>{candidates.loadingMore ? "Loading…" : "Load more documents"}</button>}
      </fieldset>
    </fieldset>
    {error && <p role="alert" className="text-red-600">{error}</p>}
    <button className={button} disabled={busy}>{busy ? "Saving…" : "Save document details"}</button>
  </form>;
}
