"use client";

import { Suspense, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { useApiData } from "@/lib/useApi";
import type { AclGrant, AuthConfig, Matter } from "@/lib/types";
import { KNOWN_PERMS } from "@/lib/types";
import { Header } from "@/components/Header";

function permLabel(perm: string): string {
  return perm.replace(/_/g, " ");
}

// Discoverability for the grant-by-principal-ID form below: without this,
// an OIDC reviewer has no way to learn their own "oidc:<hash>" string to
// hand an admin, and grant-by-principal-ID is unusable in practice even
// though the backend endpoint works. GET /v1/auth/me is the same value
// already visible in every audit event's actor_id — not new exposure.
function YourPrincipal({ oidc, principal }: { oidc: boolean; principal: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mb-6 rounded-md border border-border p-3 text-sm shadow-card">
      <p className="text-xs font-medium uppercase tracking-wide text-muted">Your principal ID</p>
      <div className="mt-1 flex items-center gap-2">
        <code className="break-all font-mono text-sm">{principal}</code>
        <button
          onClick={() => {
            navigator.clipboard.writeText(principal).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            });
          }}
          className="rounded border border-border px-1.5 py-0.5 text-xs hover:bg-black/[0.03] dark:hover:bg-white/[0.03]"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className="mt-1 text-xs text-muted">
        {oidc
          ? "Share this exact ID with a matter admin so they can grant you access — it identifies you specifically."
          : "This is the shared local identity, not a per-person ID — everyone using this deployment's password shows the same value."}
      </p>
    </div>
  );
}

// download_original and admin are the two perms bootstrap_operator does
// NOT auto-grant on matter creation (see service/app/models.py) — worth
// calling out visually since their absence from a grant is deliberate,
// not an oversight.
function GrantRow({
  grant,
  canRevoke,
  onRevoke,
}: {
  grant: AclGrant;
  canRevoke: boolean;
  onRevoke: (perm: string) => void;
}) {
  return (
    <li className="flex items-start justify-between gap-4 px-4 py-3">
      <div className="min-w-0">
        <p className="truncate font-mono text-sm">{grant.user_id}</p>
        <div className="mt-1 flex flex-wrap gap-1.5">
          {grant.perms.map((p) => (
            <span
              key={p}
              className="inline-flex items-center gap-1 rounded bg-black/[0.05] px-1.5 py-0.5 text-xs capitalize dark:bg-white/[0.08]"
            >
              {permLabel(p)}
              {canRevoke && (
                <button
                  onClick={() => onRevoke(p)}
                  title={`Revoke ${p}`}
                  className="text-muted hover:text-red-600"
                >
                  ×
                </button>
              )}
            </span>
          ))}
        </div>
      </div>
    </li>
  );
}

function GrantForm({ onGrant }: { onGrant: (userId: string, perm: string) => Promise<void> }) {
  const [userId, setUserId] = useState("");
  const [perm, setPerm] = useState<string>("read");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!userId.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await onGrant(userId.trim(), perm);
      setUserId("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Grant failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit} className="mt-4 space-y-2 rounded-md border border-border p-3">
      <div>
        <label className="mb-1 block text-xs font-medium">Principal ID</label>
        <input
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="oidc:a1b2c3…"
          className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 font-mono text-sm focus-visible:border-accent"
        />
        <p className="mt-1 text-xs text-muted">
          CounselClear does not yet resolve a reviewer&apos;s email to their login principal ID.
          Ask them to open this page themselves and copy the &quot;Your principal ID&quot; value
          above.
        </p>
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium">Permission</label>
        <select
          value={perm}
          onChange={(e) => setPerm(e.target.value)}
          className="w-full rounded-md border border-border bg-transparent px-2 py-1.5 text-sm capitalize focus-visible:border-accent"
        >
          {KNOWN_PERMS.map((p) => (
            <option key={p} value={p}>
              {permLabel(p)}
            </option>
          ))}
        </select>
      </div>
      {error && <p className="text-xs text-red-600">{error}</p>}
      <button
        type="submit"
        disabled={submitting || !userId.trim()}
        className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 disabled:opacity-50"
      >
        {submitting ? "Granting…" : "Grant"}
      </button>
    </form>
  );
}

function AccessView({ matterId }: { matterId: string }) {
  const matterQ = useApiData<Matter>(
    () => api.get(`/v1/matters/${matterId}`),
    `matter:${matterId}`,
  );
  const authQ = useApiData<AuthConfig>(() => api.get("/v1/auth/config"), "auth-config");
  const meQ = useApiData<{ principal: string }>(() => api.get("/v1/auth/me"), "auth-me");
  const aclQ = useApiData<{ grants: AclGrant[] }>(
    () => api.get(`/v1/matters/${matterId}/acl`),
    `acl:${matterId}`,
  );
  const [revokeError, setRevokeError] = useState<string | null>(null);

  const oidc = authQ.data?.oidc_enabled ?? false;

  async function grant(userId: string, perm: string) {
    await api.put(`/v1/matters/${matterId}/acl`, { user_id: userId, perm });
    aclQ.reload();
  }

  async function revoke(userId: string, perm: string) {
    setRevokeError(null);
    // Self-revoking admin/read is a real self-lockout risk (losing
    // control over, or visibility into, this matter) -- the backend
    // refuses it without an explicit confirm_self_revoke flag
    // (service/app/main.py's delete_acl), so this dialog is what actually
    // produces that flag, not just UI decoration on top of a backend that
    // would allow it either way.
    const isSelf = meQ.data?.principal === userId;
    let confirmSelfRevoke = false;
    if (isSelf && (perm === "admin" || perm === "read")) {
      const ok = window.confirm(
        `Revoke your own ${perm} access to this matter? ` +
          (perm === "admin"
            ? "You may lose the ability to manage access here — another admin would need to grant it back."
            : "You may lose visibility into this matter.") +
          " This cannot be undone from this page.",
      );
      if (!ok) return;
      confirmSelfRevoke = true;
    }
    try {
      await api.del(`/v1/matters/${matterId}/acl`, {
        user_id: userId,
        perm,
        confirm_self_revoke: confirmSelfRevoke,
      });
      aclQ.reload();
    } catch (err) {
      setRevokeError(err instanceof Error ? err.message : "Revoke failed");
    }
  }

  return (
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
      <Link href={`/matters/view?id=${matterId}`} className="text-sm text-muted hover:text-foreground">
        ← Back to matter
      </Link>
      <h1 className="font-serif mb-1 mt-2 text-2xl font-semibold tracking-tight">Access</h1>
      <p className="mb-6 text-sm text-muted">
        {matterQ.data?.name ?? (matterQ.loading ? "Loading…" : "Matter")}
      </p>
      {matterQ.error && <p className="mb-6 text-sm text-red-600">{matterQ.error}</p>}

      {!authQ.loading && !oidc && (
        <div className="mb-6 rounded-md border border-amber-600/40 bg-amber-600/10 px-4 py-3 text-sm text-amber-800 dark:text-amber-300">
          <p className="font-medium">Local-password mode: collaboration is limited.</p>
          <p className="mt-1">
            Every action taken through the shared local password is attributed to the single{" "}
            <code className="font-mono">operator</code> identity — there is no way to
            distinguish reviewers from each other in the custody chain. Per-reviewer access
            grants and audit attribution require OIDC SSO. This page is read-only in local
            mode: granting or revoking access to a name typed here would not correspond to a
            real, distinguishable login.
          </p>
        </div>
      )}
      {!authQ.loading && oidc && (
        <p className="mb-6 text-sm text-muted">
          OIDC SSO is active — each grant below is scoped to one real, distinguishable
          reviewer principal, and every change here is recorded in the{" "}
          <Link href={`/matters/audit?id=${matterId}`} className="underline hover:text-foreground">
            audit log
          </Link>
          .
        </p>
      )}

      {!authQ.loading && meQ.data && <YourPrincipal oidc={oidc} principal={meQ.data.principal} />}

      {aclQ.loading && (
        <div className="animate-pulse space-y-2">
          <div className="h-14 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
          <div className="h-14 rounded-md bg-black/[0.04] dark:bg-white/[0.04]" />
        </div>
      )}
      {aclQ.error && <p className="text-sm text-red-600">{aclQ.error}</p>}
      {revokeError && (
        <p className="mb-3 rounded-md border border-red-600/30 bg-red-600/5 px-3 py-2 text-sm text-red-600">
          {revokeError}
        </p>
      )}

      {aclQ.data && (
        <>
          <ul className="divide-y divide-border rounded-md border border-border shadow-card">
            {aclQ.data.grants.map((g) => (
              <GrantRow
                key={g.user_id}
                grant={g}
                canRevoke={oidc}
                onRevoke={(perm) => revoke(g.user_id, perm)}
              />
            ))}
          </ul>

          {oidc && <GrantForm onGrant={grant} />}
        </>
      )}
    </main>
  );
}

function AccessInner() {
  const id = useSearchParams().get("id");
  if (!id) {
    return <main className="mx-auto max-w-5xl flex-1 px-6 py-8 text-sm text-red-600">Missing matter id.</main>;
  }
  return <AccessView matterId={id} />;
}

export default function AccessPage() {
  return (
    <>
      <Header />
      <Suspense fallback={<div className="flex-1 px-6 py-8"><div className="h-8 w-40 animate-pulse rounded-md bg-black/[0.06] dark:bg-white/[0.06]" /></div>}>
        <AccessInner />
      </Suspense>
    </>
  );
}
