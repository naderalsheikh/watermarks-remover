"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { AuthConfig } from "@/lib/types";

export default function LoginPage() {
  const router = useRouter();
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    api
      .get<AuthConfig>("/v1/auth/config")
      .then(setConfig)
      .catch(() => setConfig({ oidc_enabled: false }));
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await api.post("/v1/auth/login", { password });
      router.replace("/matters");
    } catch (e) {
      if (e instanceof ApiError && e.status === 429) {
        setError("Too many failed attempts. Try again shortly.");
      } else if (e instanceof ApiError && e.status === 403) {
        setError("Invalid password.");
      } else {
        setError(e instanceof Error ? e.message : "Sign-in failed.");
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="flex flex-1 items-center justify-center px-6">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <h1 className="text-xl font-semibold tracking-tight">CounselClear</h1>
          {/* PR 44: was "Legal-document sanitization & custody" -- same
              conservative rewrite as layout.tsx's metadata description,
              matching the Release Gate framing every surface past this
              login screen already uses. */}
          <p className="mt-1 text-sm text-muted">Policy-governed document release with custody records</p>
        </div>

        {config === null ? (
          <p className="text-center text-sm text-muted">Loading…</p>
        ) : config.oidc_enabled ? (
          <a
            href="/v1/auth/oidc/login"
            className="block w-full rounded-md bg-accent px-4 py-2 text-center text-sm font-medium text-white hover:opacity-90"
          >
            Sign in with SSO
          </a>
        ) : (
          <form onSubmit={submit} className="space-y-4">
            <div>
              <label htmlFor="password" className="mb-1 block text-sm font-medium">
                Password
              </label>
              <input
                id="password"
                type="password"
                autoFocus
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-md border border-border bg-transparent px-3 py-2 text-sm outline-none focus:border-accent"
              />
            </div>
            {error && <p className="text-sm text-red-600">{error}</p>}
            <button
              type="submit"
              disabled={submitting || !password}
              className="w-full rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50"
            >
              {submitting ? "Signing in…" : "Sign in"}
            </button>
          </form>
        )}
      </div>
    </main>
  );
}
