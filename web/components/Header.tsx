"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";

export function Header() {
  const router = useRouter();
  const [loggingOut, setLoggingOut] = useState(false);

  async function logout() {
    setLoggingOut(true);
    try {
      await api.post("/v1/auth/logout");
    } finally {
      router.replace("/login");
    }
  }

  return (
    <header className="border-b border-border">
      <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
        <div className="flex items-center gap-6">
          <Link href="/dashboard" className="font-serif text-lg font-medium tracking-tight">
            Counsel<em className="italic">Clear</em>
          </Link>
          <nav className="flex items-center gap-4 text-sm text-muted">
            <Link href="/dashboard" className="hover:text-foreground">
              Overview
            </Link>
            <Link href="/matters" className="hover:text-foreground">
              Matters
            </Link>
          </nav>
        </div>
        <button
          onClick={logout}
          disabled={loggingOut}
          className="text-sm text-muted hover:text-foreground disabled:opacity-50"
        >
          {loggingOut ? "Signing out…" : "Sign out"}
        </button>
      </div>
    </header>
  );
}
