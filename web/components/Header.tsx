"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState } from "react";
import { api } from "@/lib/api";

export function Header() {
  const router = useRouter();
  const pathname = usePathname();
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
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-y-2 px-6 py-4">
        <div className="flex flex-wrap items-center gap-6">
          <Link href="/dashboard" className="font-serif text-lg font-medium tracking-tight">
            Counsel<em className="italic">Clear</em>
          </Link>
          <nav aria-label="Main navigation" className="flex items-center gap-4 text-sm text-muted">
            <Link
              href="/dashboard"
              aria-current={pathname === "/dashboard" ? "page" : undefined}
              className={`hover:text-foreground ${pathname === "/dashboard" ? "font-medium text-foreground" : ""}`}
            >
              Overview
            </Link>
            <Link
              href="/matters"
              aria-current={pathname.startsWith("/matters") ? "page" : undefined}
              className={`hover:text-foreground ${pathname.startsWith("/matters") ? "font-medium text-foreground" : ""}`}
            >
              Matters
            </Link>
            <Link
              href="/verify"
              aria-current={pathname === "/verify" ? "page" : undefined}
              className={`hover:text-foreground ${pathname === "/verify" ? "font-medium text-foreground" : ""}`}
            >
              Verify Packet
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
