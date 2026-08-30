"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

// Root redirects to /dashboard — the same page a successful login lands on
// (app/login/page.tsx), so both entry paths share one landing surface.
export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/dashboard");
  }, [router]);
  return null;
}
