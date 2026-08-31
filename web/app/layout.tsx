import type { Metadata } from "next";
import { Newsreader } from "next/font/google";
import "./globals.css";

// Serif for the wordmark and page headings only -- body copy stays the
// system sans stack. Self-hosted by next/font, so no external font request.
const displaySerif = Newsreader({
  subsets: ["latin"],
  weight: ["500", "600"],
  style: ["normal", "italic"],
  variable: "--font-display-serif",
});

export const metadata: Metadata = {
  title: "CounselClear",
  // PR 44: was "Legal-document sanitization with chain of custody" --
  // scrubber-first framing left over from before the Release Gate
  // repositioning (PR 39-43). Conservative rewrite, not a rebrand: still
  // describes exactly what the product does, just leads with the
  // release/custody framing every other surface now uses.
  description: "Policy-governed document release with custody records",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`h-full antialiased ${displaySerif.variable}`}>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
