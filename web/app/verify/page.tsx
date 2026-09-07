"use client";

import { useState } from "react";
import Link from "next/link";
import { Header } from "@/components/Header";
import {
  verifyReleasePacket,
  type VerificationReport,
} from "@/lib/packetVerifier";

function formatBytes(n?: number): string {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

export default function VerifyPage() {
  const [packetText, setPacketText] = useState("");
  const [packetFileName, setPacketFileName] = useState<string | null>(null);
  const [derivativeFile, setDerivativeFile] = useState<{
    name: string;
    data: ArrayBuffer;
  } | null>(null);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  function copyHash(hash: string) {
    navigator.clipboard.writeText(hash).then(() => {
      setCopiedHash(hash);
      setTimeout(() => setCopiedHash(null), 1200);
    });
  }

  async function runVerification(
    text: string,
    deriv = derivativeFile,
  ) {
    if (!text.trim()) {
      setReport(null);
      return;
    }
    setVerifying(true);
    try {
      const rep = await verifyReleasePacket(text, {
        derivative: deriv ?? undefined,
      });
      setReport(rep);
    } finally {
      setVerifying(false);
    }
  }

  function handlePacketUpload(file: File) {
    setPacketFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = String(e.target?.result ?? "");
      setPacketText(text);
      runVerification(text, derivativeFile);
    };
    reader.readAsText(file);
  }

  function handleDerivativeUpload(file: File) {
    const reader = new FileReader();
    reader.onload = (e) => {
      const buffer = e.target?.result as ArrayBuffer;
      const deriv = { name: file.name, data: buffer };
      setDerivativeFile(deriv);
      if (packetText.trim()) {
        runVerification(packetText, deriv);
      }
    };
    reader.readAsArrayBuffer(file);
  }

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <Header />

      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
        <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="font-serif text-2xl font-medium tracking-tight">
              Release Packet Verifier
            </h1>
            <p className="text-xs text-muted mt-1">
              Client-side evidentiary verification (WebCrypto) · No bytes are sent to any server.
            </p>
          </div>
          <Link
            href="/matters"
            className="text-xs text-muted hover:text-foreground"
          >
            ← Back to Matters
          </Link>
        </div>

        {/* Input area */}
        <div className="mb-8 grid grid-cols-1 gap-6 md:grid-cols-2">
          {/* Packet upload */}
          <div className="rounded-md border border-border p-4 shadow-card">
            <h2 className="text-sm font-semibold tracking-tight mb-2">
              1. Release Packet JSON <span className="text-red-600 dark:text-red-400">*</span>
            </h2>
            <p className="text-xs text-muted mb-3">
              Upload <code className="font-mono">release_packet.json</code> or{" "}
              <code className="font-mono">release_result.json</code>.
            </p>
            <div className="flex flex-col gap-2">
              <label
                onDragOver={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  const file = e.dataTransfer.files?.[0];
                  if (file) handlePacketUpload(file);
                }}
                className="flex cursor-pointer flex-col items-center justify-center rounded-md border border-dashed border-border bg-black/[0.01] p-4 text-center hover:bg-black/[0.03] focus-within:ring-2 focus-within:ring-accent dark:hover:bg-white/[0.03]"
              >
                <span className="text-xs font-medium">
                  {packetFileName ? packetFileName : "Select release_packet.json"}
                </span>
                <span className="text-[11px] text-muted mt-0.5">
                  Click or drag file here
                </span>
                <input
                  type="file"
                  accept=".json,application/json"
                  aria-label="Upload release packet JSON file"
                  className="sr-only"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handlePacketUpload(file);
                  }}
                />
              </label>

              <details className="text-xs text-muted mt-1">
                <summary className="cursor-pointer select-none">Or paste raw JSON</summary>
                <textarea
                  value={packetText}
                  onChange={(e) => {
                    setPacketText(e.target.value);
                    setPacketFileName("Pasted JSON");
                    runVerification(e.target.value, derivativeFile);
                  }}
                  rows={4}
                  aria-label="Paste raw release packet JSON"
                  placeholder='{"spec_version": "1.0", "hashes": ...}'
                  className="mt-2 w-full rounded border border-border bg-transparent p-2 font-mono text-[11px] focus-visible:border-accent"
                />
              </details>
            </div>
          </div>

          {/* Derivative upload */}
          <div className="rounded-md border border-border p-4 shadow-card">
            <h2 className="text-sm font-semibold tracking-tight mb-2">
              2. Derivative Document (Optional)
            </h2>
            <p className="text-xs text-muted mb-3">
              Upload the released file (PDF, DOCX) to independently verify its SHA-256 byte match.
            </p>
            <label
              onDragOver={(e) => {
                e.preventDefault();
                e.stopPropagation();
              }}
              onDrop={(e) => {
                e.preventDefault();
                e.stopPropagation();
                const file = e.dataTransfer.files?.[0];
                if (file) handleDerivativeUpload(file);
              }}
              className="flex cursor-pointer flex-col items-center justify-center rounded-md border border-dashed border-border bg-black/[0.01] p-4 text-center hover:bg-black/[0.03] focus-within:ring-2 focus-within:ring-accent dark:hover:bg-white/[0.03]"
            >
              <span className="text-xs font-medium">
                {derivativeFile ? `${derivativeFile.name} (${formatBytes(derivativeFile.data.byteLength)})` : "Select derivative file"}
              </span>
              <span className="text-[11px] text-muted mt-0.5">
                Click or drag file here
              </span>
              <input
                type="file"
                aria-label="Upload derivative file to verify bytes"
                className="sr-only"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) handleDerivativeUpload(file);
                }}
              />
            </label>
            {derivativeFile && (
              <button
                onClick={() => {
                  setDerivativeFile(null);
                  if (packetText) runVerification(packetText, null);
                }}
                className="mt-2 text-xs text-muted hover:text-foreground"
              >
                Clear derivative file
              </button>
            )}
          </div>
        </div>

        {verifying && (
          <p className="text-xs text-muted animate-pulse">Computing cryptographic hashes…</p>
        )}

        {/* Verification Report Display */}
        {report && (
          <div className="space-y-6">
            {/* Top Status Banner */}
            <div
              className={`rounded-md border p-4 shadow-card ${
                report.status === "INTERNALLY CONSISTENT"
                  ? "border-emerald-600/30 bg-emerald-600/5 text-emerald-800 dark:text-emerald-300"
                  : "border-red-600/30 bg-red-600/5 text-red-800 dark:text-red-300"
              }`}
            >
              <div className="flex items-center justify-between gap-4">
                <div>
                  <span className="inline-block rounded px-2 py-0.5 text-xs font-semibold tracking-wide uppercase bg-black/10 dark:bg-white/10">
                    {report.status}
                  </span>
                  <p className="text-xs mt-2 font-medium">
                    {report.status === "INTERNALLY CONSISTENT"
                      ? report.derivativeVerified
                        ? "All declared hashes, schema bindings, and derivative file bytes verified."
                        : "Packet structure and internal custody digests verified (no derivative document provided for byte comparison)."
                      : "One or more cryptographic or structural checks failed. Do not rely on this packet without investigation."}
                  </p>
                  <p className="text-[11px] text-muted mt-1">
                    Doctrine §5: Confirms internal consistency only; does not establish external truth, third-party authentication, or legal privilege.
                  </p>
                </div>
              </div>
            </div>

            {/* Core Details Grid */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-4">
              <div className="rounded-md border border-border p-3 shadow-card">
                <p className="text-[11px] text-muted uppercase">Release ID</p>
                <p className="font-mono text-xs font-medium truncate mt-1">
                  {report.releaseId ?? "—"}
                </p>
              </div>
              <div className="rounded-md border border-border p-3 shadow-card">
                <p className="text-[11px] text-muted uppercase">Policy</p>
                <p className="text-xs font-medium truncate mt-1">
                  {report.policyId ?? "—"}
                </p>
              </div>
              <div className="rounded-md border border-border p-3 shadow-card">
                <p className="text-[11px] text-muted uppercase">Status</p>
                <p className="text-xs font-medium capitalize mt-1">
                  {report.jobStatus ?? "—"}
                </p>
              </div>
              <div className="rounded-md border border-border p-3 shadow-card">
                <p className="text-[11px] text-muted uppercase">Anchor</p>
                <p className="text-xs font-medium truncate mt-1">
                  {report.anchor.type}
                </p>
              </div>
            </div>

            {/* Custody Hashes */}
            <div className="rounded-md border border-border p-4 shadow-card space-y-3">
              <h3 className="text-sm font-semibold tracking-tight">Custody Digest Chain</h3>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <p className="text-xs text-muted mb-1">Original SHA-256 (Declared WORM)</p>
                  <div className="flex items-center gap-2 font-mono text-xs break-all bg-black/[0.02] p-2 rounded border border-border dark:bg-white/[0.02]">
                    <span>{report.originalSha256 ?? "Not declared"}</span>
                    {report.originalSha256 && (
                      <button
                        onClick={() => copyHash(report.originalSha256!)}
                        aria-label="Copy original SHA-256 digest"
                        className="shrink-0 text-muted hover:text-foreground text-[11px]"
                      >
                        {copiedHash === report.originalSha256 ? "copied" : "copy"}
                      </button>
                    )}
                  </div>
                </div>

                <div>
                  <p className="text-xs text-muted mb-1">Derivative SHA-256</p>
                  <div className="flex items-center gap-2 font-mono text-xs break-all bg-black/[0.02] p-2 rounded border border-border dark:bg-white/[0.02]">
                    <span>{report.derivativeDeclared?.sha256 ?? "Not declared"}</span>
                    {report.derivativeDeclared?.sha256 && (
                      <button
                        onClick={() => copyHash(report.derivativeDeclared!.sha256!)}
                        aria-label="Copy derivative SHA-256 digest"
                        className="shrink-0 text-muted hover:text-foreground text-[11px]"
                      >
                        {copiedHash === report.derivativeDeclared!.sha256 ? "copied" : "copy"}
                      </button>
                    )}
                  </div>
                  {report.derivativeDeclared && (
                    <p className="text-[11px] text-muted mt-1">
                      {report.derivativeVerified
                        ? "✓ Verified matching against uploaded derivative bytes"
                        : "Upload derivative file to verify byte-identical match"}
                    </p>
                  )}
                </div>
              </div>
            </div>

            {/* Checks List */}
            <div className="rounded-md border border-border shadow-card overflow-hidden">
              <div className="border-b border-border bg-black/[0.02] px-4 py-2.5 text-xs font-semibold uppercase tracking-wider dark:bg-white/[0.02]">
                Verification Checks ({report.checks.length})
              </div>
              <ul className="divide-y divide-border">
                {report.checks.map((c, i) => (
                  <li key={i} className="flex items-start justify-between gap-4 px-4 py-2.5 text-xs">
                    <div>
                      <p className="font-medium">{c.name}</p>
                      <p className="text-muted text-[11px] mt-0.5">{c.detail}</p>
                    </div>
                    <span
                      className={`shrink-0 rounded px-1.5 py-0.5 font-medium ${
                        c.pass
                          ? "bg-emerald-600/10 text-emerald-700 dark:text-emerald-300"
                          : "bg-red-600/10 text-red-700 dark:text-red-300"
                      }`}
                    >
                      {c.pass ? "Pass" : "Fail"}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Dispositions & Legal Justifications */}
            {(report.dispositions.stripped.length > 0 ||
              report.dispositions.kept.length > 0 ||
              report.legalJustifications.length > 0) && (
              <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                {/* Dispositions */}
                <div className="rounded-md border border-border p-4 shadow-card space-y-3">
                  <h3 className="text-sm font-semibold tracking-tight">Disposition Summary</h3>
                  {report.dispositions.stripped.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-emerald-700 dark:text-emerald-400 mb-1">
                        Stripped Actions ({report.dispositions.stripped.length})
                      </p>
                      <ul className="list-disc list-inside text-xs text-muted space-y-0.5">
                        {report.dispositions.stripped.map((a, idx) => (
                          <li key={idx} className="truncate">{a}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {report.dispositions.kept.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-amber-700 dark:text-amber-400 mb-1">
                        Retained Content ({report.dispositions.kept.length})
                      </p>
                      <ul className="list-disc list-inside text-xs text-muted space-y-0.5">
                        {report.dispositions.kept.map((a, idx) => (
                          <li key={idx} className="truncate">{a}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Legal Justifications */}
                <div className="rounded-md border border-border p-4 shadow-card space-y-3">
                  <h3 className="text-sm font-semibold tracking-tight">Asserted Withholding Grounds</h3>
                  {report.legalJustifications.length === 0 ? (
                    <p className="text-xs text-muted">No specific withholding grounds asserted.</p>
                  ) : (
                    <ul className="divide-y divide-border text-xs">
                      {report.legalJustifications.map((j, idx) => (
                        <li key={idx} className="py-2 space-y-0.5">
                          <div className="flex justify-between items-center">
                            <span className="font-medium">{j.subtype}</span>
                            <span className="rounded bg-black/[0.04] dark:bg-white/[0.04] px-1.5 py-0.5 font-mono text-[10px]">
                              {j.basis}
                            </span>
                          </div>
                          {j.note && <p className="text-muted text-[11px]">{j.note}</p>}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
