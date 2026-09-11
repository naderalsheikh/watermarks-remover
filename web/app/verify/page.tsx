"use client";

import { useRef, useState } from "react";
import Link from "next/link";
import { Header } from "@/components/Header";
import {
  verifyReleasePacket,
  type VerificationReport,
  type CheckStatus,
} from "@/lib/packetVerifier";

function formatBytes(n?: number): string {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}

const checkLabels: Record<CheckStatus, string> = {
  passed: "Passed", failed: "Failed", not_checked: "Not checked", unavailable: "Unavailable",
};
const checkColors: Record<CheckStatus, string> = {
  passed: "bg-emerald-600/10 text-emerald-700 dark:text-emerald-300",
  failed: "bg-red-600/10 text-red-700 dark:text-red-300",
  not_checked: "bg-amber-600/10 text-amber-800 dark:text-amber-300",
  unavailable: "bg-black/5 text-muted dark:bg-white/5",
};
type DerivativeFile = { name: string; data: ArrayBuffer };

export default function VerifyPage() {
  const [packetText, setPacketText] = useState("");
  const [packetFileName, setPacketFileName] = useState<string | null>(null);
  const [derivativeFile, setDerivativeFile] = useState<DerivativeFile | null>(null);
  const [report, setReport] = useState<VerificationReport | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const activeRun = useRef(0);
  const packetRead = useRef(0);
  const derivativeRead = useRef(0);
  const readingPacket = useRef(false);
  const readingDerivative = useRef(false);
  const latestPacket = useRef("");
  const latestDerivative = useRef<DerivativeFile | null>(null);

  async function copyHash(hash: string) {
    setCopyError(null);
    try {
      await navigator.clipboard.writeText(hash);
      setCopiedHash(hash);
    } catch {
      setCopyError("The browser could not copy the digest. Select the digest text and copy it manually.");
    }
  }

  async function runVerification(text = latestPacket.current, deriv = latestDerivative.current) {
    const run = ++activeRun.current;
    setReport(null);
    setCopyError(null);
    setCopiedHash(null);
    if (readingPacket.current || readingDerivative.current) {
      setVerifying(true);
      return;
    }
    if (!text.trim()) {
      setVerifying(false);
      return;
    }
    setVerifying(true);
    try {
      const nextReport = await verifyReleasePacket(text, { derivative: deriv ?? undefined });
      if (run === activeRun.current) setReport(nextReport);
    } catch {
      if (run === activeRun.current) setError("Browser verification could not finish. Retry with the complete JSON file, or run the offline verifier on the packet.");
    } finally {
      if (run === activeRun.current) setVerifying(false);
    }
  }

  async function handlePacketUpload(file: File) {
    const read = ++packetRead.current;
    ++activeRun.current;
    readingPacket.current = true;
    latestPacket.current = "";
    setPacketText("");
    setPacketFileName(file.name);
    setReport(null);
    setError(null);
    setVerifying(true);
    try {
      const text = await file.text();
      if (read !== packetRead.current) return;
      readingPacket.current = false;
      latestPacket.current = text;
      setPacketText(text);
      if (!text.trim()) {
        setError("The JSON file is empty. Select a complete release_packet.json or release_result.json.");
        setVerifying(readingDerivative.current);
        return;
      }
      await runVerification();
    } catch {
      if (read !== packetRead.current) return;
      readingPacket.current = false;
      setVerifying(readingDerivative.current);
      setError("The JSON file could not be read. Select it again or paste its contents below.");
    }
  }

  async function handleDerivativeUpload(file: File) {
    const read = ++derivativeRead.current;
    ++activeRun.current;
    readingDerivative.current = true;
    latestDerivative.current = null;
    setDerivativeFile(null);
    setReport(null);
    setError(null);
    setVerifying(true);
    try {
      const data = await file.arrayBuffer();
      if (read !== derivativeRead.current) return;
      readingDerivative.current = false;
      const derivative = { name: file.name, data };
      latestDerivative.current = derivative;
      setDerivativeFile(derivative);
      await runVerification();
    } catch {
      if (read !== derivativeRead.current) return;
      readingDerivative.current = false;
      setVerifying(readingPacket.current);
      setError("The document could not be read. Select the file again to compare its bytes.");
    }
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
              Schema and SHA-256 checks run in this browser. Selected file contents stay on this device.
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
              1. Release JSON (required)
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
                <span className="text-sm font-medium break-all">
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
                    e.currentTarget.value = "";
                    if (file) handlePacketUpload(file);
                  }}
                />
              </label>

              <details className="text-xs text-muted mt-1">
                <summary className="cursor-pointer select-none">Or paste raw JSON</summary>
                <textarea
                  value={packetText}
                  onChange={(e) => {
                    ++packetRead.current;
                    readingPacket.current = false;
                    latestPacket.current = e.target.value;
                    setError(null);
                    setPacketText(e.target.value);
                    setPacketFileName("Pasted JSON");
                    void runVerification();
                  }}
                  rows={4}
                  aria-label="Paste raw release packet JSON"
                  placeholder='{"spec_version": "1.0", "hashes": ...}'
                  className="mt-2 w-full rounded border border-border bg-transparent p-2 font-mono text-base focus-visible:border-accent"
                />
              </details>
            </div>
          </div>

          {/* Derivative upload */}
          <div className="rounded-md border border-border p-4 shadow-card">
            <h2 className="text-sm font-semibold tracking-tight mb-2">
              2. Released document (optional)
            </h2>
            <p className="text-xs text-muted mb-3">
              Select the released file to compare its bytes with the digest in release_packet.json. A release_result.json does not declare a document digest.
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
              <span className="text-sm font-medium break-all">
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
                  e.currentTarget.value = "";
                  if (file) handleDerivativeUpload(file);
                }}
              />
            </label>
            {derivativeFile && (
              <button
                onClick={() => {
                  ++derivativeRead.current;
                  readingDerivative.current = false;
                  latestDerivative.current = null;
                  setError(null);
                  setDerivativeFile(null);
                  void runVerification();
                }}
                className="mt-2 text-xs text-muted hover:text-foreground"
              >
                Clear derivative file
              </button>
            )}
          </div>
        </div>

        <div role="status" aria-live="polite" className="text-sm text-muted">
          {verifying && <p>Reading selected files and checking available evidence…</p>}
        </div>
        {error && <p role="alert" className="mb-4 text-sm text-red-700 dark:text-red-300">{error}</p>}
        {copyError && <p role="alert" className="mb-4 text-sm text-red-700 dark:text-red-300">{copyError}</p>}

        {/* Verification Report Display */}
        {report && (
          <div className="space-y-6">
            {/* Top Status Banner */}
            <div
              role="status"
              aria-live="polite"
              className={`rounded-md border p-4 shadow-card ${
                report.status === "INTERNALLY INCONSISTENT"
                  ? "border-red-600/30 bg-red-600/5 text-red-800 dark:text-red-300"
                  : "border-amber-600/30 bg-amber-600/5 text-amber-900 dark:text-amber-200"
              }`}
            >
              <div className="flex items-center justify-between gap-4">
                <div>
                  <span className="inline-block rounded px-2 py-0.5 text-xs font-semibold tracking-wide uppercase bg-black/10 dark:bg-white/10">
                    {report.status}
                  </span>
                  <p className="text-xs mt-2 font-medium">
                    {report.status === "INTERNALLY INCONSISTENT"
                      ? "A structural check or evidence comparison failed. Review the failed checks below before relying on this artifact."
                      : "No check failed, but verification is incomplete. Only checks marked Passed were performed successfully."}
                  </p>
                  <p className="text-sm mt-2">
                    {report.checks.filter((check) => check.status === "passed").length} passed · {report.checks.filter((check) => check.status === "failed").length} failed · {report.checks.filter((check) => check.status === "not_checked").length} not checked · {report.checks.filter((check) => check.status === "unavailable").length} unavailable
                  </p>
                  <p className="text-sm mt-2">
                    This browser does not authenticate the operator signature or timestamp, verify the audit chain, or inspect the complete packet. Use the offline verifier with the complete packet, a trusted operator key, and the exported audit CSV for those checks.
                  </p>
                </div>
              </div>
            </div>

            {/* Core Details Grid */}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-4">
              <div className="rounded-md border border-border p-3 shadow-card">
                <p className="text-[11px] text-muted uppercase">Release ID</p>
                <p className="font-mono text-xs font-medium break-words mt-1">
                  {report.releaseId ?? "—"}
                </p>
              </div>
              <div className="rounded-md border border-border p-3 shadow-card">
                <p className="text-[11px] text-muted uppercase">Policy</p>
                <p className="text-xs font-medium break-words mt-1">
                  {report.policyId ?? "—"}
                </p>
              </div>
              <div className="rounded-md border border-border p-3 shadow-card">
                <p className="text-[11px] text-muted uppercase">Declared release status</p>
                <p className="text-xs font-medium capitalize mt-1">
                  {report.jobStatus ?? "—"}
                </p>
              </div>
              <div className="rounded-md border border-border p-3 shadow-card">
                <p className="text-[11px] text-muted uppercase">Declared anchor</p>
                <p className="text-xs font-medium break-words mt-1">
                  {report.anchor.type}
                </p>
                <p className="text-sm text-muted mt-1">{report.anchor.detail}</p>
              </div>
            </div>

            {/* Custody Hashes */}
            <div className="rounded-md border border-border p-4 shadow-card space-y-3">
              <h3 className="text-sm font-semibold tracking-tight">Declared and compared digests</h3>
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                <div>
                  <p className="text-xs text-muted mb-1">Original SHA-256 (declared only)</p>
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
                  <p className="text-xs text-muted mb-1">Released document SHA-256</p>
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
                        ? "Selected document bytes match the declared SHA-256."
                        : derivativeFile
                          ? "Document bytes have not passed comparison. See the digest check below."
                          : "Select the released document to compare its bytes."}
                    </p>
                  )}
                </div>
              </div>
            </div>

            {/* Checks List */}
            <div className="rounded-md border border-border shadow-card overflow-hidden">
              <div className="border-b border-border bg-black/[0.02] px-4 py-2.5 text-xs font-semibold uppercase tracking-wider dark:bg-white/[0.02]">
                Evidence checks ({report.checks.length})
              </div>
              <ul className="divide-y divide-border">
                {report.checks.map((c, i) => (
                  <li key={i} className="flex items-start justify-between gap-4 px-4 py-2.5 text-xs">
                    <div className="min-w-0 break-words">
                      <p className="font-medium">{c.name}</p>
                      <p className="text-muted text-sm mt-0.5 [overflow-wrap:anywhere]">{c.detail}</p>
                    </div>
                    <span className={`shrink-0 rounded px-1.5 py-0.5 font-medium ${checkColors[c.status]}`}>
                      {checkLabels[c.status]}
                    </span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Dispositions & Legal Justifications */}
            {(report.dispositions.stripped.length > 0 ||
              report.dispositions.kept.length > 0 ||
              report.dispositions.refused.length > 0 ||
              report.legalJustifications.length > 0) && (
              <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                {/* Dispositions */}
                <div className="rounded-md border border-border p-4 shadow-card space-y-3">
                  <h3 className="text-sm font-semibold tracking-tight">Declared dispositions</h3>
                  {report.dispositions.stripped.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-emerald-700 dark:text-emerald-400 mb-1">
                        Declared removals ({report.dispositions.stripped.length})
                      </p>
                      <ul className="list-disc list-inside text-xs text-muted space-y-0.5">
                        {report.dispositions.stripped.map((a, idx) => (
                          <li key={idx} className="break-words">{a}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {report.dispositions.kept.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-amber-700 dark:text-amber-400 mb-1">
                        Declared retained content ({report.dispositions.kept.length})
                      </p>
                      <ul className="list-disc list-inside text-xs text-muted space-y-0.5">
                        {report.dispositions.kept.map((a, idx) => (
                          <li key={idx} className="break-words">{a}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {report.dispositions.refused.length > 0 && (
                    <div>
                      <p className="text-sm font-medium mb-1">Declared refusals ({report.dispositions.refused.length})</p>
                      <ul className="list-disc list-inside text-sm text-muted space-y-1">
                        {report.dispositions.refused.map((action, index) => <li key={index} className="break-words">{action}</li>)}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Legal Justifications */}
                <div className="rounded-md border border-border p-4 shadow-card space-y-3">
                  <h3 className="text-sm font-semibold tracking-tight">Asserted Withholding Grounds</h3>
                  <p className="text-sm text-muted">Copied from the artifact. These assertions do not establish legal privilege or a valid withholding basis.</p>
                  {report.legalJustifications.length === 0 ? (
                    <p className="text-xs text-muted">No specific withholding grounds asserted.</p>
                  ) : (
                    <ul className="divide-y divide-border text-xs">
                      {report.legalJustifications.map((j, idx) => (
                        <li key={idx} className="py-2 space-y-0.5">
                          <div className="flex flex-wrap justify-between items-start gap-2">
                            <span className="min-w-0 break-words font-medium">{j.subtype}</span>
                            <span className="rounded bg-black/[0.04] dark:bg-white/[0.04] px-1.5 py-0.5 font-mono text-[10px]">
                              {j.basis}
                            </span>
                          </div>
                          {j.note && <p className="text-muted text-sm [overflow-wrap:anywhere]">{j.note}</p>}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            )}
            {report.limitations.length > 0 && (
              <div className="rounded-md border border-border p-4">
                <h3 className="text-sm font-semibold">Artifact limitations</h3>
                <ul className="mt-2 list-disc pl-5 text-sm text-muted space-y-1">
                  {report.limitations.map((limitation, index) => <li key={index} className="break-words">{limitation}</li>)}
                </ul>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
