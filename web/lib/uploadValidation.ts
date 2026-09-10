// Client-side upload guard. The API still validates and malware-scans every
// upload server-side — this only gives a paralegal an immediate, friendly
// rejection instead of waiting for a POST to fail, and narrows the OS file
// picker via the `accept` attribute.
//
// The set mirrors what the CounselClear engine actually processes: the legal
// document core (DOCX / PDF / Markdown / HTML) plus the plaintext and image
// formats it also cleans. Keeping it in sync with the backend avoids
// false rejections of files the server would happily accept.

export const ACCEPTED_EXTENSIONS = [
  ".docx",
  ".pdf",
  ".md",
  ".markdown",
  ".txt",
  ".html",
  ".htm",
  ".png",
  ".jpg",
  ".jpeg",
  ".svg",
] as const;

// Value for an <input type="file"> `accept` attribute.
export const ACCEPT_ATTR = ACCEPTED_EXTENSIONS.join(",");

// Human-readable list for messages, leading with the legal-document core.
export const ACCEPTED_LABEL = "DOCX, PDF, Markdown, HTML, TXT, or images (PNG/JPEG/SVG)";

/** Lowercased extension including the dot, or "" if the name has none. */
export function fileExtension(filename: string): string {
  const base = filename.split(/[\\/]/).pop() ?? filename;
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return "";
  return base.slice(dot).toLowerCase();
}

export function isAcceptedFilename(filename: string): boolean {
  return (ACCEPTED_EXTENSIONS as readonly string[]).includes(fileExtension(filename));
}

/**
 * Returns null when the file is acceptable, or a friendly, actionable
 * rejection message naming the offending type and the supported set.
 */
export function validateUploadFilename(filename: string): string | null {
  const name = (filename ?? "").trim();
  if (!name) return "Choose a file to upload.";
  if (isAcceptedFilename(name)) return null;
  const ext = fileExtension(name);
  const got = ext ? `"${ext}" files` : "files without an extension";
  return `Can't upload ${got}. CounselClear accepts ${ACCEPTED_LABEL}.`;
}
