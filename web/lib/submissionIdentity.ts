// Persist only a digest and a random retry key, never document or form content.
const memory = new Map<string, string>();

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, canonical(v)]));
  }
  return value;
}

export function submissionFingerprint(path: string, body: unknown): string {
  return JSON.stringify([path, canonical(body ?? null)]);
}

export async function submissionIdentity(fingerprint: string) {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.randomUUID) {
    throw new Error("Open CounselClear using HTTPS or localhost to submit work with safe retry tracking.");
  }
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(fingerprint));
  const name = "counselclear:submission:" + Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
  let key = memory.get(name);
  if (!key) {
    try { key = sessionStorage.getItem(name) ?? undefined; } catch { /* restricted storage: keep the in-memory identity */ }
  }
  key ||= crypto.randomUUID();
  memory.set(name, key);
  try { sessionStorage.setItem(name, key); } catch { /* memory still covers retries in this page session */ }
  return {
    key,
    complete() {
      memory.delete(name);
      try { sessionStorage.removeItem(name); } catch { /* restricted storage */ }
    },
  };
}
