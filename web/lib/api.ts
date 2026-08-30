// Every call is same-origin (see next.config.ts) so the SameSite=Strict
// cc_session cookie rides along automatically — no token to store, no
// Authorization header to manage.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "include",
    headers: {
      ...(init?.body && !(init.body instanceof FormData)
        ? { "Content-Type": "application/json" }
        : {}),
      ...init?.headers,
    },
  });
  if (!res.ok) {
    let message = res.statusText;
    try {
      // FastAPI error bodies carry `detail` as a plain string for
      // HTTPException (the common case) but as an ARRAY of per-field
      // objects for request-validation 422s. Assigning the array
      // straight into Error.message and rendering it crashes React
      // ("Objects are not valid as a React child") -- so normalize to
      // a string here, at the one boundary every error passes through.
      const body = (await res.json()) as { detail?: unknown };
      if (typeof body.detail === "string") {
        message = body.detail;
      } else if (Array.isArray(body.detail)) {
        const parts = body.detail
          .map((d) =>
            d && typeof d === "object" && "msg" in d
              ? `${loc(d)} ${String((d as { msg: unknown }).msg)}`
              : JSON.stringify(d),
          )
          .filter((s) => s.length > 0);
        if (parts.length > 0) message = parts.join("; ");
      }
    } catch {
      // response wasn't JSON — keep statusText
    }
    throw new ApiError(res.status, message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// "body.reason -> must be of string type" from a 422 item's loc+msg --
// the field path plus the human-readable constraint, no raw JSON dump.
function loc(d: object): string {
  const l = (d as { loc?: unknown }).loc;
  if (Array.isArray(l) && l.length > 1) return `body.${l.slice(1).join(".")}:`;
  return "";
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "POST",
      body:
        body instanceof FormData ? body : body !== undefined ? JSON.stringify(body) : undefined,
    }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(body) }),
  del: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "DELETE",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
};
