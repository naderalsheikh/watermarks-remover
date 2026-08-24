import type { NextConfig } from "next";

// Same-origin by design (see docs/COUNSELCLEAR_DESIGN.md, PR 19): the
// cc_session cookie is SameSite=Strict, so this app must never be fetched
// cross-origin from the API. In production, nginx serves this app's static
// export at `/` and proxies `/v1/*` to cc-api — see deploy/nginx-counselclear.conf.example.
// `next dev` has no such proxy in front of it, so it needs its own: rewrites()
// here forward `/v1/*` to the local API during development only. Static
// export (`output: "export"`) does not support rewrites at all — Next
// errors even under `next dev` if both are set at once — so the two are
// mutually exclusive on NODE_ENV, not just conditionally applied.
const isDev = process.env.NODE_ENV === "development";

const nextConfig: NextConfig = {
  ...(isDev
    ? {
        async rewrites() {
          const api = process.env.COUNSELCLEAR_API_ORIGIN ?? "http://127.0.0.1:8443";
          return [{ source: "/v1/:path*", destination: `${api}/v1/:path*` }];
        },
      }
    : { output: "export" }),
};

export default nextConfig;
