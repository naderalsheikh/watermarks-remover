export type AuthConfig = { oidc_enabled: boolean };

// `perms` is present on POST /v1/matters and GET /v1/matters/{id} (the
// caller's own grants on this matter, service/app/main.py's _matter_dict)
// -- not on list_matters items, which don't compute it per-row. Frontend
// uses it to hide/disable controls that would otherwise 403.
export type Matter = { id: string; name: string; created_utc: string; perms?: string[] };
export type Perm = "read" | "upload" | "inspect" | "sanitize" | "download_original" | "admin";

export type Document = {
  id: string;
  matter_id: string;
  filename: string;
  sha256: string;
  bytes: number;
  created_utc: string;
};

export type Policy = { id: string; label: string; description: string; bulk_safe: boolean };

export type JobKind = "inspect" | "sanitize";
// service/app/runner.py's terminal set is ("done", "refused", "failed") —
// "refused" is a distinct, correct outcome (policy declined to produce a
// derivative, e.g. a macro-enabled file under a mutating policy), not a
// bug or a plain failure. It was missing here entirely until this fix,
// which meant a refused job rendered with an undefined StatusBadge style
// — exactly the kind of silent-wrong presentation this product's trust
// bar exists to catch.
export type JobStatus = "queued" | "running" | "done" | "failed" | "refused";

export type FindingLocation = {
  part: string | null;
  xpath_or_field: string | null;
  page: number | null;
  sheet: number | null;
  slide: number | null;
  offset: number | null;
  bbox: [number, number, number, number] | null;
  pane: string;
};

export type Finding = {
  finding_id: string;
  category: string;
  subtype: string;
  format: string;
  location: FindingLocation;
  field: string | null;
  value_redacted: string | null;
  action_recommended: string;
  action_allowed_by_policy: string[];
  content_visible: boolean;
  risk_level: "critical" | "high" | "medium" | "low" | "info";
  confidence: "confirmed" | "probable" | "informational" | "likely_false_positive";
  removal_changes_visible_content: boolean;
  requires_approval: boolean;
  requires_attestation: boolean;
  notes: string | null;
  // Inspect-time only (service/app/worker.py): the policy-engine subtype
  // this finding maps to, and whether Production's default for that
  // subtype is "approve" (i.e. a per-finding decision would apply). null
  // policy_subtype means this finding has no policy-engine mapping.
  policy_subtype?: string | null;
};

export type JobResult = {
  findings?: Finding[];
  manifest?: Record<string, unknown>;
  verification_pass?: boolean;
  [key: string]: unknown;
};

export type VerificationCheck = { name: string; detail: string; pass: boolean };

// Sanitize jobs don't carry structured Finding[] — apply_actions already
// resolved every finding into an action, so the manifest (docs/COUNSELCLEAR_DESIGN.md
// "Manifest") records what happened instead: plain-text summaries, not the
// pre-decision Finding schema inspect jobs use.
export type Manifest = {
  actions: string[];
  findings_before: string[];
  derivative: { filename: string; bytes: number; sha256: string };
  original: { filename: string; bytes: number; sha256: string };
  policy: { id: string; version: number };
  verification: { pass: boolean; checks: VerificationCheck[] };
  [key: string]: unknown;
};

export type Job = {
  id: string;
  matter_id: string;
  document_id: string;
  kind: JobKind;
  policy_id: string;
  status: JobStatus;
  error: string | null;
  attestation: boolean;
  worker_image: string;
  created_utc: string;
  finished_utc: string | null;
  result?: JobResult;
};

// GET /v1/matters/{id}/audit — the tamper-evident per-matter log
// (service/app/main.py list_audit): every event is hash-chained, so the
// chain_ok flag is the integrity verdict, not the rows themselves.
export type AuditEvent = {
  id: string;
  seq: number;
  action: string;
  actor_id: string;
  payload: Record<string, unknown> | null;
  prev_hash: string;
  row_hash: string;
  at: string;
};

export type Audit = {
  chain_ok: boolean;
  chain_detail: string;
  total: number;
  offset: number;
  limit: number;
  events: AuditEvent[];
};

// GET /v1/matters/{id}/acl — current access grants, one row per user_id.
export type AclGrant = { user_id: string; perms: string[] };

// GET /v1/dashboard — operator overview (service/app/main.py dashboard).
// Unlike /v1/matters (whose list page honestly says "loaded-so-far"), every
// number here is a server-computed total over the FULL ACL-visible corpus,
// so the UI may present these as global truth for what this principal can
// read. "attention" is ordered by severity: unreviewed findings first,
// then refused, failed, stale.
export type AttentionType = "unreviewed_findings" | "refused" | "failed" | "stale";

export type AttentionItem = {
  type: AttentionType;
  matter_id: string;
  matter_name: string;
  document_id?: string;
  document_name?: string;
  job_id?: string;
  kind?: JobKind;
  detail: string;
  created_utc: string;
};

export type DashboardRecent = {
  matter_id: string;
  matter_name: string;
  action: string;
  actor_id: string;
  at: string;
};

// admin_matters: how many of the principal's readable matters they also
// administer (service/app/main.py dashboard, 2026-08-25 disclosure split)
// -- "stale" attention items and `recent` are scoped to those matters
// only, since both are audit-derived and audit itself is admin-gated
// (same as GET .../audit). refused/failed/unreviewed_findings stay at
// read scope: their detail is already visible through read-gated
// per-job routes, so the dashboard isn't the first place it leaks.
export type Dashboard = {
  totals: {
    matters: number;
    documents: number;
    jobs: Record<JobStatus, number>;
  };
  attention: AttentionItem[];
  recent: DashboardRecent[];
  admin_matters: number;
};

// POST /v1/matters/{id}/bulk-jobs — one job per document, each audited and
// reported individually (service/app/main.py bulk_jobs). `status` and
// `error` are per-document: a refused or failed job shows up next to the
// successes, never laundered into a blanket "bulk succeeded".
export type BulkJobResult = {
  document_id: string;
  document_name: string;
  job_id: string;
  kind: JobKind;
  policy_id: string;
  status: JobStatus;
  error: string;
};

export type BulkJobsResponse = {
  results: BulkJobResult[];
  summary: {
    requested: number;
    done: number;
    refused: number;
    failed: number;
    queued: number;
    running: number;
  };
};

// POST/GET /v1/matters/{id}/batches[/{batch_id}] — the async counterpart
// to bulk-jobs (PR 31). Same per-document results[]/summary shape as
// BulkJobsResponse (still never a vague "batch succeeded"), plus the
// batch's own identity and lifecycle: finished_utc is null while any
// child is queued or running, and gets set exactly once by the backend
// dispatcher when every child has reached a terminal state.
export type BatchResponse = {
  id: string;
  matter_id: string;
  kind: JobKind;
  policy_id: string;
  total: number;
  created_utc: string;
  finished_utc: string | null;
  results: BulkJobResult[];
  summary: BulkJobsResponse["summary"];
};

export const KNOWN_PERMS = [
  "read",
  "upload",
  "inspect",
  "sanitize",
  "download_original",
  "admin",
] as const;
