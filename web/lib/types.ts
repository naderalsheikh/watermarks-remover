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
  // PR 40: null for an inspect job or one created via the legacy
  // /sanitize-jobs route -- neither ever gets a Release wrapper. Present
  // only for a job created through POST .../releases. This is the ONLY
  // way the UI discovers a Job's Release: there's no separate "list
  // releases" fetch or Release detail page in this pass.
  release_id: string | null;
  profile_id: string | null;
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

// POST/GET /v1/matters/{id}/batches[/{batch_id}] — one row per document
// (service/app/main.py create_batch), never laundered into a vague
// "batch succeeded". Formerly the shape the synchronous /bulk-jobs
// endpoint (PR 23) returned directly; that endpoint was retired in PR 31
// commit 3 once the frontend moved to polling this async resource, and
// this result/summary shape carried over unchanged.
export type BulkJobResult = {
  document_id: string;
  document_name: string;
  job_id: string;
  kind: JobKind;
  policy_id: string;
  status: JobStatus;
  error: string;
  // PR 40: same meaning as Job.release_id/profile_id above -- null unless
  // this batch was created through POST .../releases.
  release_id: string | null;
  profile_id: string | null;
};

// finished_utc is null while any child is queued or running, and gets
// set exactly once by the backend dispatcher when every child has
// reached a terminal state.
export type BatchResponse = {
  id: string;
  matter_id: string;
  kind: JobKind;
  policy_id: string;
  total: number;
  created_utc: string;
  finished_utc: string | null;
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

// GET /v1/release-profiles (service/app/main.py RELEASE_PROFILES) — the
// user-facing destination/use-case a release action picks from. Each
// resolves to exactly one policy_id server-side; policy_id itself stays
// the internal identifier, shown only in a "technical details"
// disclosure, never as the primary choice (PR 40).
export type ReleaseProfile = {
  id: string;
  label: string;
  policy_id: string;
  description: string;
};

export type ReleaseProfilesResponse = {
  release_profiles: ReleaseProfile[];
  recipient_types: string[];
};

// The Release row itself (service/app/models.py Release / _release_dict).
// status mirrors Job.status's own vocabulary exactly — synced 1:1, never
// a separate mapping.
export type Release = {
  id: string;
  matter_id: string;
  document_id: string;
  batch_id: string | null;
  job_id: string;
  policy_id: string;
  profile_id: string;
  recipient_type: string;
  recipient_name: string;
  purpose: string;
  intended_external: boolean;
  requested_by: string;
  status: JobStatus;
  created_utc: string;
  finished_utc: string | null;
};

// GET /v1/matters/{id}/releases/{id}/result — release_result.json's own
// shape (service/app/main.py _build_release_result). Produced for EVERY
// terminal release, done included: for a refused/failed one this is the
// only structured artifact (no derivative, no zip).
export type ReleaseResult = {
  spec_version: string;
  release_id: string;
  job_id: string;
  document_id: string;
  matter_id: string;
  status: JobStatus;
  policy_id: string;
  profile_id: string;
  recipient_type: string;
  recipient_name: string;
  purpose: string;
  intended_external: boolean;
  reason: string;
  original_sha256: string;
  created_at: string;
  finished_at: string | null;
  audit_refs: { release_created_seq: number | null; release_terminal_seq: number | null };
  limitations: string[];
  certificate_html_sha256: string;
  generated_at: string;
  anchor: { type: string; digest: string | null; reference: string | null };
};

// POST /v1/matters/{id}/documents/{doc_id}/releases — the single-document
// release response: everything the UI needs in one round trip (no
// separate Release detail page in this pass).
export type ReleaseCreateResponse = {
  release: Release;
  job: Job;
  release_result: ReleaseResult;
};

// POST /v1/matters/{id}/releases — batch release: reuses BatchResponse's
// own shape underneath (its `results` entries already carry
// release_id/profile_id), plus the per-document Release rows created
// alongside it.
export type BatchReleaseResponse = {
  batch: BatchResponse;
  releases: Release[];
};

export const KNOWN_PERMS = [
  "read",
  "upload",
  "inspect",
  "sanitize",
  "download_original",
  "admin",
] as const;
