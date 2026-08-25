export type AuthConfig = { oidc_enabled: boolean };

export type Matter = { id: string; name: string; created_utc: string };

export type Document = {
  id: string;
  matter_id: string;
  filename: string;
  sha256: string;
  bytes: number;
  created_utc: string;
};

export type Policy = { id: string; label: string; description: string };

export type JobKind = "inspect" | "sanitize";
export type JobStatus = "queued" | "running" | "done" | "failed";

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
  events: AuditEvent[];
};
