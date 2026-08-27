# Proposal: release packet verification and anchoring

Proposal only — no implementation in this pass. Sharpens the proof
model from `docs/release-control-evidence-thesis.md` into a concrete,
buildable spec before any of it is coded.

**Scope note on the strategy-exploration material this proposal follows
from:** a multi-model exploration was run on "what makes this a
must-have" and produced several memoranda with strategic/business
framing (risk-transfer primitives, insurance economics, historical
institutional patterns). That material is raw input, not adopted
doctrine — consistent with `docs/counselclear-strategy.md` point 6
(model output is not product truth). This proposal deliberately does
**not** import that material's business claims or vocabulary into
engineering scope. It takes only the one concrete, already-agreed
technical conclusion those memos converged on and the existing thesis
already stated: **the current proof is self-attested, and closing that
gap needs a spec, a verifier, and an anchor — in that order.** Nothing
below is scoped to "must-have" claims; it's scoped to what's actually
buildable and honestly describable today.

## 1. What the current release packet proves today

Grounded in the actual code as of PR 36 (`service/app/main.py`,
`service/scripts/custody.py::emit_manifest`, `service/app/audit.py`),
not aspiration:

- **Content binding.** `manifest.json`'s `original.sha256` and
  `derivative.sha256` bind a specific derivative to a specific
  original, recorded at generation time.
- **Internal, recomputable consistency.** Every audit row's `row_hash`
  is `event_hash(prev_hash, seq, actor_id, action, payload)`
  (`audit.py::event_hash`) — recomputable by anyone holding the row's
  own stored fields. The certificate's "custody record" section already
  does exactly this for a job's own `job.inspect`/`job.sanitize` rows
  (`_build_certificate_html`'s `audit_integrity_ok` check).
- **Disclosure completeness for what ran.** The certificate's
  limitations section is derived from the same manifest data the
  derivative was built from — there's no separate summary that can
  drift from what actually happened.
- **A packaged, self-contained bundle.** `derivative/`, `manifest.json`,
  `report.json`, `certificate.html`, `README.txt` travel together by
  default (PR 36) — the recipient doesn't have to reassemble anything
  from separate downloads.

## 2. What it does not prove

- **No external timestamp.** Every timestamp (`created_utc`,
  `finished_utc`, `generated_at`) is an ISO string this application
  itself wrote (`models.py::_now`). Nothing outside the database
  confirms any of it existed at the claimed time — a party with
  database access could set any timestamp on any row.
- **No public or customer-held anchor.** The entire chain lives in one
  database this product's own operator controls. No independent copy
  exists anywhere else by default.
- **No independent verifier.** "Verification" today means either
  recomputing `event_hash` against values the *same* database supplied
  (not independent of that database), or reading the certificate's own
  "OK"/"MISMATCH" text and trusting it. There is no separate tool a
  third party can run, offline, against a downloaded packet, without
  ever talking to the CounselClear API.
- **No signed policy digest.** `POLICIES` in `main.py` is a literal
  list; "policy `external_sharing` v1" is a label, not a hash-pinned,
  independently citable artifact. Nothing proves *which exact rules*
  produced a given derivative beyond the id/version integer.

## 3. Minimal release-packet manifest/spec

A new file, `release_packet.json`, added to the existing bundle zip
alongside the current five files. Canonical JSON — sorted keys, no
insignificant whitespace — matching the exact style `audit.py` already
uses for hashing (`json.dumps(payload, sort_keys=True, separators=(",", ":"))`),
so this isn't a new convention, just the existing one applied to a new
document.

```json
{
  "spec_version": "1.0",
  "packet_id": "<job_id>",
  "matter_id": "...",
  "document_id": "...",
  "job_id": "...",
  "kind": "sanitize",
  "status": "done",
  "policy": {
    "id": "external_sharing",
    "version": 1,
    "digest": null
  },
  "hashes": {
    "original_sha256": "...",
    "derivative_sha256": "...",
    "manifest_json_sha256": "...",
    "report_json_sha256": "...",
    "certificate_html_sha256": "..."
  },
  "audit_refs": {
    "job_event_seqs": [3, 4],
    "certificate_issued_seq": 4,
    "bundle_download_seq": 3
  },
  "limitations": ["..."],
  "generated_at": "2026-08-27T00:00:00+00:00",
  "generated_by": "operator",
  "anchor": {
    "type": "none",
    "digest": null,
    "reference": null
  }
}
```

Notes on the shape, not just the fields:

- **`policy.digest: null`** is deliberately reserved, not implemented —
  hash-pinning the actual policy rule content (not just an id/version
  label) is real design work (what exactly gets hashed — the `POLICIES`
  literal? the engine's `policies.py` subtype table both must stay in
  sync with, per PR 17's isolation doctrine?) that this proposal is not
  trying to resolve. The field exists so a later pass can populate it
  without a spec version bump.
- **`hashes.*_json_sha256` / `*_html_sha256`** hash the *packaged bytes*
  of each sibling file exactly as they sit in the zip — this is what
  lets a verifier confirm the packet wasn't partially swapped
  (derivative from one job, certificate from another) without needing
  any network access.
- **`audit_refs`** are `seq` numbers, not full audit rows — this
  manifest doesn't duplicate the audit chain, it points into it, so a
  holder of the full matter audit log (an admin, via the existing
  `/audit` export) can cross-reference without this file growing
  unbounded.
- **`anchor`** is the field this whole proposal is building toward
  being able to fill in later (§5/§6) without another format
  migration — `type: "none"` today is itself an honest, explicit
  statement, not an omission.

## 4. Offline/public verifier design

A verifier that takes a release packet (zip or extracted directory) and
checks everything checkable **without any network access and without
trusting the issuing CounselClear instance**:

1. Parse `release_packet.json`; validate required fields are present
   (`spec_version` known, all `hashes.*` present).
2. Recompute SHA-256 of every sibling file actually present in the
   packet; compare against the declared hash. Report per-file
   `MATCH`/`MISMATCH` — a mismatch on any file is the strongest possible
   finding this tool can produce (tampering after packaging, or a
   corrupted transfer).
3. Cross-check `release_packet.json`'s `job_id`/`matter_id`/
   `document_id`/`policy.id`/`status` against the same fields recorded
   inside `manifest.json` and (via simple substring/text checks, not a
   full HTML parse) `certificate.html` — catches a packet reassembled
   from mismatched parts even if individual file hashes weren't touched
   post-hoc (i.e., someone builds a *consistent* fake from real pieces
   of two different jobs).
4. **Report the anchor status honestly and prominently, every time.**
   If `anchor.type == "none"` (true for every packet this proposal's
   first implementation would produce — see §6), the verifier's output
   leads with something like:

   > NOT EXTERNALLY ANCHORED. This packet's timestamp and content are
   > self-attested by the system that produced it. No independent party
   > has confirmed this content existed at the claimed time. Hash
   > checks above confirm internal consistency only.

   This is not boilerplate to bury — it's the single most important
   line the tool prints, and it must never be silently true "verified"
   language layered over it.

**Two delivery forms, not mutually exclusive:**

- **CLI** (`tools/counselclear_verify_release_packet.py`): stdlib-only
  (`hashlib`, `json`, `zipfile`), same "no third-party dependency, no
  engine import" discipline as `tools/counselclear_airlock.py` — this
  is the natural v1, cheapest to build and test, and the one that
  matters most for the CI/scriptable case.
- **Static web verifier** (fast-follow, not required for v1): a
  self-contained HTML+JS page using the browser's native
  `crypto.subtle.digest` for SHA-256 — no library, nothing installed,
  nothing sent over the network (the file never leaves the browser). A
  claims adjuster or opposing counsel's staff dropping a packet onto a
  page is a meaningfully lower-friction ask than "install Python and
  run a script." Worth building once the CLI's logic is proven, not
  before — the CLI is where the actual verification logic should be
  written and tested once; the web page can be a thin restatement of
  the same checks in JS, or could shell out to the same logic if this
  becomes a build-tooling question later.

## 5. External anchoring options

Already surveyed in full in `docs/release-control-evidence-thesis.md`
§4 (RFC 3161 timestamp authority, public transparency log, extending
the existing S3 Object Lock custody infrastructure to the audit chain,
signed daily digest, third-party attestation partner) — not re-derived
here. The one addition this proposal makes: whichever anchor is chosen
later, it attaches by populating the `anchor` block in §3's spec
(`type`, `digest`, `reference`) without changing anything else about
the packet's shape. That's the concrete meaning of "anchor-ready" —
the format doesn't need to know which anchor mechanism wins before it
can be built.

## 6. Recommended first implementation

Scoped to be buildable as one reviewable pass, with **no anchor
mechanism included**:

1. Add `release_packet.json` to `job_bundle`'s zip (`service/app/main.py`) —
   a sixth file alongside the existing five, built from data the route
   already has in hand (matter, job, doc, the certificate/manifest
   content already being assembled).
2. `tools/counselclear_verify_release_packet.py` — the CLI verifier
   from §4, steps 1–4, including the always-shown "NOT EXTERNALLY
   ANCHORED" notice.
3. `anchor.type: "none"` shipped and left that way — this pass is the
   spec and the verifier, not an anchor. A real anchor is a separate,
   later proposal once this spec exists to attach to.
4. Tests: a fixture packet with all hashes correct (verifier reports
   clean); a fixture with one file's bytes altered post-hash (verifier
   reports that specific mismatch and only that one); a fixture with
   internally-consistent-but-cross-mismatched ids (§4 step 3's check);
   confirmation the "not anchored" notice always appears when
   `anchor.type == "none"`.

## 7. Forbidden claims until anchoring ships

None of the following may appear in `release_packet.json`, the
verifier's output, `certificate.html`, `README.txt`, or any other
generated artifact until an anchor from §5 is actually implemented and
load-bearing:

- **"Unforgeable"**
- **"Independently timestamped"**
- **"Court-proof"**
- **"Unimpeachable"**

This list is consistent with, and specifically sharpens for this new
surface, `docs/release-control-evidence-thesis.md` §6's existing list
(which reads "independently verifiable" where this one reads
"independently timestamped" — both point at the same gap: the *hash*
checks are independently *recomputable* today, but nothing is
independently *timestamped* or verifiable *without trusting the issuer*
yet). Honest language that remains available: *"hashes verified
internally consistent; this packet is not externally anchored."*
