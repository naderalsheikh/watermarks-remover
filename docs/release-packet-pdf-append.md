# Design note: appending a certificate page to PDF derivatives

Evaluated during PR 36 (release packet). **Not implemented this pass** —
recommendation is to leave `certificate.html` as a sibling file for every
derivative format, PDF included, rather than appending a rendered
certificate page onto PDF derivatives specifically.

## The idea

For a PDF derivative specifically (not docx/xlsx/pptx/images/text — those
have no comparable "just add a page" operation), append a final page
rendering the certificate's content (hashes, policy, verification,
limitations) directly into the derivative PDF, so the proof travels
inside the file a recipient actually opens, not just alongside it.

## Why not, for now

1. **Byte-preservation/provenance risk.** `verify_derivative`'s
   `reinspect_targeted_gone` and `no_new_identity_findings` checks
   (`service/scripts/verify.py`) inspect the *whole* derivative file,
   including page count and structure, against what sanitize actually
   targeted. Appending a page after verification would either need to
   run before the append (verifying a file the recipient never receives)
   or after it (verifying a file this feature just structurally changed,
   risking a false positive/negative on checks that were written for
   "sanitize changed nothing outside what it targeted"). Getting this
   right needs verify.py-level design work, not a bolt-on.
2. **New rendering dependency.** Producing a real PDF page (not just
   raw content-stream bytes) from certificate content — text layout,
   pagination for long limitation lists, table structure — realistically
   needs a PDF-writing dependency (e.g. `reportlab`, `weasyprint`, or a
   `qpdf`/raw-content-stream hand-roll for anything beyond trivial
   fixed-layout text). The engine currently has zero such dependencies;
   `docs/counselclear-strategy.md` point 4 already flags "no PDF
   rendering dependency" as a boundary worth protecting deliberately,
   not something to cross for a UX nicety.
3. **The claim it would make.** An appended page inside the PDF a
   recipient opens directly could easily be read as "the proof is part
   of the document," when the actual guarantee is "the proof is a
   separate, independently-hash-verifiable record of what happened to
   the document." Keeping certificate.html a sibling file keeps that
   distinction honest by construction — doctrine point 5 (evidence-bound
   claims) applies to what the *packaging* implies, not only to prose.
4. **PDF-only.** Every other derivative format has no equivalent
   operation, so this would be a special case for one format, not a
   release-packet-wide improvement — the sibling-file model already
   treats every format identically.

## If revisited later

A future pass could scope this much more narrowly: a fixed-layout,
single "certificate summary" page (no long limitation lists, no
dynamic pagination) using raw PDF content-stream construction (the
codebase already does adjacent low-level PDF structural work in
`container_meta.py`'s `clean_pdf`/`_pdf_structural_rewrite` — no new
rendering library, just more careful PDF object construction), appended
*after* `verify_derivative` runs against the un-appended file, with an
explicit `verification.certificate_page_appended: true` manifest field
so the audit trail is honest about a post-verification structural
change. That's real design work with its own tradeoffs, not something
to fold into this pass.
