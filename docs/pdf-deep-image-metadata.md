# PDF deep-image metadata — design note

## Status (2026-08-25): detection + byte-preserving removal landed; Ghostscript rejected

**Landed:** `embedded_image_metadata_present`, `embedded_provenance_present`,
`_iter_pdf_image_xobject_spans`/`_iter_pdf_image_xobjects`, and
`pdf_deep_image_scan` (`service/scripts/container_meta.py`) — byte-level
JPEG-marker detection of embedded EXIF/APPn metadata and C2PA/JUMBF
provenance inside PDF image XObjects. Wired into both `inspect_pdf` (as
findings) and `clean_pdf` (as a `deep_images` manifest field).

**Removal also landed**, via the byte-preserving approach outlined below
rather than Ghostscript: `_strip_jpeg_appn` splices the identified APPn
segments directly out of the extracted JPEG stream (SOS-through-EOI scan
data copied verbatim, never decoded); `strip_pdf_image_metadata` locates
every DCTDecode image XObject with a direct `/Length` (`_pdf_direct_length`
— an indirect `/Length N G R` is skipped rather than guessed at, and in
practice this rarely triggers once qpdf has run: qpdf's own structural
rewrite normalizes indirect references to direct integers as a side
effect, confirmed by hand), applies the strip, and patches `/Length`;
`clean_pdf` runs it and follows with the existing `_pdf_structural_rewrite`
(qpdf) to fix up xref offsets, the same rule the stdlib XMP-strip fallback
already follows for any byte-range mutation. Proven, not just argued: a
regression test strips a real (Ghostscript-generated, baked into the test
file) JPEG's embedded C2PA marker through a full `clean_pdf` round trip —
exiftool pass, qpdf rewrite, the strip, a second qpdf rebuild — and asserts
the SOS-to-EOI scan data is **byte-identical** before and after. That's the
evidence the Ghostscript approach below could never have produced even if
it had worked.

**Reporting was landed separately, and mattered**: the strip runs for real
on every PDF sanitize job via `policies._apply_pdf` (confirmed by reading
the call chain, not assumed) — but two gaps meant nobody could see it happen:
`findings_from_container_report`'s dispatch is a strict prefix match with
no fallback, so `inspect_pdf`'s two new finding strings had no matching
prefix and were silently dropped before ever reaching `job.result.findings`
(now fixed: `embedded_image_metadata`/`embedded_image_provenance` are their
own structured `Finding` subtypes, distinct from the generic
`has_c2pa`-driven "Content Credentials manifest present" finding, since only
the embedded-image case carries the indirect-`/Length` caveat). Separately,
`_apply_pdf` filtered `clean_pdf`'s returned `meta` dict down to
`{mode, structural_rewrite, info_clear}` before building the sanitize
manifest's `actions` — `deep_images` was dropped there too, so a real
sanitize job's manifest never said anything happened to the image even
though it had (now fixed: an `embedded_image_metadata` `ActionRecord` is
added when a strip ran, or flags the indirect-`/Length` case when one
didn't). Verified through `clean_to_bundle` itself, not `_apply_pdf` in
isolation — a regression test asserts the actual manifest `actions` list.

**A precise, verified nuance on the indirect-`/Length` skip's reachability**:
for `external_sharing`/`production` (`policies._PDF_STRICT_TOOLING_
POLICIES`), the skip is unreachable through a real sanitize job. Both
policies hard-require `clean_pdf`'s `structural_rewrite` (qpdf
`--linearize`) to have succeeded before the job is allowed to complete — and
that same rewrite is exactly what normalizes an indirect `/Length` to
direct as a side effect, confirmed above. So by the time a strict-policy
job could reach the strip step, there's no indirect reference left to skip.
Confirmed by hand: simulating qpdf's absence for a strict policy doesn't
reach the "flag" case at all — the job fails closed with `CustodyError:
... tooling bar ...` before it gets that far, which is itself the correct,
existing, pre-this-work behavior (a strict-policy job must not ship a
derivative it couldn't fully verify). The skip path is real and unit-tested
(`test_clean_pdf_reports_indirect_length_images_honestly`), just only
actually reachable outside the two strict-tooling policies or when calling
`clean_pdf` directly.

**Known gap, not fixed, now disclosed rather than silently left implicit**:
`privacy_only`'s PDF path (`_exiftool_privacy_pdf`) is a separate,
narrower exiftool-only routine that never calls `clean_pdf` at all — a
`privacy_only` sanitize job on a PDF does not strip embedded-image
metadata today, even though the policy's own design intent (GPS-only
strip, not `strip_all_metadata`) suggests it plausibly should. Whether
that's the right call for `privacy_only` specifically is a policy-semantics
question, not a bug in this work — left for a deliberate decision, not
bundled into this pass.

What *was* fixed: the manifest used to say nothing about this at all —
`findings_before` would list the embedded-image finding but `actions`
never mentioned it, so a `privacy_only` derivative could look like a
complete privacy strip when GPS-bearing image metadata had actually
survived untouched inside it (confirmed live against the real API before
the fix: exactly that gap, on a real job). `_apply_pdf` now emits an
explicit `embedded_image_metadata: flag` record whenever this path
leaves real metadata behind — same subtype prefix the job page's
`EmbeddedImageNotice` already renders as "not cleared" for the
indirect-`/Length` case, so this reached the UI with no frontend change
at all. Proven, not just claimed: a regression test asserts the embedded
JPEG's scan data is byte-identical before and after (the "not stripped"
claim is actually true), that the disclosure record is present when
metadata is, and absent when it isn't
(`test_privacy_only_pdf_discloses_untouched_embedded_image_metadata`,
`test_privacy_only_pdf_without_embedded_image_metadata_has_no_flag`).

**Rejected: the Ghostscript re-encode pass.** It was built (seven
correctness points from the original design below all addressed —
symlink-safe temp path, single clean-wide budget, correct Downsample vs.
DownsampleType flag semantics verified against a real `gs` invocation,
`always` escalating on any metadata not just provenance) and then **not
shipped**, because it failed the one constraint that actually matters for
this product: **no visual degradation**.

What was found: with the corrected Ghostscript flags
(`-dDownsample*Images=false -dEncode*Images=false`, disabling both
downsampling and re-encoding), `gs -sDEVICE=pdfwrite` reliably **dropped the
embedded image entirely** from the output — not recompressed, not
downsampled, gone. Confirmed this wasn't a decode failure: a raster render
of the same input (`-sDEVICE=ppmraw`) proved Ghostscript's own interpreter
drew the image correctly (real non-white pixels present); `pdfwrite`'s PDF
*output* just didn't retain it as an XObject, with no error or warning.
Ruled out as causes: image size (tried 1×1 and 16×16), a `/Width`/`/Height`
mismatch against the JPEG's own SOF header (confirmed matching), and the
injected metadata marker itself (an untagged image with no marker at all
was dropped identically). Root cause not isolated, and no longer worth
isolating now that the byte-preserving approach ships instead — but if
Ghostscript involvement is ever revisited (e.g. for non-JPEG filters this
pass doesn't cover), the test matrix below is where to start.

**Known non-goal, unchanged:** non-JPEG image filters (JBIG2, CCITT fax)
aren't covered by either detection or removal.

**If Ghostscript involvement is ever reconsidered** (not currently
planned — the byte-preserving approach covers the JPEG/DCTDecode case this
design exists for), it should only ever be an explicit opt-in fallback, not
the default legal-preservation path, and only after a proper test matrix:
take a real scanned PDF (not a synthetic fixture) with a JPEG XObject
carrying real EXIF/XMP/C2PA, run the candidate rewrite, and compare —
rendered page before/after, page count, content-stream presence, image
XObject count before/after, extracted image dimensions before/after, and
whether image bytes were actually recompressed (byte-identical scan data is
the strongest check, not merely "visually similar"). Repeat across more
than one Ghostscript version if practical. No such mode ships without
passing that gate.

Whichever direction, this needs its own design note before implementation —
this file's original design (below) is retained for the detection work it
correctly specified, not as a green light for the removal pass.

---

## Original design (2026-08-25) — detection as specified; removal shipped via
## the byte-preserving approach described in the Status section above, not
## the Ghostscript pass this section originally proposed

## Problem

`clean_pdf` (`service/scripts/container_meta.py:3134`) strips document-level
metadata — the `/Info` dictionary and the XMP packet — via `exiftool -all=`
plus a structural rewrite that drops the now-unreferenced objects
(`_pdf_structural_rewrite`, `_pdf_info_clear`). None of that touches image
XObjects: a PDF page that *is* a scanned or photographed JPEG keeps every
byte of that JPEG's own EXIF, GPS, thumbnail, and any C2PA manifest attached
to it, after a clean that reports success. For a legal-sanitization product
this is a real leak, not a cosmetic gap — camera GPS and author identity are
exactly the categories `privacy_only`/`external_sharing` exist to remove.

There is currently no code path in `container_meta.py` that walks JPEG
segment headers inside a PDF's image streams. `image_meta.py` has a
fill-byte-aware JPEG walker (`inspect_jpeg`) for *standalone* JPEG files, but
nothing reuses it against bytes extracted from inside a PDF.

Ghostscript is not in our toolchain today — not in any `service/Dockerfile*`,
not referenced anywhere in `service/scripts/`. Adding this capability means
adding a new binary dependency to the worker image.

## What upstream's version got right (and wrong first)

Upstream implemented this as a `deep_images` pass across five commits
(`42c6c8f` + four review-round fixes) that we evaluated during the cherry-pick
attempt but never merged (the merge itself corrupted `container_meta.py`
twice — see the 2026-08-24 incident notes; the *feature* was never actually
at fault). Reading all five commits end to end, the review rounds found real
bugs worth avoiding from the start rather than rediscovering:

1. **A `deep_images="always"` mode that doesn't actually always clear
   metadata.** It only escalated to a re-encode when an AI/C2PA marker
   survived — ordinary camera EXIF set no such signal, so a file Ghostscript
   copied byte-for-byte kept its EXIF under a mode that promised to remove
   it. Fix: escalate on *any* APPn metadata marker in `always` mode, not just
   provenance markers.
2. **APP0 (JFIF) and APP2 (ICC) are not metadata** — they're structural
   (JFIF header) and functional (how colors are decoded). A detector that
   treats every APPn marker as strippable metadata will corrupt color
   rendering or break the JFIF header. Exclude both explicitly.
3. **A predictable Ghostscript output path is a symlink-attack vector** — a
   local attacker with write access to the temp directory can pre-place a
   symlink at a guessable path and redirect the write. The output path must
   be unpredictable (random suffix or a proper `tempfile` primitive), matching
   the no-symlink contract the rest of custody/write-once code already holds
   itself to.
4. **Per-tool timeouts compound.** One PDF can trigger two Ghostscript passes
   plus multiple exiftool/qpdf calls; left to independent timeouts that's
   minutes on a request thread, and `/clean/batch` pays it once per file.
   Fix: one deadline spanning the whole clean, each subprocess call gets
   whatever budget remains, capped by its own ceiling.
5. **Tool-presence gating must be independent per tool, and must not
   double-report.** The deep-image pass needs Ghostscript; the document-level
   strip needs exiftool. A machine with one but not the other must run
   whichever passes it can, name its actual mode accurately (`exiftool` /
   `stdlib-xmp` / `copy`), and never emit "install ghostscript" twice for a
   rung that plainly can't run.
6. **Provenance detection must read the PDF's raw bytes directly**, not go
   through `inspect_pdf`'s marker scan — that scan drops stream payloads
   before looking, so a C2PA manifest living only inside a JPEG XObject
   registers as absent. `auto` mode's whole justification is catching exactly
   this case.
7. **Byte-range deletion without a following rebuild produces an unparseable
   file.** The stdlib XMP-strip fallback (no exiftool) deletes bytes in
   place, which shifts every xref offset and stream `/Length` after the cut.
   That's tolerable only when something rebuilds the file afterward; if nothing
   does (e.g. `deep_images="never"` short-circuits it), the file must be
   rebuilt some other way before it's handed back, not returned broken.

None of these are exotic — they're the kind of thing a first pass reliably
misses and a security-focused review reliably catches four commits later.
Building them in from the start is the actual value of "read upstream, don't
port upstream."

## Proposed scope

A `deep_images` parameter on `clean_pdf`, mirroring the shape upstream
settled on but implemented against our current functions and our existing
`custody`/write-once conventions, not theirs:

- **Detection, two new byte-level helpers in `container_meta.py`** (walking
  raw PDF bytes for JPEG XObject stream markers, no decode, no external
  tool — reuse the marker-walking approach already proven in
  `image_meta.py:inspect_jpeg`, generalized to operate on an extracted
  stream buffer rather than a whole-file path):
  - `embedded_image_metadata_present(data) -> bool` — any APPn marker except
    APP0/APP2.
  - `embedded_provenance_present(data) -> bool` — JUMBF or a provenance XMP
    packet specifically in APP1/APP11, distinct from ordinary EXIF.
- **Modes**, matching the operator-facing knob CounselClear's policy engine
  would set: `auto` (re-encode only if provenance or the `always` criteria
  match), `always` (escalate on any APPn metadata per point 1 above),
  `never`/`lossless` (detect and report for the manifest/findings, never
  re-encode).
- **The re-encode itself**: Ghostscript pdfwrite, output to an unpredictable
  path (point 3), inside the existing PDF clean budget rather than its own
  timeout (point 4) — reuse or extend whatever budget mechanism
  `_pdf_structural_rewrite`/`_pdf_info_clear` already coordinate under, add
  one if none currently spans the whole `clean_pdf` call.
- **Runs independent of exiftool's presence** (point 5): the deep-image pass
  is gated on Ghostscript alone; `clean_pdf`'s existing exiftool-present /
  degraded-stdlib branches both call into it afterward.
- **Manifest fields**: `layer_deep_images: {mode, ran, escalated, findings}`
  or similar — exact shape to match `emit_manifest`'s existing conventions,
  not upstream's.

## New dependency: Ghostscript

Needs adding to `service/Dockerfile.counselclear`'s worker image (the
isolated per-job container per PR 17 — this only ever runs on already-scoped,
already-sandboxed job input, same trust boundary as exiftool/qpdf today) and
to CI's tool-availability checks. Version-pin it the same way qpdf/exiftool
already are. Not a change to the always-on API process's dependencies.

## Test plan

- Fixture: a PDF whose single page is a JPEG XObject carrying EXIF GPS tags
  and a synthetic C2PA/JUMBF marker in APP11.
- `auto` mode detects the provenance marker and escalates; verify GPS and
  the C2PA marker are both gone post-clean.
- `always` mode on a fixture with only ordinary camera EXIF (no provenance)
  still escalates and clears it (point 1's regression).
- A fixture with an ICC profile (APP2) round-trips with color rendering
  intact — i.e. the profile is *not* treated as strippable metadata (point 2).
- No-Ghostscript environment: deep pass reports unavailable once, does not
  duplicate the warning, document-level strip still succeeds via whichever
  path is available (point 5).
- Budget test: a deliberately slow/huge fixture is capped by the single
  clean-wide deadline, not the sum of per-tool timeouts (point 4).
- Symlink test: pre-place a symlink at the naively-predictable output path,
  confirm the actual write target is unpredictable and the symlink is
  untouched (point 3).

## Non-goals

- Non-JPEG image XObjects (JBIG2, CCITT fax) — out of scope for v1 of this
  capability; flag as a finding, don't attempt to clean.
- Anything beyond PDF — this is specific to `clean_pdf`'s image-XObject gap.

## Effort estimate

Medium: the detection helpers are small and mechanical (JPEG segment walking
is already a solved problem in this codebase); the correctness work is in
getting the seven points above right the first time, plus the new Docker
dependency and its CI/tool-presence plumbing. A reasonable single well-scoped
implementation task, suitable for dispatch once this note is agreed — not
something to split further.
