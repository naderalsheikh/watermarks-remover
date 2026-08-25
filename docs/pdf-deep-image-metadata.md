# PDF deep-image metadata — design note

## Status (2026-08-25): detection landed, removal deliberately not implemented

**Landed:** `embedded_image_metadata_present`, `embedded_provenance_present`,
`_iter_pdf_image_xobjects`, and `pdf_deep_image_scan` (`service/scripts/container_meta.py`) —
byte-level JPEG-marker detection of embedded EXIF/APPn metadata and C2PA/JUMBF
provenance inside PDF image XObjects. Wired into both `inspect_pdf` (as
findings) and `clean_pdf` (as a `deep_images` manifest field). No removal —
every path reports what it finds and changes nothing about the image.

**Deliberately not implemented: the Ghostscript re-encode pass.** It was
built (seven correctness points from the original design below all
addressed — symlink-safe temp path, single clean-wide budget, correct
Downsample vs. DownsampleType flag semantics verified against a real `gs`
invocation, `always` escalating on any metadata not just provenance) and
then **not shipped**, because it failed the one constraint that actually
matters for this product: **no visual degradation**.

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
was dropped identically). Root cause not isolated — could be specific to
small/synthetic test images and not affect real photographic scans, or
could be a more general `pdfwrite` behavior. For a legal-evidence product,
silently losing image content is a strictly worse failure than leaving
metadata in place, so this path does not ship while that's unresolved.

**Follow-up investigation, not started.** Two candidate directions, in
order of preference:

1. **Byte-preserving stream surgery, no re-render at all.**
   `_iter_pdf_image_xobjects` already extracts the exact raw JPEG stream;
   `_iter_jpeg_appn`'s marker walk already identifies each APPn segment's
   precise byte range. Removing metadata could mean splicing those ranges
   out of the stream directly — the same technique `_strip_id3v2`/
   `_drop_tag_blocks` already use elsewhere in this codebase for surgical
   byte-range removal — leaving the DCT-encoded scan data completely
   untouched, then re-inserting the shortened stream into the PDF and
   running the existing `_pdf_structural_rewrite` (qpdf) to fix up
   `/Length` and xref offsets. This gives a **by-construction** no-degradation
   guarantee (the pixel data is never decoded, never re-encoded — only
   well-formed header bytes before the scan segment are ever removed)
   instead of an after-the-fact "looks fine after raster render" check,
   which alone isn't sufficient evidence for an evidentiary tool.
2. **Ghostscript, but only as an explicit opt-in fallback**, not the default
   legal-preservation path, and only after a proper test matrix: take a
   real scanned PDF (not a synthetic fixture) with a JPEG XObject carrying
   real EXIF/XMP/C2PA, run the candidate rewrite, and compare — rendered
   page before/after, page count, content-stream presence, image XObject
   count before/after, extracted image dimensions before/after, and whether
   image bytes were actually recompressed (byte-identical scan data is the
   strongest check, not merely "visually similar"). Repeat across more than
   one Ghostscript version if practical. No cleaning mode ships without
   passing that gate.

Whichever direction, this needs its own design note before implementation —
this file's original design (below) is retained for the detection work it
correctly specified, not as a green light for the removal pass.

---

## Original design (2026-08-25, detection portion implemented as specified;
## removal portion superseded by the Status section above)

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
