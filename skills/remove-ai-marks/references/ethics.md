# Intended use

This skill removes machine-readable provenance marks and hygiene problems from content **you own or are authorized to process**.

## Appropriate

- Privacy: strip tool/device/AI provenance from your own files before sharing
- Engineering hygiene: remove invisible Unicode that breaks diffs, search, or paste
- Research: understand how text and C2PA marks work across vendors
- Cleaning your own drafts where policy allows unmarked local copies

## Not appropriate

- Academic fraud or misrepresenting AI assistance where disclosure is required
- Circumventing lawful transparency or platform disclosure rules
- Claiming cleaned content is “human-written” for compliance theater

A removed mark does **not** mean the content was never AI-assisted. Use this toolkit honestly.

## Documents received from a counterparty (`counselclear intake`)

Everything above is about content *you* produce and send. `counselclear intake`
is the inverse case: read-only inspection of files someone else sent *you* —
an opposing-counsel production, a deal-room upload, a vendor submission —
within an engagement you're actually on. This is standard due-diligence
practice (equivalent to opening a received Word document and checking File →
Info, or running Document Inspector on it) made systematic across a whole
production instead of one file at a time. It never cleans or modifies
anything; it only reports what's already embedded in files you legitimately
hold a copy of.

**Appropriate**

- Due diligence: checking a production or submission for leaked privilege,
  internal deliberation, or negotiating-position tells the sender didn't mean
  to share (stray tracked changes, comments, hidden sheets/slides)
- Provenance/authenticity checks on files received as part of a matter you're
  engaged on (who actually drafted this, does the metadata match who it was
  represented to be from)
- Verifying your own outbound productions didn't leak anything, from the
  recipient's likely vantage point

**Not appropriate**

- Analyzing files you obtained outside the scope of an actual engagement, or
  that you are not authorized to hold or process at all
- Circumventing a legal hold, protective order, or an explicit confidentiality
  restriction that governs how the files may be used
- Compiling extracted identities across matters, or any use beyond the matter
  the files were produced for
- Republishing or forwarding extracted personal information (names, GPS
  coordinates, contact details) for any purpose other than the matter itself

**How access is limited:** the command refuses to run without an explicit
`--i-am-authorized` flag (the same pattern as `--attest` for breaking a
digital signature) — there is no default/implicit path into this feature.
Real identity values (author/company names, not just "present") stay
redacted unless `--reveal-identities` is *also* passed explicitly; the
default report shows only counts and categories, matching the same
"categories only" posture the rest of the product uses for its own audit
logs. Both flags are per-invocation, not a standing setting.

As with removal, a finding here is informational, not proof of anything —
metadata can be wrong, stale, or attributable to a template rather than a
person. Treat it as a lead to verify, not a conclusion to act on directly.

## Honesty in reports

Always separate:

1. **Verifiable** removals (Unicode counts, metadata actions)
2. **Best-effort** statistical rewrite (no gold undetection claim)
3. **Optional / out-of-scope** channels (optional external pixel removal via CtrlRegen; audio/video watermarks, **C2PA soft binding**, secret-key detectors, and training backdoors are out of scope)

Do not imply that a successful C2PA/metadata strip means “no AI provenance left.” Soft-bound and SynthID-class media signals can survive. Point users at vendor verify tools when they need residual checks (see README *Residual risk after a clean*).

## Responsible use and liability

This project aims to help users understand and remove AI provenance marks from content they own or are authorized to process. Users are free to leverage this toolkit for privacy, engineering hygiene, and research — including evaluating and improving watermark robustness — however, they must adhere to local regulations and use it responsibly. The developers disclaim any liability for potential misuse by users.
