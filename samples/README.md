# samples/ — synthetic evaluation documents

This directory holds **synthetic, entirely fictional** documents used to
demonstrate CounselClear during an evaluation (see `../QUICKSTART.md`). They
exist so a reviewer can watch the airlock produce a real, evidence-bound
finding without ever touching real client data.

## What belongs here

- **Only synthetic content.** No real client names, matters, privileged text,
  or personal data — ever. Anything committed here is world-readable in the
  repository.
- **Documents that carry deliberate, known test artifacts** the engine will
  detect and report — for example: hidden/invisible Unicode (zero-width
  characters), author/producer metadata, tracked changes, comments, hidden
  worksheets, or embedded object metadata. Each artifact should be documented
  so an evaluator knows exactly what to look for in the findings report.
- Small files. These are demonstrations, not a benchmark corpus. Larger
  research corpora live under `benchmarks/` (outside the commercial surface).

## What does NOT belong here

- Real documents of any kind.
- Files whose expected outcome is undocumented — a sample nobody can predict
  the finding for teaches an evaluator nothing.

## Current samples

| File | Deliberate test artifacts | Expected in the findings report |
|---|---|---|
| `synthetic_engagement_letter.txt` | A zero-width space (U+200B) embedded between two words; an inline author/firm metadata marker in the body text. | The Unicode-hygiene check should surface the zero-width character; the author/firm marker is visible text a reviewer can confirm the report accounts for. |

CounselClear reports each artifact with evidence-bound language — *"Stripped
under policy X"*, *"Kept because reason Y"*, *"Out of scope for this policy"* —
never a blanket "clean" or "all watermarks removed" claim.
