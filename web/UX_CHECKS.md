# Matter workflow verification — 2026-09-07

This pass starts from `f6faae6`. It builds on the visible-selection work
already committed as `398a384`; that earlier work is not counted as new here.

## Changes

- Document search and status filters stay mounted during loading, errors,
  and empty results. Clear-search and reset-filter actions restore focus.
- Document-load failures offer retry and do not also claim the matter is empty.
- Selection and active batch controls remain available outside the results
  list. Counts include all selected IDs and disclose those outside the current
  view, including a different search or an unloaded page. Selection trimming
  and opening bulk actions are disabled while a search is pending.
- Each row links directly to its newest loaded result, using the same history
  order as its status. A later failure, refusal, or inspection takes precedence
  over an earlier successful release. No extra job is created by following it.
- Document names and action buttons wrap on narrow screens. Report links stay
  within their container. Changing the matter ID remounts its local form,
  search, batch, and selection state.
- Pagination rejects duplicate pending offsets and ignores callbacks from
  replaced queries, reloads, and unmounted lists. Network requests themselves
  are not aborted. A failed page remains retryable.

## Checks actually run

Commands run directly, with their exit statuses checked:

```sh
cd web
npm run lint
npm test
npm run build -- --webpack
```

Frontend lint passed. All **124 tests across 14 files** passed (15 new tests:
8 for result routing, 7 for request lifetimes). The static production build
passed using webpack, including TypeScript and static page generation. The
build and browser preview used a separate source copy with the same installed
dependencies to avoid another session's active Next development server. The
default Turbopack production build was not run.

Live browser checks used fictional documents in an isolated local API data
root, not a client matter. A temporary local forwarding proxy introduced only
the specified delay or failure:

| Scenario | Observed result |
| --- | --- |
| Search for a nonexistent filename | Before the fix, the search field disappeared. After it, the search remained editable and reset restored the documents. |
| Select a document, then search for no matches | Selection bar remained visible: 1 selected, 0 visible, 1 outside this view. Bulk confirmation disclosed the hidden selection. |
| Cancel bulk confirmation and keep only visible selections | Hidden selection cleared; no bulk job was submitted. |
| Open sample macro-enabled document's “Review refusal” link | Opened the existing refused release, showing no derivative and the policy refusal reason. |
| Phone viewport at 390 × 844 | Document names and action rows were readable; no horizontal page overflow. |
| Load page 2 of 55 documents; delay offset 50 by four seconds; search for one filename before it returns | New search showed one row. After the proxy recorded the old response as finished, the new search still showed exactly one row. |
| Return HTTP 503 for document search | Error and retry action appeared; no false “No documents match” message. Search stayed editable. |
| Restore the endpoint and click retry | Matching document returned and retry error disappeared. |
| Clear search and load the next page normally | 50 rows became 55 rows; no remaining load-more button. |

A second agent performed a read-only source review of the changes and found
no actionable regression. It did not independently execute these checks.

## Limits

Status and direct result links still reflect **loaded job history**, not
unloaded jobs; the existing pagination disclosure remains. This pass does not
alter sanitizer behavior, release guarantees, permissions, or verification
semantics. The full Python suite was not rerun, and the known backend flake and
other work in `docs/HANDOFF-2026-09-07-open-work.md` remain outside this pass.

The browser checks are recorded manual checks, not automated browser tests.
The pure request-lifetime and result-routing regressions run under Vitest.
