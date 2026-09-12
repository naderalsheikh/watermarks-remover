# Document organization

The server groups independent uploaded documents within a matter. This increment
adds client name, matter number, active/closed status, document categories, and
explicit links between revisions. These are organization metadata, not custody
facts or a replacement for a document management system.

Matter administrators can edit client name, matter number and status through
**Edit matter details**. Closing a matter is reversible: choose Active to reopen.
It does not change permissions, cancel jobs, prevent new work, alter retention,
or remove the matter from audit/dashboard totals. The list can filter active,
closed or all matters, and searches name/client/number across all readable matters.
Client name is a text label, not a separate client entity; matter numbers are not
unique identifiers. The server's existing matter IDs remain authoritative.

Within a matter, **Category and revisions** shows a document's relationships.
Administrators can set a category and select an earlier upload from a paginated,
server-searched list. Categories are free text (80 characters), trimmed and
case-sensitive; an empty value means Uncategorized. Category filtering runs on
the server across the full matter. Job-status filters retain their existing
loaded-history scope. A link opened from revision history targets that document
even if it would otherwise be beyond the first page; Show all documents returns
to the full list.

A revision link is an operator assertion, not automatic content comparison.
Each document can name one earlier revision; multiple later uploads can link to
it. The server rejects self-links, cycles, missing documents and cross-matter
links. Links may be corrected or removed by an administrator, with an audit event.
No version number, latest-version claim, or automatic release inheritance is
assigned. Uploading the same filename again still creates a separate document.

Organization writes require both read and admin permissions, lock the matter
while validating links, and use an expected metadata version to reject stale
edits with HTTP 409. Reload the page before reviewing/retrying a conflicting
edit. No-op saves do not add audit events. Successful changes and their audit
records commit together. Existing original bytes, hashes, paths, jobs, release
records, and preserved certificates are unchanged.

## API

- POST /v1/matters accepts optional client_name and matter_number.
- GET /v1/matters accepts q (name/client/number) and status (active/closed).
- PUT /v1/matters/{id}/organization accepts client_name, matter_number,
  status and expected_version.
- GET /v1/matters/{id}/documents accepts category (empty = Uncategorized)
  and document_id, in addition to existing search/pagination.
- GET /v1/matters/{id}/document-categories returns the matter's distinct categories.
- PUT /v1/matters/{id}/documents/{doc}/organization accepts category,
  previous_revision_id (null to unlink) and expected_version.
- GET /v1/matters/{id}/documents/{doc}/revisions returns the earlier document
  and a paginated list of immediate later linked uploads.

Matter and document responses include organization_version. The PUT operations
only affect the organization fields above; they do not rename files or matters.

## Upgrade and recovery

Migration 0018 follows 0017. Existing matters become active with empty client
and matter-number labels. Existing documents are uncategorized and unlinked.
No content or released evidence is rewritten. Upgrade the API and UI together.
The backup/restore tooling preserves the additional database metadata; no
filesystem paths need changing for these fields. Downgrading below 0018 discards
organization fields and revision links. Preserve a backup and do not treat that
downgrade as a lossless rollback.
