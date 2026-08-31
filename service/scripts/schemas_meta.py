"""Published-schema registry for CounselClear custody artifacts (PR 63).

Every custody artifact embeds two fields tying it to the published
contract it was built against:

- ``schema_version`` -- the version named in the schema file's own
  ``version`` field, so a reader can tell WHICH published contract
  without fetching anything.
- ``schema_sha256`` -- sha256 of the published schema FILE's bytes.
  A verifier that ships the same schema files recomputes this hash and
  fails loudly on a mismatch, so a bundle built against a modified
  contract can never re-hash clean against the published one.

Both are computed here, once, from the files in ``schemas/`` -- the
single source of truth, never a hardcoded digest in an emitter that can
drift from the file it claims to describe. Stdlib-only by design: the
offline verifier and the app both import this, and neither may gain a
dependency from it.

Hashing the file BYTES (not a re-serialization of the parsed JSON) is
the contract: the published artifact IS the file, and two JSON
serializations of the same schema can differ in whitespace/key order --
hashing anything else would let a republished-but-equivalent schema
file fail a bundle that was honestly built against its bytes, and
would punish the formatting, not the content.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"

# artifact name -> the published schema file describing it. The three
# custody artifacts this pass pins; release_result.json deliberately
# not pinned here (its emitter, _build_release_result, follows the same
# pattern -- see PR 63's scope: this registry grows one entry at a time
# as artifacts adopt it).
ARTIFACT_SCHEMAS = {
    "manifest": "manifest.schema.json",
    "report": "report.schema.json",
    "release_packet": "release_packet.schema.json",
}


def schema_version_of(schema_name: str) -> int:
    """The schema file's own ``version`` field -- a schema author bumps
    this when the contract changes, so the artifact's declared
    schema_version is the schema's own claim about itself, not a number
    an emitter made up."""
    doc = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    return int(doc["version"])


def schema_sha256_of(schema_name: str) -> str:
    return hashlib.sha256((SCHEMA_DIR / schema_name).read_bytes()).hexdigest()


SCHEMA_VERSION = {name: schema_version_of(fname) for name, fname in ARTIFACT_SCHEMAS.items()}
SCHEMA_SHA256 = {name: schema_sha256_of(fname) for name, fname in ARTIFACT_SCHEMAS.items()}
