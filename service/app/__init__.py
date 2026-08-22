"""CounselClear product control plane (PR 15, Phase 2).

Single-tenant FastAPI app over the engine MVP library:

- matter-scoped /v1 routes only; UUID opacity is not an ACL, so every job
  path nests under its matter
- local argon2 auth: session cookie backed by a 0600 hash file
- originals are stored write-once via custody.write_once at upload time;
  derivatives come from engine_api.clean_to_bundle (plan -> apply ->
  verify -> write-once) so a failed gate produces nothing
- download bundles contain derivative + reports + manifest by default;
  the original rides along only behind an explicit opt-in flag (audited)
- malware scanning is an interface with an honest stub implementation

Jobs never execute in the API process (PR 17): the runner spawns a
one-shot worker subprocess per job, or a hardened digest-pinned container
in docker mode (--network none, read-only rootfs, tmpfs, no caps).
"""

# Engine library (service/scripts) must be importable in EVERY process that
# touches this package — API, uvicorn/asgi and the per-job worker child,
# which starts with only service/ on sys.path. This must run before any
# submodule imports custody/engine_api.
import sys as _sys
from pathlib import Path as _Path

_SCRIPTS = _Path(__file__).resolve().parents[1] / "scripts"
if str(_SCRIPTS) not in _sys.path:
    _sys.path.insert(0, str(_SCRIPTS))

from .main import create_app  # noqa: E402

__all__ = ["create_app"]
