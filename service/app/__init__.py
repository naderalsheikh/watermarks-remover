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

In-process execution is acceptable at this profile by design; workers,
OIDC and Postgres arrive with the production profile.
"""

from .main import create_app

__all__ = ["create_app"]
