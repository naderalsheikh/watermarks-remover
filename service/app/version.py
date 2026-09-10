"""Single source of truth for the running product version.

Kept in its own module (not app/__init__.py) so both the FastAPI app and
health/version endpoints can import it without risking an import cycle with
app.main (which app/__init__ imports at load time)."""

from __future__ import annotations

__all__ = ["PRODUCT", "__version__"]

# Product marketing/display name and semantic version surfaced by /health and
# /version. Bump on each pilot release so operators and health probes can pin
# exactly which build is live.
PRODUCT = "CounselClear"
__version__ = "1.0.0"
