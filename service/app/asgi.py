"""Module-level ASGI app for uvicorn / compose (single-tenant profile).

Requires COUNSELCLEAR_LOCAL_PASSWORD (and optionally COUNSELCLEAR_DATA_ROOT)
in the environment; see compose.yaml ``legal`` profile.
"""

from .main import create_app

app = create_app()
