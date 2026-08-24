"""ASGI entrypoint for running cc-api outside Docker: `uvicorn app_launcher:app`.

app.main.create_app() is a factory, not a module-level `app`, so uvicorn's
`module:app` invocation needs this one-line wrapper somewhere on sys.path.
"""

from app.main import create_app

app = create_app()
