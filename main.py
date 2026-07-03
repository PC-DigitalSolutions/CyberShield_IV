"""Deployment entrypoint shim.

Some hosts (Render's native Python builder, etc.) auto-generate the start
command `uvicorn main:app`, expecting a top-level `main` module. The real
application lives at `src.api.main`. Re-export it here so that entrypoint —
and our Dockerfile's `uvicorn src.api.main:app` — both work.
"""

from src.api.main import app  # noqa: F401
