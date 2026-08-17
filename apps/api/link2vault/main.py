"""FastAPI application factory."""

from fastapi import FastAPI

from link2vault import __version__
from link2vault.config import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the Link2Vault HTTP application."""
    resolved = settings or Settings()
    app = FastAPI(title=resolved.app_name, version=__version__)

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
