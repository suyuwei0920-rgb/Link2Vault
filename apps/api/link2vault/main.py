"""FastAPI application factory."""

from fastapi import FastAPI

from link2vault import __version__
from link2vault.api.admin_session_routes import router as admin_session_router
from link2vault.api.device_routes import router as device_router
from link2vault.api.ingest_routes import router as ingest_router
from link2vault.api.task_routes import router as task_router
from link2vault.config import Settings
from link2vault.security.admin import AdminCsrfMiddleware, AdminSecurity
from link2vault.security.tokens import EnrollmentService
from link2vault.storage.device_repository import DeviceRepository
from link2vault.storage.quota_repository import QuotaRepository
from link2vault.storage.task_repository import TaskRepository


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the Link2Vault HTTP application."""
    resolved = settings or Settings()
    app = FastAPI(title=resolved.app_name, version=__version__)
    app.state.settings = resolved
    app.state.task_repository = TaskRepository(resolved.data_dir)
    app.state.quota_repository = QuotaRepository(resolved.data_dir)
    device_repository = DeviceRepository(resolved.data_dir)
    app.state.enrollment_service = EnrollmentService(
        device_repository,
        pepper=resolved.token_pepper.get_secret_value().encode("utf-8"),
    )
    app.state.admin_security = AdminSecurity(
        resolved.public_base_url,
        resolved.csrf_signing_key.get_secret_value().encode("utf-8"),
    )
    app.add_middleware(AdminCsrfMiddleware, security=app.state.admin_security)
    app.include_router(admin_session_router)
    app.include_router(device_router)
    app.include_router(ingest_router)
    app.include_router(task_router)

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app
