"""Administrator browser session bootstrap."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response

from link2vault.security.admin import (
    CSRF_COOKIE_NAME,
    CSRF_MAX_AGE_SECONDS,
    AdminSecurity,
)

router = APIRouter()


@router.get("/admin/session")
def create_admin_session(request: Request, response: Response) -> dict[str, object]:
    """Set and return a signed double-submit token without credentials."""

    security: AdminSecurity = request.app.state.admin_security
    token = security.issue_token()
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=CSRF_MAX_AGE_SECONDS,
        secure=True,
        httponly=False,
        samesite="strict",
        path="/admin",
    )
    return {
        "csrf_token": token,
        "expires_in_seconds": CSRF_MAX_AGE_SECONDS,
    }
