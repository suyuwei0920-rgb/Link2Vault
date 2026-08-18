"""FastAPI authentication dependencies."""

from __future__ import annotations

from typing import Annotated

from fastapi import Header, HTTPException, Request, status

from link2vault.domain.devices import DeviceIdentity
from link2vault.security.tokens import EnrollmentService

_UNAUTHORIZED = {
    "code": "UNAUTHORIZED",
    "message": "Device authorization failed",
}


def get_enrollment_service(request: Request) -> EnrollmentService:
    """Load the application-scoped enrollment service."""

    return request.app.state.enrollment_service


def require_device(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> DeviceIdentity:
    """Authenticate only an Authorization bearer header."""

    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=_UNAUTHORIZED)
    token = authorization.removeprefix("Bearer ")
    try:
        return get_enrollment_service(request).verify(token)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_UNAUTHORIZED,
        ) from exc
