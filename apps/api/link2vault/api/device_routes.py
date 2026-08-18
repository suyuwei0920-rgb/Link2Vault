"""Device enrollment and administration routes."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field

from link2vault.api.dependencies import get_enrollment_service, require_device
from link2vault.domain.devices import DeviceIdentity
from link2vault.security.tokens import EnrollmentService

router = APIRouter()


class EnrollmentCodeRequest(BaseModel):
    """Administrator request for a short-lived code."""

    name: str = Field(min_length=1, max_length=100)


class EnrollmentExchangeRequest(BaseModel):
    """Device request to exchange a one-time code."""

    code: str = Field(min_length=1, max_length=128)


class DeviceResponse(BaseModel):
    """Credential-free device representation."""

    id: str
    name: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None

    @classmethod
    def from_identity(cls, device: DeviceIdentity) -> DeviceResponse:
        return cls(**device.__dict__)


@router.post("/admin/enrollment-codes")
def create_enrollment_code(
    body: EnrollmentCodeRequest,
    service: Annotated[EnrollmentService, Depends(get_enrollment_service)],
) -> dict[str, str]:
    """Issue one administrator-created enrollment code."""

    enrollment = service.issue_code(body.name)
    return {
        "code": enrollment.code,
        "device_name": enrollment.device_name,
        "expires_at": enrollment.expires_at.isoformat(),
    }


@router.post("/ingest/enroll")
def exchange_enrollment_code(
    body: EnrollmentExchangeRequest,
    service: Annotated[EnrollmentService, Depends(get_enrollment_service)],
) -> dict[str, object]:
    """Exchange a one-time code for a device bearer token."""

    try:
        issued = service.exchange(body.code)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_ENROLLMENT", "message": "Enrollment failed"},
        ) from exc
    return {
        "device": DeviceResponse.from_identity(issued.device).model_dump(mode="json"),
        "token": issued.token,
    }


@router.get("/ingest/device", response_model=DeviceResponse)
def current_device(
    device: Annotated[DeviceIdentity, Depends(require_device)],
) -> DeviceResponse:
    """Return the authenticated device without secret material."""

    return DeviceResponse.from_identity(device)


@router.get("/admin/devices", response_model=list[DeviceResponse])
def list_devices(
    service: Annotated[EnrollmentService, Depends(get_enrollment_service)],
) -> list[DeviceResponse]:
    """List enrolled devices."""

    return [DeviceResponse.from_identity(device) for device in service.list_devices()]


@router.delete("/admin/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_device(
    device_id: str,
    service: Annotated[EnrollmentService, Depends(get_enrollment_service)],
) -> Response:
    """Revoke one enrolled device."""

    try:
        service.revoke(device_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
