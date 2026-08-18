"""Device enrollment domain models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DeviceIdentity:
    """Public, non-secret device identity."""

    id: str
    name: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


@dataclass(frozen=True)
class EnrollmentCode:
    """Short-lived plaintext enrollment code returned only to an administrator."""

    code: str
    device_name: str
    expires_at: datetime


@dataclass(frozen=True)
class PlainDeviceToken:
    """Long-lived token returned only once during enrollment."""

    device: DeviceIdentity
    token: str
