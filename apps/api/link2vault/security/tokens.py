"""One-time enrollment and revocable device tokens."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from link2vault.domain.devices import DeviceIdentity, EnrollmentCode, PlainDeviceToken
from link2vault.storage.device_repository import DeviceRepository


def token_digest(token: str, pepper: bytes) -> str:
    """Return the keyed digest stored in place of a plaintext token."""

    return hmac.new(pepper, token.encode("utf-8"), hashlib.sha256).hexdigest()


class EnrollmentService:
    """Issue, exchange, verify, list and revoke device credentials."""

    def __init__(
        self,
        repository: DeviceRepository,
        *,
        pepper: bytes,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if len(pepper) < 16:
            raise ValueError("token pepper must contain at least 16 bytes")
        self._repository = repository
        self._pepper = pepper
        self._clock = clock or (lambda: datetime.now(UTC))

    def issue_code(self, name: str, ttl_seconds: int = 300) -> EnrollmentCode:
        """Create a one-time enrollment code with a bounded lifetime."""

        normalized_name = name.strip()
        if not normalized_name or len(normalized_name) > 100:
            raise ValueError("device name must contain 1 to 100 characters")
        if not 1 <= ttl_seconds <= 300:
            raise ValueError("enrollment lifetime must be between 1 and 300 seconds")
        now = self._clock()
        code = secrets.token_urlsafe(16)
        expires_at = now + timedelta(seconds=ttl_seconds)
        self._repository.store_enrollment_code(
            name=normalized_name,
            code_digest=token_digest(code, self._pepper),
            created_at=now,
            expires_at=expires_at,
        )
        return EnrollmentCode(
            code=code,
            device_name=normalized_name,
            expires_at=expires_at,
        )

    def exchange(self, code: str) -> PlainDeviceToken:
        """Consume a valid one-time code and return a token exactly once."""

        token = secrets.token_urlsafe(32)
        device = self._repository.exchange_code(
            code_digest=token_digest(code, self._pepper),
            token_digest=token_digest(token, self._pepper),
            now=self._clock(),
        )
        if device is None:
            raise ValueError("invalid or expired enrollment code")
        return PlainDeviceToken(device=device, token=token)

    def verify(self, token: str) -> DeviceIdentity:
        """Verify a bearer token and update its last-used timestamp."""

        if not token:
            raise ValueError("unauthorized device")
        device = self._repository.verify_token(
            token_digest(token, self._pepper),
            self._clock(),
        )
        if device is None:
            raise ValueError("unauthorized device")
        return device

    def revoke(self, device_id: str) -> None:
        """Revoke one device without affecting other enrolled devices."""

        if not self._repository.revoke(device_id, self._clock()):
            raise KeyError(device_id)

    def list_devices(self) -> tuple[DeviceIdentity, ...]:
        """Return all enrolled devices without credential material."""

        return self._repository.list_devices()
