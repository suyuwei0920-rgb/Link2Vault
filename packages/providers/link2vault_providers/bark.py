"""Content-minimal Bark push notifications."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

import httpx

from link2vault_providers.contracts import (
    Notification,
    NotificationReceipt,
    ProviderError,
)


class BarkNotifier:
    def __init__(
        self,
        *,
        base_url: str,
        device_key: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Bark base URL must be a safe HTTPS origin")
        if not device_key:
            raise ValueError("Bark device key is required")
        self._endpoint = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/push", "", "")
        )
        self._device_key = device_key
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(15))

    async def send(self, notification: Notification) -> NotificationReceipt:
        body = f"{notification.status}: {notification.task_id}"
        try:
            response = await self._client.post(
                self._endpoint,
                json={
                    "device_key": self._device_key,
                    "title": notification.title,
                    "body": body,
                    "group": "Link2Vault",
                },
            )
        except httpx.HTTPError as exc:
            raise ProviderError(
                "BARK_NETWORK",
                retryable=True,
                safe_message="Push notification request failed",
            ) from exc
        if response.status_code >= 400:
            raise ProviderError(
                "BARK_REJECTED",
                retryable=response.status_code >= 500,
                safe_message="Push notification provider rejected the request",
            )
        return NotificationReceipt(provider="bark", accepted=True)
