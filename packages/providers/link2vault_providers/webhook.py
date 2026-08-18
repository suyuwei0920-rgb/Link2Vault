"""Generic HMAC-signed metadata-only webhook notifications."""

from __future__ import annotations

import hashlib
import hmac
import json
from urllib.parse import urlsplit

import httpx

from link2vault_providers.contracts import (
    Notification,
    NotificationReceipt,
    ProviderError,
)


class WebhookNotifier:
    def __init__(
        self,
        *,
        endpoint: str,
        signing_secret: bytes,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or parsed.hostname is None or parsed.username:
            raise ValueError("Webhook endpoint must use HTTPS without credentials")
        if len(signing_secret) < 16:
            raise ValueError("Webhook signing secret is too short")
        self._endpoint = endpoint
        self._secret = signing_secret
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(15))

    async def send(self, notification: Notification) -> NotificationReceipt:
        content = json.dumps(
            {
                "task_id": notification.task_id,
                "status": notification.status,
                "title": notification.title,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        signature = hmac.new(self._secret, content, hashlib.sha256).hexdigest()
        try:
            response = await self._client.post(
                self._endpoint,
                content=content,
                headers={
                    "Content-Type": "application/json",
                    "X-Link2Vault-Signature": f"sha256={signature}",
                },
            )
        except httpx.HTTPError as exc:
            raise ProviderError(
                "WEBHOOK_NETWORK",
                retryable=True,
                safe_message="Webhook notification request failed",
            ) from exc
        if response.status_code >= 400:
            raise ProviderError(
                "WEBHOOK_REJECTED",
                retryable=response.status_code >= 500,
                safe_message="Webhook endpoint rejected the request",
            )
        return NotificationReceipt(provider="webhook", accepted=True)
