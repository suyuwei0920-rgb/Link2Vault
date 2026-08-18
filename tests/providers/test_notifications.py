from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest
from link2vault_providers.bark import BarkNotifier
from link2vault_providers.contracts import Notification
from link2vault_providers.webhook import WebhookNotifier


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_bark_sends_metadata_without_transcript_preview_by_default() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"code": 200, "message": "success"})

    notifier = BarkNotifier(
        base_url="https://example.com/",
        device_key="DUMMY_" + "device-key",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    receipt = await notifier.send(
        Notification("synthetic-task", "completed", "Capture completed")
    )

    payload = json.loads(requests[0].content)
    assert receipt.accepted is True
    assert requests[0].url.path.endswith("/push")
    assert set(payload) == {"device_key", "title", "body", "group"}
    assert "transcript" not in requests[0].content.decode().casefold()


@pytest.mark.anyio
async def test_webhook_signs_exact_json_body() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    secret = b"DUMMY_webhook-signing-value"
    notifier = WebhookNotifier(
        endpoint="https://example.com/hook",
        signing_secret=secret,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await notifier.send(Notification("synthetic-task", "failed", "Capture failed"))

    expected = hmac.new(secret, requests[0].content, hashlib.sha256).hexdigest()
    assert requests[0].headers["X-Link2Vault-Signature"] == f"sha256={expected}"
