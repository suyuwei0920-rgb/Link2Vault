"""OpenAI-compatible multipart ASR adapter."""

from __future__ import annotations

import mimetypes

import httpx

from link2vault_providers.contracts import (
    MediaInput,
    ProviderError,
    TranscriptResult,
    TranscriptSegment,
)


class OpenAICompatibleAsrProvider:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key or not model:
            raise ValueError("ASR credentials and model are required")
        self._api_key = api_key
        self._model = model
        if client is None and base_url is None:
            raise ValueError("ASR base URL is required")
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(120),
        )

    async def transcribe(self, media: MediaInput) -> TranscriptResult:
        try:
            content = media.path.read_bytes()
            response = await self._client.post(
                "/audio/transcriptions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                data={"model": self._model, "response_format": "verbose_json"},
                files={
                    "file": (
                        media.path.name,
                        content,
                        mimetypes.guess_type(media.path.name)[0]
                        or "application/octet-stream",
                    )
                },
            )
        except (OSError, httpx.HTTPError) as exc:
            raise ProviderError(
                "OPENAI_ASR_NETWORK",
                retryable=isinstance(exc, httpx.TimeoutException),
                safe_message="ASR request failed",
            ) from exc
        request_id = response.headers.get("x-request-id")
        if response.status_code >= 400:
            raise ProviderError(
                "OPENAI_ASR_REJECTED",
                retryable=response.status_code >= 500,
                safe_message="ASR provider rejected the request",
                provider_request_id=request_id,
            )
        try:
            payload = response.json()
            segments = tuple(
                TranscriptSegment(
                    start_seconds=float(segment["start"]),
                    end_seconds=float(segment["end"]),
                    text=str(segment["text"]),
                    speaker=(
                        None
                        if segment.get("speaker") is None
                        else str(segment["speaker"])
                    ),
                )
                for segment in payload.get("segments", [])
            )
            text = str(payload["text"])
            duration = float(payload.get("duration", media.duration_seconds))
            language = str(payload.get("language", "unknown"))
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderError(
                "OPENAI_ASR_INVALID_RESPONSE",
                retryable=False,
                safe_message="ASR provider returned invalid structured output",
                provider_request_id=request_id,
            ) from exc
        return TranscriptResult(
            provider="openai-compatible",
            model=self._model,
            language=language,
            duration_seconds=duration,
            text=text,
            segments=segments,
            provider_job_id=request_id,
        )
