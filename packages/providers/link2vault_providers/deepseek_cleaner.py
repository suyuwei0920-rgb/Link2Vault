"""DeepSeek-compatible conservative transcript cleaning."""

from __future__ import annotations

import json

import httpx

from link2vault_providers.contracts import CleanRequest, CleanResult, ProviderError

_SYSTEM_PROMPT = """你是会议逐字稿校对助手。只修正明显的识别错误，不得猜测人名、数字、日期、承诺或说话人身份。无法确定时必须保留[听不清]。输出严格 JSON，字段为 summary、decisions、action_items、open_questions、cleaned_transcript；数组字段只包含字符串。"""


class DeepSeekCleaner:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key or not model:
            raise ValueError("DeepSeek credentials and model are required")
        self._api_key = api_key
        self._model = model
        if client is None and base_url is None:
            raise ValueError("DeepSeek base URL is required")
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(60),
        )

    async def clean(self, request: CleanRequest) -> CleanResult:
        try:
            response = await self._client.post(
                "/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": self._model,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user", "content": request.raw_transcript},
                    ],
                },
            )
        except httpx.TimeoutException as exc:
            raise ProviderError(
                "DEEPSEEK_TIMEOUT",
                retryable=True,
                safe_message="Transcript cleaning timed out",
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                "DEEPSEEK_NETWORK",
                retryable=True,
                safe_message="Transcript cleaning network request failed",
            ) from exc
        request_id = response.headers.get("x-request-id")
        if response.status_code >= 400:
            raise ProviderError(
                "DEEPSEEK_REJECTED",
                retryable=response.status_code >= 500,
                safe_message="Transcript cleaning provider rejected the request",
                provider_request_id=request_id,
            )
        try:
            envelope = response.json()
            payload = json.loads(envelope["choices"][0]["message"]["content"])
            summary = _require_string(payload, "summary")
            decisions = _require_strings(payload, "decisions")
            actions = _require_strings(payload, "action_items")
            questions = _require_strings(payload, "open_questions")
            cleaned = _require_string(payload, "cleaned_transcript")
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderError(
                "DEEPSEEK_INVALID_RESPONSE",
                retryable=False,
                safe_message="Transcript cleaning returned invalid structured output",
                provider_request_id=request_id,
            ) from exc
        return CleanResult(
            provider="deepseek",
            model=self._model,
            summary=summary,
            decisions=decisions,
            action_items=actions,
            open_questions=questions,
            cleaned_transcript=cleaned,
        )


def _require_string(payload: object, key: str) -> str:
    if not isinstance(payload, dict) or not isinstance(payload.get(key), str):
        raise TypeError("invalid string field")
    return payload[key]


def _require_strings(payload: object, key: str) -> tuple[str, ...]:
    if not isinstance(payload, dict) or not isinstance(payload.get(key), list):
        raise TypeError("invalid list field")
    values = payload[key]
    if not all(isinstance(value, str) for value in values):
        raise ValueError("invalid list member")
    return tuple(values)
