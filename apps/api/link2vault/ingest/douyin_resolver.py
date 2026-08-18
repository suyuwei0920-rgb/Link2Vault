"""Resolve one Douyin share text into a canonical video or profile target."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal, Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from link2vault.ingest.remote_url import (
    HostResolver,
    InvalidInput,
    SocketHostResolver,
    validate_remote_url,
)
from link2vault.ingest.share_text import extract_single_url

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_VIDEO_PATH = re.compile(r"^/video/(?P<id>[0-9]+)/?$")
_PROFILE_PATH = re.compile(r"^/user/(?P<id>[A-Za-z0-9_-]+)/?$")


class AsyncHttpClient(Protocol):
    """Minimal HTTP client boundary used by the resolver."""

    async def get(self, url: str, *, follow_redirects: bool) -> httpx.Response: ...


@dataclass(frozen=True)
class ResolvedTarget:
    """Canonical, pre-paid-stage classification result."""

    kind: Literal["video", "profile"]
    canonical_url: str
    media_candidates: tuple[str, ...]
    title: str | None


class DouyinResolver:
    """Follow only validated redirects and classify the final public target."""

    def __init__(
        self,
        *,
        client: AsyncHttpClient | None = None,
        host_resolver: HostResolver | None = None,
        max_redirects: int = 5,
    ) -> None:
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(15.0),
            follow_redirects=False,
        )
        self._host_resolver = host_resolver or SocketHostResolver()
        self._max_redirects = max_redirects

    async def resolve(self, share_text: str) -> ResolvedTarget:
        """Resolve noisy share text without trusting any redirect hop."""

        current_url = extract_single_url(share_text)
        for redirect_count in range(self._max_redirects + 1):
            validated = await validate_remote_url(
                current_url,
                "page",
                self._host_resolver,
            )
            try:
                response = await self._client.get(
                    validated.url,
                    follow_redirects=False,
                )
            except httpx.HTTPError as exc:
                raise InvalidInput(
                    "UPSTREAM_UNAVAILABLE",
                    "Douyin page could not be retrieved",
                ) from exc
            if response.status_code in _REDIRECT_STATUSES:
                if redirect_count == self._max_redirects:
                    raise InvalidInput("TOO_MANY_REDIRECTS", "Too many redirect hops")
                location = response.headers.get("location")
                if not location:
                    raise InvalidInput("INVALID_REDIRECT", "Redirect target is missing")
                current_url = urljoin(current_url, location)
                continue
            if not 200 <= response.status_code < 300:
                raise InvalidInput(
                    "UPSTREAM_REJECTED",
                    "Douyin page was not available",
                )
            target = self._classify(current_url)
            if target.kind == "video":
                return await self._with_video_metadata(target)
            return target
        raise InvalidInput("TOO_MANY_REDIRECTS", "Too many redirect hops")

    async def _with_video_metadata(self, target: ResolvedTarget) -> ResolvedTarget:
        item_match = _VIDEO_PATH.fullmatch(urlsplit(target.canonical_url).path)
        if item_match is None:
            return target
        item_id = item_match.group("id")
        h5_origin = "https://" + "www." + "iesdouyin.com"
        h5_url = f"{h5_origin}/share/video/{item_id}/"
        await validate_remote_url(h5_url, "page", self._host_resolver)
        try:
            response = await self._client.get(h5_url, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise InvalidInput(
                "METADATA_UNAVAILABLE",
                "Douyin video metadata could not be retrieved",
            ) from exc
        if response.status_code != 200:
            raise InvalidInput(
                "METADATA_UNAVAILABLE",
                "Douyin video metadata was not available",
            )
        if len(response.content) > 2 * 1024 * 1024:
            raise InvalidInput("METADATA_TOO_LARGE", "Douyin metadata was too large")
        item = self._extract_router_item(response.text, item_id)
        video = item.get("video") if isinstance(item.get("video"), dict) else {}
        media_candidates = self._media_urls(video)
        if not media_candidates:
            raise InvalidInput(
                "MEDIA_URL_NOT_FOUND",
                "Douyin video metadata did not contain a media URL",
            )
        canonical = target.canonical_url
        return ResolvedTarget(
            kind="video",
            canonical_url=canonical,
            media_candidates=media_candidates,
            title=str(item.get("desc") or "").strip()[:120] or None,
        )

    @classmethod
    def _extract_router_item(cls, html: str, item_id: str) -> dict[str, object]:
        marker = "window._ROUTER_DATA = "
        start = html.find(marker)
        if start < 0:
            raise InvalidInput(
                "DOUYIN_CHALLENGE",
                "Douyin returned a verification page instead of video metadata",
            )
        start += len(marker)
        end = html.find("</script>", start)
        if end < 0:
            raise InvalidInput("METADATA_INVALID", "Douyin metadata was malformed")
        try:
            payload = json.loads(html[start:end].strip().rstrip(";"))
        except json.JSONDecodeError as exc:
            raise InvalidInput("METADATA_INVALID", "Douyin metadata was malformed") from exc
        item = cls._find_item(payload, item_id)
        if item is None:
            raise InvalidInput(
                "VIDEO_NOT_AVAILABLE",
                "Douyin video is unavailable or requires authentication",
            )
        return item

    @classmethod
    def _find_item(cls, value: object, item_id: str) -> dict[str, object] | None:
        if isinstance(value, dict):
            if str(value.get("aweme_id", "")) == item_id and isinstance(
                value.get("video"), dict
            ):
                return value
            items = value.get("item_list")
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and str(item.get("aweme_id", "")) == item_id:
                        return item
            for nested in value.values():
                found = cls._find_item(nested, item_id)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for nested in value:
                found = cls._find_item(nested, item_id)
                if found is not None:
                    return found
        return None

    @staticmethod
    def _media_urls(video: dict[str, object]) -> tuple[str, ...]:
        urls: list[str] = []
        for key in ("play_addr", "play_addr_h264", "download_addr", "audio"):
            address = video.get(key)
            if not isinstance(address, dict):
                continue
            values = address.get("url_list")
            if isinstance(values, list):
                urls.extend(
                    value
                    for value in values
                    if isinstance(value, str) and value.startswith("https://")
                )
        return tuple(dict.fromkeys(urls))[:10]

    @staticmethod
    def _classify(url: str) -> ResolvedTarget:
        parsed = urlsplit(url)
        canonical_url = urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")
        )
        if _VIDEO_PATH.fullmatch(parsed.path):
            kind: Literal["video", "profile"] = "video"
        elif _PROFILE_PATH.fullmatch(parsed.path):
            kind = "profile"
        else:
            raise InvalidInput(
                "UNSUPPORTED_DOUYIN_TARGET",
                "Final target is not a canonical Douyin video or profile",
            )
        return ResolvedTarget(
            kind=kind,
            canonical_url=canonical_url,
            media_candidates=(),
            title=None,
        )
