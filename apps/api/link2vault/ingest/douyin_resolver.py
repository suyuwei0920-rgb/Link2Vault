"""Resolve one Douyin share text into a canonical video or profile target."""

from __future__ import annotations

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
            return self._classify(current_url)
        raise InvalidInput("TOO_MANY_REDIRECTS", "Too many redirect hops")

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
