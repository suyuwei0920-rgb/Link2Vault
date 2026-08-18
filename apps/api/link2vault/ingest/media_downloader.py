"""Bounded, redirect-aware Douyin media download."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol
from urllib.parse import urljoin
from uuid import uuid4

import httpx

from link2vault.ingest.remote_url import (
    HostResolver,
    InvalidInput,
    SocketHostResolver,
    validate_remote_url,
)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class DownloadHttpClient(Protocol):
    def build_request(self, method: str, url: str) -> httpx.Request: ...

    async def send(
        self, request: httpx.Request, *, stream: bool
    ) -> httpx.Response: ...


class MediaDownloadError(RuntimeError):
    """Content-free media failure safe for persistence."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = code not in {
            "MEDIA_TOO_LARGE",
            "MEDIA_TYPE_REJECTED",
            "MEDIA_PATH_REJECTED",
        }


class DouyinMediaDownloader:
    """Try allowlisted candidates and atomically persist the first valid media."""

    def __init__(
        self,
        *,
        media_root: Path,
        client: DownloadHttpClient | None = None,
        host_resolver: HostResolver | None = None,
        max_bytes: int = 1024 * 1024 * 1024,
        max_redirects: int = 5,
    ) -> None:
        self._media_root = media_root
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5, read=60, write=30, pool=5),
            follow_redirects=False,
            trust_env=False,
            headers={"Accept-Encoding": "identity"},
        )
        self._host_resolver = host_resolver or SocketHostResolver()
        self._max_bytes = max_bytes
        self._max_redirects = max_redirects

    async def download(self, candidates: tuple[str, ...], task_id: str) -> Path:
        if not candidates:
            raise MediaDownloadError("MEDIA_URL_NOT_FOUND", "No media candidate exists")
        task_dir = self._safe_task_dir(task_id)
        task_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        output = task_dir / "source.media"
        last_error: Exception | None = None
        for candidate in candidates:
            try:
                await self._download_candidate(candidate, output)
                return output
            except (InvalidInput, MediaDownloadError, httpx.HTTPError) as exc:
                last_error = exc
                output.unlink(missing_ok=True)
        if isinstance(last_error, MediaDownloadError):
            raise last_error
        raise MediaDownloadError(
            "MEDIA_DOWNLOAD_FAILED",
            "All validated media candidates failed",
        ) from last_error

    def _safe_task_dir(self, task_id: str) -> Path:
        if not task_id or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in task_id):
            raise MediaDownloadError("MEDIA_PATH_REJECTED", "Task path is invalid")
        root = self._media_root.resolve()
        candidate = root / task_id
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            raise MediaDownloadError("MEDIA_PATH_REJECTED", "Task path is invalid")
        return candidate

    async def _download_candidate(self, url: str, output: Path) -> None:
        current = url
        for redirect_count in range(self._max_redirects + 1):
            await validate_remote_url(current, "media", self._host_resolver)
            request = self._client.build_request("GET", current)
            response = await self._client.send(request, stream=True)
            try:
                if response.status_code in _REDIRECT_STATUSES:
                    if redirect_count == self._max_redirects:
                        raise MediaDownloadError(
                            "MEDIA_REDIRECT_LIMIT",
                            "Media redirected too many times",
                        )
                    location = response.headers.get("location")
                    if not location:
                        raise MediaDownloadError(
                            "MEDIA_REDIRECT_INVALID",
                            "Media redirect target is missing",
                        )
                    current = urljoin(current, location)
                    continue
                if response.status_code not in {200, 206}:
                    raise MediaDownloadError(
                        "MEDIA_UPSTREAM_REJECTED",
                        "Media host rejected the request",
                    )
                content_type = response.headers.get("content-type", "").split(";", 1)[0]
                if content_type and not (
                    content_type.startswith(("audio/", "video/"))
                    or content_type == "application/octet-stream"
                ):
                    raise MediaDownloadError(
                        "MEDIA_TYPE_REJECTED",
                        "Media response type was rejected",
                    )
                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        if int(declared) > self._max_bytes:
                            raise MediaDownloadError(
                                "MEDIA_TOO_LARGE",
                                "Media exceeds the configured size limit",
                            )
                    except ValueError:
                        pass
                await self._write_response(response, output)
                return
            finally:
                await response.aclose()
        raise MediaDownloadError("MEDIA_REDIRECT_LIMIT", "Media redirected too many times")

    async def _write_response(self, response: httpx.Response, output: Path) -> None:
        temporary = output.with_name(f".{output.name}.{uuid4().hex}.partial")
        received = 0
        try:
            with temporary.open("xb") as destination:
                async for chunk in response.aiter_bytes(64 * 1024):
                    received += len(chunk)
                    if received > self._max_bytes:
                        raise MediaDownloadError(
                            "MEDIA_TOO_LARGE",
                            "Media exceeds the configured size limit",
                        )
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            if received == 0:
                raise MediaDownloadError("MEDIA_EMPTY", "Media response was empty")
            os.replace(temporary, output)
        finally:
            temporary.unlink(missing_ok=True)
