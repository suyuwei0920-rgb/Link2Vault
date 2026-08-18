"""Bounded streaming of untrusted recording uploads."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from link2vault.media.probe import MediaRejected

_CHUNK_BYTES = 1024 * 1024
_ALLOWED_TYPES = {
    ".aac": frozenset({"audio/aac", "audio/x-aac"}),
    ".amr": frozenset({"audio/amr"}),
    ".flac": frozenset({"audio/flac", "audio/x-flac"}),
    ".m4a": frozenset({"audio/mp4", "audio/x-m4a"}),
    ".mp3": frozenset({"audio/mpeg", "audio/mp3"}),
    ".ogg": frozenset({"audio/ogg"}),
    ".opus": frozenset({"audio/opus", "audio/ogg"}),
    ".wav": frozenset({"audio/wav", "audio/wave", "audio/x-wav"}),
}


class AsyncUpload(Protocol):
    """Minimal upload contract shared with FastAPI UploadFile."""

    filename: str | None
    content_type: str | None

    async def read(self, size: int) -> bytes: ...


@dataclass(frozen=True)
class UploadReceipt:
    """Server-controlled partial upload metadata."""

    path: Path
    size_bytes: int
    sha256: str
    extension: str


async def stream_upload(
    upload: AsyncUpload,
    destination: Path,
    max_bytes: int,
) -> UploadReceipt:
    """Stream in fixed chunks, enforce the limit, fsync and retain no orphan."""

    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    extension = Path(upload.filename or "").suffix.casefold()
    content_type = (upload.content_type or "").split(";", maxsplit=1)[0].casefold()
    if extension not in _ALLOWED_TYPES or content_type not in _ALLOWED_TYPES[extension]:
        raise MediaRejected("UNSUPPORTED_MEDIA_TYPE", "Upload type is not supported")
    destination.mkdir(parents=True, exist_ok=True)
    partial_path = destination / f"{uuid4()}{extension}.partial"
    digest = hashlib.sha256()
    total = 0
    try:
        with partial_path.open("xb") as output:
            while chunk := await upload.read(_CHUNK_BYTES):
                total += len(chunk)
                if total > max_bytes:
                    raise MediaRejected("UPLOAD_TOO_LARGE", "Upload is too large")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        if total == 0:
            raise MediaRejected("EMPTY_UPLOAD", "Upload is empty")
    except BaseException:
        partial_path.unlink(missing_ok=True)
        raise
    return UploadReceipt(
        path=partial_path,
        size_bytes=total,
        sha256=digest.hexdigest(),
        extension=extension,
    )
