"""Probe untrusted media through ffprobe without exposing file content."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


class MediaRejected(ValueError):
    """Typed media rejection safe to map to a client error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class MediaInfo:
    """Validated audio metadata required for quota reservation."""

    duration_seconds: float
    codec_name: str


def probe_media(path: Path) -> MediaInfo:
    """Require one supported audio stream and a positive measured duration."""

    completed = subprocess.run(
        [
            "ffprobe",
            "-v",
            "error",
            "-print_format",
            "json",
            "-show_format",
            "-show_streams",
            "--",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise MediaRejected("INVALID_MEDIA", "Upload is not valid audio media")
    try:
        payload = json.loads(completed.stdout)
        audio_stream = next(
            stream
            for stream in payload["streams"]
            if stream.get("codec_type") == "audio" and stream.get("codec_name")
        )
        raw_duration = payload.get("format", {}).get("duration") or audio_stream.get(
            "duration"
        )
        duration = float(raw_duration)
    except (KeyError, StopIteration, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise MediaRejected("INVALID_MEDIA", "Upload is not valid audio media") from exc
    if not 0 < duration <= 240 * 60:
        raise MediaRejected(
            "INVALID_DURATION",
            "Audio duration must be between zero and 240 minutes",
        )
    return MediaInfo(
        duration_seconds=duration,
        codec_name=str(audio_stream["codec_name"]),
    )
