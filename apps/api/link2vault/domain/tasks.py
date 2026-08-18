"""Capture task domain models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class CaptureSource(StrEnum):
    """Supported capture sources."""

    DOUYIN = "douyin"
    RECORDING = "recording"


class TaskStage(StrEnum):
    """Ordered stages in the capture pipeline."""

    VALIDATING = "validating"
    FETCHING = "fetching"
    ASR = "asr"
    CLEANING = "cleaning"
    WRITING = "writing"
    NOTIFYING = "notifying"


class TaskStatus(StrEnum):
    """Persistent task lifecycle state."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class CaptureTask:
    """Immutable view of one capture task."""

    id: str
    source: CaptureSource
    status: TaskStatus
    stage: TaskStage
    fingerprint: str
    created_at: datetime
    updated_at: datetime
    media_seconds: float | None
    artifacts: Mapping[str, str]
    error_code: str | None
    input_ref: str | None = None
