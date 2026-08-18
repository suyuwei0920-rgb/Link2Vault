"""Authenticated recording and Douyin link ingestion routes."""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field

from link2vault.api.dependencies import require_device
from link2vault.config import Settings
from link2vault.domain.devices import DeviceIdentity
from link2vault.domain.tasks import CaptureSource
from link2vault.ingest.remote_url import InvalidInput
from link2vault.ingest.share_text import extract_single_url
from link2vault.media.probe import MediaRejected, probe_media
from link2vault.media.uploads import stream_upload
from link2vault.storage.quota_repository import QuotaExceeded, QuotaRepository
from link2vault.storage.task_repository import TaskRepository

router = APIRouter()


class LinkCaptureRequest(BaseModel):
    """One noisy mobile share-text payload."""

    share_text: str = Field(min_length=1, max_length=16_384)


def _accepted(task_id: str, *, deduplicated: bool) -> dict[str, object]:
    return {
        "task_id": task_id,
        "status_url": f"/ingest/tasks/{task_id}",
        "deduplicated": deduplicated,
    }


@router.post("/ingest/links", status_code=status.HTTP_202_ACCEPTED)
def ingest_link(
    body: LinkCaptureRequest,
    request: Request,
    _device: Annotated[DeviceIdentity, Depends(require_device)],
) -> dict[str, object]:
    """Queue one unambiguous Douyin share URL for validated resolution."""

    repository: TaskRepository = request.app.state.task_repository
    try:
        url = extract_single_url(body.share_text)
    except InvalidInput as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    fingerprint = hashlib.sha256(url.encode("utf-8")).hexdigest()
    completed = repository.find_completed_by_fingerprint(fingerprint)
    if completed is not None:
        return _accepted(completed.id, deduplicated=True)
    task = repository.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint=fingerprint,
        input_ref=url,
    )
    return _accepted(task.id, deduplicated=False)


@router.post("/ingest/recordings", status_code=status.HTTP_202_ACCEPTED)
async def ingest_recording(
    request: Request,
    _device: Annotated[DeviceIdentity, Depends(require_device)],
    file: Annotated[UploadFile, File()],
) -> dict[str, object]:
    """Validate, quota-check and atomically accept one recording."""

    settings: Settings = request.app.state.settings
    tasks: TaskRepository = request.app.state.task_repository
    quotas: QuotaRepository = request.app.state.quota_repository
    receipt = None
    task = None
    reserved = False
    final_path: Path | None = None
    try:
        receipt = await stream_upload(
            file,
            settings.media_tmp_dir,
            settings.max_upload_mb * 1024 * 1024,
        )
        media = await asyncio.to_thread(probe_media, receipt.path)
        if media.duration_seconds > settings.max_audio_minutes * 60:
            raise MediaRejected("INVALID_DURATION", "Audio is longer than allowed")
        completed = tasks.find_completed_by_fingerprint(receipt.sha256)
        if completed is not None:
            receipt.path.unlink(missing_ok=True)
            return _accepted(completed.id, deduplicated=True)
        task = tasks.create_capture(
            source=CaptureSource.RECORDING,
            fingerprint=receipt.sha256,
            media_seconds=media.duration_seconds,
        )
        quotas.reserve_audio_seconds(
            task.id,
            media.duration_seconds,
            settings.monthly_audio_minutes * 60,
        )
        reserved = True
        task_dir = settings.media_tmp_dir / task.id
        task_dir.mkdir(parents=True, exist_ok=False)
        final_candidate = task_dir / f"source{receipt.extension}"
        os.replace(receipt.path, final_candidate)
        try:
            tasks.set_input_ref(task.id, str(final_candidate))
        except BaseException:
            final_candidate.unlink(missing_ok=True)
            task_dir.rmdir()
            raise
        final_path = final_candidate
        return _accepted(task.id, deduplicated=False)
    except MediaRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except QuotaExceeded as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"code": "QUOTA_EXCEEDED", "message": "Monthly audio quota exceeded"},
        ) from exc
    finally:
        if receipt is not None and receipt.path.exists():
            receipt.path.unlink(missing_ok=True)
        if task is not None and final_path is None:
            tasks.delete_if_queued(task.id)
            if reserved:
                quotas.release(task.id)


@router.get("/ingest/tasks/{task_id}")
def ingest_task_status(
    task_id: str,
    request: Request,
    _device: Annotated[DeviceIdentity, Depends(require_device)],
) -> dict[str, str | None]:
    """Return content-free status for an authenticated mobile client."""

    repository: TaskRepository = request.app.state.task_repository
    try:
        task = repository.get(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
    return {
        "task_id": task.id,
        "status": task.status.value,
        "stage": task.stage.value,
        "error_code": task.error_code,
    }
