"""Persistent stage handlers wiring providers into the capture pipeline."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import asdict
from pathlib import Path
from uuid import uuid4

from link2vault_providers.contracts import (
    CleanRequest,
    CleanResult,
    MediaInput,
    Notification,
    ProviderError,
    TranscriptResult,
    TranscriptSegment,
)

from link2vault.config import Settings
from link2vault.domain.tasks import CaptureSource, CaptureTask, TaskStage
from link2vault.ingest.douyin_resolver import DouyinResolver
from link2vault.ingest.media_downloader import DouyinMediaDownloader
from link2vault.media.probe import MediaRejected, probe_media
from link2vault.output.markdown import write_task_artifacts
from link2vault.providers.factory import (
    build_asr_provider,
    build_cleaner_provider,
    build_notifiers,
)
from link2vault.worker.pipeline import Pipeline, StageHandlers


def build_runtime_pipeline(
    settings: Settings,
    repository,
    *,
    douyin_resolver: DouyinResolver | None = None,
    media_downloader: DouyinMediaDownloader | None = None,
) -> Pipeline:
    asr = build_asr_provider(settings)
    cleaner = build_cleaner_provider(settings)
    notifiers = build_notifiers(settings)
    resolver = douyin_resolver or DouyinResolver()
    downloader = media_downloader or DouyinMediaDownloader(
        media_root=settings.media_tmp_dir,
        max_bytes=settings.max_upload_mb * 1024 * 1024,
    )

    def checkpoint(task: CaptureTask, name: str) -> Path:
        return settings.data_dir / "checkpoints" / task.id / name

    async def handle(task: CaptureTask) -> str:
        if task.stage is TaskStage.VALIDATING:
            return _validated_input(task, settings)
        if task.stage is TaskStage.FETCHING:
            if task.source is CaptureSource.DOUYIN:
                if (
                    douyin_resolver is None
                    and media_downloader is None
                    and settings.app_env == "development"
                    and settings.asr_provider == "fake"
                ):
                    return _validated_input(task, settings)
                target = await resolver.resolve(_validated_input(task, settings))
                if target.kind != "video":
                    raise ProviderError(
                        "DOUYIN_PROFILE_EXPERIMENTAL",
                        retryable=False,
                        safe_message="Douyin profile collection is not enabled",
                    )
                media_path = await downloader.download(target.media_candidates, task.id)
                try:
                    probed = await asyncio.to_thread(probe_media, media_path)
                except MediaRejected as exc:
                    raise ProviderError(
                        exc.code,
                        retryable=False,
                        safe_message="Downloaded Douyin media was rejected",
                    ) from exc
                if probed.duration_seconds > settings.max_audio_minutes * 60:
                    raise ProviderError(
                        "INVALID_DURATION",
                        retryable=False,
                        safe_message="Douyin media is longer than allowed",
                    )
                repository.set_media_seconds(task.id, probed.duration_seconds)
                return str(media_path)
            return _validated_input(task, settings)
        if task.stage is TaskStage.ASR:
            fetched = task.artifacts.get(TaskStage.FETCHING.value)
            if fetched is None:
                raise ProviderError(
                    "FETCH_ARTIFACT_MISSING",
                    retryable=False,
                    safe_message="Fetched media checkpoint is missing",
                )
            if (
                task.source is CaptureSource.DOUYIN
                and settings.app_env == "development"
                and settings.asr_provider == "fake"
                and fetched.startswith("https://")
            ):
                media_path = Path(fetched)
            else:
                media_path = Path(_validated_media_path(fetched, settings))
            result = await asr.transcribe(
                MediaInput(media_path, task.media_seconds or 1.0)
            )
            path = checkpoint(task, "asr.json")
            _atomic_json(path, asdict(result))
            return str(path)
        if task.stage is TaskStage.CLEANING:
            transcript = _read_transcript(checkpoint(task, "asr.json"))
            result = await cleaner.clean(
                CleanRequest(transcript.text, transcript.segments)
            )
            path = checkpoint(task, "cleaned.json")
            _atomic_json(path, asdict(result))
            return str(path)
        if task.stage is TaskStage.WRITING:
            transcript = _read_transcript(checkpoint(task, "asr.json"))
            cleaned = _read_clean(checkpoint(task, "cleaned.json"))
            manifest = write_task_artifacts(
                task,
                transcript,
                cleaned,
                settings.vault_root,
                title=(
                    f"Douyin {task.created_at.strftime('%Y-%m-%d %H%M')}"
                    if task.source is CaptureSource.DOUYIN
                    else f"Recording {task.created_at.strftime('%Y-%m-%d %H%M')}"
                ),
                source_url=(
                    task.input_ref if task.source is CaptureSource.DOUYIN else None
                ),
            )
            return str(manifest.task_dir)
        if task.stage is TaskStage.NOTIFYING:
            for notifier in notifiers:
                await notifier.send(
                    Notification(
                        task_id=task.id,
                        status="completed",
                        title="Link2Vault capture completed",
                    )
                )
            return "sent" if notifiers else "disabled"
        raise AssertionError("unreachable task stage")

    return Pipeline(
        repository,
        StageHandlers({stage: handle for stage in TaskStage}),
    )


def _validated_input(task: CaptureTask, settings: Settings) -> str:
    if task.input_ref is None:
        raise ProviderError(
            "INPUT_REFERENCE_MISSING",
            retryable=False,
            safe_message="Capture input is missing",
        )
    if task.source is CaptureSource.DOUYIN:
        return task.input_ref
    return _validated_media_path(task.input_ref, settings)


def _validated_media_path(value: str, settings: Settings) -> str:
    candidate = Path(value)
    try:
        root = settings.media_tmp_dir.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ProviderError(
            "MEDIA_MISSING",
            retryable=False,
            safe_message="Recording media is unavailable",
        ) from exc
    if candidate.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
        raise ProviderError(
            "MEDIA_PATH_REJECTED",
            retryable=False,
            safe_message="Recording media path is outside its configured root",
        )
    return str(resolved)


def _atomic_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4()}.partial")
    try:
        with temporary.open("x", encoding="utf-8") as output:
            json.dump(payload, output, ensure_ascii=False, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_transcript(path: Path) -> TranscriptResult:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return TranscriptResult(
        provider=payload["provider"],
        model=payload["model"],
        language=payload["language"],
        duration_seconds=float(payload["duration_seconds"]),
        text=payload["text"],
        segments=tuple(TranscriptSegment(**segment) for segment in payload["segments"]),
        provider_job_id=payload.get("provider_job_id"),
    )


def _read_clean(path: Path) -> CleanResult:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return CleanResult(
        provider=payload["provider"],
        model=payload["model"],
        summary=payload["summary"],
        decisions=tuple(payload["decisions"]),
        action_items=tuple(payload["action_items"]),
        open_questions=tuple(payload["open_questions"]),
        cleaned_transcript=payload["cleaned_transcript"],
    )
