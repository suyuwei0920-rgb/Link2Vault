"""Persistent stage handlers wiring providers into the capture pipeline."""

from __future__ import annotations

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
from link2vault.output.markdown import write_task_artifacts
from link2vault.providers.factory import (
    build_asr_provider,
    build_cleaner_provider,
    build_notifiers,
)
from link2vault.worker.pipeline import Pipeline, StageHandlers


def build_runtime_pipeline(settings: Settings, repository) -> Pipeline:
    asr = build_asr_provider(settings)
    cleaner = build_cleaner_provider(settings)
    notifiers = build_notifiers(settings)

    def checkpoint(task: CaptureTask, name: str) -> Path:
        return settings.data_dir / "checkpoints" / task.id / name

    async def handle(task: CaptureTask) -> str:
        if task.stage is TaskStage.VALIDATING:
            return _validated_input(task, settings)
        if task.stage is TaskStage.FETCHING:
            if task.source is CaptureSource.DOUYIN:
                if settings.app_env == "development" and settings.asr_provider == "fake":
                    return _validated_input(task, settings)
                raise ProviderError(
                    "DOUYIN_FETCH_ADAPTER_REQUIRED",
                    retryable=False,
                    safe_message="Douyin media fetch adapter is not configured",
                )
            return _validated_input(task, settings)
        if task.stage is TaskStage.ASR:
            media_path = Path(_validated_input(task, settings))
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
    candidate = Path(task.input_ref)
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
