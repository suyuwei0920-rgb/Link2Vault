from __future__ import annotations

from datetime import UTC, datetime

import pytest
from link2vault.domain.tasks import CaptureSource, CaptureTask, TaskStage, TaskStatus
from link2vault.output.markdown import write_task_artifacts
from link2vault_providers.contracts import (
    CleanResult,
    TranscriptResult,
    TranscriptSegment,
)


def task() -> CaptureTask:
    timestamp = datetime(2026, 8, 18, 10, 15, tzinfo=UTC)
    return CaptureTask(
        id="synthetic-task",
        source=CaptureSource.RECORDING,
        status=TaskStatus.RUNNING,
        stage=TaskStage.WRITING,
        fingerprint="synthetic-fingerprint",
        created_at=timestamp,
        updated_at=timestamp,
        media_seconds=12.0,
        artifacts={},
        error_code=None,
    )


def transcript(text: str = "Speaker 1: 原始内容。") -> TranscriptResult:
    return TranscriptResult(
        provider="fake",
        model="offline-v1",
        language="zh",
        duration_seconds=12.0,
        text=text,
        segments=(TranscriptSegment(0, 12, text, "Speaker 1"),),
    )


def cleaned() -> CleanResult:
    return CleanResult(
        provider="fake",
        model="offline-v1",
        summary="会议摘要",
        decisions=("采用方案甲",),
        action_items=("张三跟进",),
        open_questions=("日期[听不清]",),
        cleaned_transcript="Speaker 1：整理后的内容。",
    )


def test_writes_safe_dated_obsidian_directory_and_all_artifacts(tmp_path) -> None:
    manifest = write_task_artifacts(
        task(),
        transcript(),
        cleaned(),
        tmp_path,
        title='客户/会议: "方案"',
        source_url=(
            "https://" + "example.com/video/1?tracking=private-marker#fragment"
        ),
    )

    assert manifest.task_dir.relative_to(tmp_path).parts == (
        "2026",
        "08",
        "2026-08-18_1015_客户_会议_方案",
    )
    assert {path.name for path in manifest.task_dir.iterdir()} == {
        "note.md",
        "transcript.raw.md",
        "metadata.json",
    }
    note = manifest.note_path.read_text(encoding="utf-8")
    assert 'title: "客户/会议: \\"方案\\""' in note
    assert "## 决策" in note
    assert "## 待办事项" in note
    assert "日期[听不清]" in note
    metadata = manifest.metadata_path.read_text(encoding="utf-8")
    assert "private-marker" not in metadata
    assert "?" not in metadata
    assert not list(manifest.task_dir.glob("*.partial"))


def test_raw_transcript_is_immutable_across_rewrites(tmp_path) -> None:
    write_task_artifacts(task(), transcript(), cleaned(), tmp_path, title="会议")

    with pytest.raises(ValueError, match="immutable"):
        write_task_artifacts(
            task(),
            transcript("Different raw content"),
            cleaned(),
            tmp_path,
            title="会议",
        )

    raw_path = next(tmp_path.rglob("transcript.raw.md"))
    assert "原始内容" in raw_path.read_text(encoding="utf-8")
    assert "Different" not in raw_path.read_text(encoding="utf-8")
