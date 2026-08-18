"""Atomic, history-preserving Obsidian Markdown output."""

from __future__ import annotations

import json
import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from link2vault_providers.contracts import CleanResult, TranscriptResult

from link2vault.domain.tasks import CaptureTask


@dataclass(frozen=True)
class ArtifactManifest:
    task_dir: Path
    note_path: Path
    raw_transcript_path: Path
    metadata_path: Path


def _safe_filename(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip()
    normalized = re.sub(r"[\\/:*?\"<>|\x00-\x1f]", "_", normalized)
    normalized = re.sub(r"\s+", "_", normalized)
    normalized = re.sub(r"_+", "_", normalized).strip("._ ")
    return (normalized or "untitled")[:80].rstrip("._ ")


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4()}.partial")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _redact_url(value: str | None) -> str | None:
    if value is None:
        return None
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _bullet_section(title: str, values: tuple[str, ...]) -> str:
    body = "\n".join(f"- {value}" for value in values) if values else "- 无"
    return f"## {title}\n\n{body}"


def write_task_artifacts(
    task: CaptureTask,
    transcript: TranscriptResult,
    cleaned: CleanResult,
    vault_root: Path,
    *,
    title: str,
    source_url: str | None = None,
) -> ArtifactManifest:
    """Write a cleaned note beside an immutable raw transcript and metadata."""

    timestamp = task.created_at
    task_dir = (
        vault_root
        / timestamp.strftime("%Y")
        / timestamp.strftime("%m")
        / f"{timestamp.strftime('%Y-%m-%d_%H%M')}_{_safe_filename(title)}"
    )
    task_dir.mkdir(parents=True, exist_ok=True)
    note_path = task_dir / "note.md"
    raw_path = task_dir / "transcript.raw.md"
    metadata_path = task_dir / "metadata.json"

    raw_content = transcript.text.rstrip() + "\n"
    if raw_path.exists():
        if raw_path.read_text(encoding="utf-8") != raw_content:
            raise ValueError("raw transcript is immutable")
    else:
        _atomic_write(raw_path, raw_content)

    yaml_title = json.dumps(title, ensure_ascii=False)
    note_content = "\n\n".join(
        (
            f"---\ntitle: {yaml_title}\ntask_id: {task.id}\nsource: {task.source.value}\n---",
            f"# {title}",
            f"## 摘要\n\n{cleaned.summary}",
            _bullet_section("决策", cleaned.decisions),
            _bullet_section("待办事项", cleaned.action_items),
            _bullet_section("待确认内容", cleaned.open_questions),
            f"## 整理稿\n\n{cleaned.cleaned_transcript}",
        )
    ) + "\n"
    _atomic_write(note_path, note_content)

    metadata = {
        "schema_version": 1,
        "task_id": task.id,
        "source": task.source.value,
        "source_url": _redact_url(source_url),
        "created_at": task.created_at.isoformat(),
        "duration_seconds": transcript.duration_seconds,
        "asr": {"provider": transcript.provider, "model": transcript.model},
        "cleaner": {"provider": cleaned.provider, "model": cleaned.model},
    }
    _atomic_write(
        metadata_path,
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return ArtifactManifest(
        task_dir=task_dir,
        note_path=note_path,
        raw_transcript_path=raw_path,
        metadata_path=metadata_path,
    )
