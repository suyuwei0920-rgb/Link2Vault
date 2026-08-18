"""Administrator task history, retry, export and deletion routes."""

from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from link2vault.config import Settings
from link2vault.domain.tasks import CaptureTask, TaskStage
from link2vault.output.export import export_vault
from link2vault.storage.task_repository import TaskRepository

router = APIRouter()


class RetryRequest(BaseModel):
    stage: TaskStage
    confirm_possible_charge: bool = False


class DeleteTaskRequest(BaseModel):
    delete_vault: bool = False


def _task_summary(task: CaptureTask) -> dict[str, str | None]:
    return {
        "id": task.id,
        "source": task.source.value,
        "status": task.status.value,
        "stage": task.stage.value,
        "created_at": task.created_at.isoformat(),
        "updated_at": task.updated_at.isoformat(),
        "error_code": task.error_code,
    }


def _safe_remove_directory(root: Path, candidate: Path) -> None:
    if not candidate.exists() and not candidate.is_symlink():
        return
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValueError("task artifact path is not a safe directory")
    resolved_root = root.resolve(strict=True)
    resolved_candidate = candidate.resolve(strict=True)
    if not resolved_candidate.is_relative_to(resolved_root) or any(
        child.is_symlink() for child in candidate.rglob("*")
    ):
        raise ValueError("task artifact path escaped its configured root")
    shutil.rmtree(resolved_candidate)


@router.get("/admin/tasks")
def list_admin_tasks(request: Request) -> list[dict[str, str | None]]:
    repository: TaskRepository = request.app.state.task_repository
    return [_task_summary(task) for task in repository.list_tasks()]


@router.get("/admin/tasks/{task_id}")
def get_admin_task(task_id: str, request: Request) -> dict[str, object]:
    repository: TaskRepository = request.app.state.task_repository
    try:
        task = repository.get(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
    return {**_task_summary(task), "artifacts": dict(task.artifacts)}


@router.post("/admin/tasks/{task_id}/retry")
def retry_admin_task(
    task_id: str,
    body: RetryRequest,
    request: Request,
) -> dict[str, str | None]:
    if not body.confirm_possible_charge:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "CHARGE_CONFIRMATION_REQUIRED"},
        )
    repository: TaskRepository = request.app.state.task_repository
    try:
        task = repository.reset_from_stage(task_id, body.stage)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT) from exc
    return _task_summary(task)


@router.get("/admin/tasks/{task_id}/markdown", response_class=FileResponse)
def download_task_markdown(task_id: str, request: Request) -> FileResponse:
    repository: TaskRepository = request.app.state.task_repository
    settings: Settings = request.app.state.settings
    try:
        task = repository.get(task_id)
        writing_path = task.artifacts[TaskStage.WRITING.value]
    except (KeyError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
    task_dir = Path(writing_path)
    if not task_dir.is_absolute():
        task_dir = settings.vault_root / task_dir
    note = task_dir / "note.md"
    try:
        root = settings.vault_root.resolve(strict=True)
        resolved = note.resolve(strict=True)
    except OSError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
    if note.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return FileResponse(resolved, media_type="text/markdown", filename="note.md")


@router.get("/admin/vault/export", response_class=StreamingResponse)
def download_vault_export(request: Request) -> StreamingResponse:
    settings: Settings = request.app.state.settings
    settings.vault_root.mkdir(parents=True, exist_ok=True)
    return export_vault(settings.vault_root)


@router.delete("/admin/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_admin_task(
    task_id: str,
    body: DeleteTaskRequest,
    request: Request,
) -> Response:
    repository: TaskRepository = request.app.state.task_repository
    settings: Settings = request.app.state.settings
    try:
        task = repository.get(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND) from exc
    try:
        _safe_remove_directory(settings.media_tmp_dir, settings.media_tmp_dir / task.id)
        if body.delete_vault and TaskStage.WRITING.value in task.artifacts:
            vault_path = Path(task.artifacts[TaskStage.WRITING.value])
            if not vault_path.is_absolute():
                vault_path = settings.vault_root / vault_path
            _safe_remove_directory(settings.vault_root, vault_path)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT) from exc
    if not repository.delete_terminal(task.id):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
