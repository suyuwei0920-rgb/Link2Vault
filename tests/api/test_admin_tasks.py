from __future__ import annotations

from fastapi.testclient import TestClient
from link2vault.config import Settings
from link2vault.domain.tasks import CaptureSource, TaskStage, TaskStatus
from link2vault.main import create_app


def admin_client(tmp_path):
    settings = Settings(
        data_dir=tmp_path / "state",
        media_tmp_dir=tmp_path / "media",
        vault_root=tmp_path / "vault-root",
        public_base_url="https://example.com",
        token_pepper="test-token-pepper-value",
        csrf_signing_key="test-csrf-signing-key-value",
    )
    app = create_app(settings)
    client = TestClient(app, base_url=settings.public_base_url)
    csrf = client.get("/admin/session").json()["csrf_token"]
    headers = {
        "Origin": settings.public_base_url,
        "X-CSRF-Token": csrf,
    }
    return app, client, headers, settings


def test_admin_history_lists_content_free_task_state(tmp_path) -> None:
    app, client, _headers, _settings = admin_client(tmp_path)
    created = app.state.task_repository.create_capture(
        source=CaptureSource.DOUYIN,
        fingerprint="history-task",
    )

    response = client.get("/admin/tasks")

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": created.id,
            "source": "douyin",
            "status": "queued",
            "stage": "validating",
            "created_at": created.created_at.isoformat(),
            "updated_at": created.updated_at.isoformat(),
            "error_code": None,
        }
    ]


def test_admin_can_explicitly_retry_failed_task_from_stage(tmp_path) -> None:
    app, client, headers, _settings = admin_client(tmp_path)
    repository = app.state.task_repository
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="retry-task",
    )
    repository.claim_next("worker-a")
    repository.fail_stage(created.id, TaskStage.ASR, "ASR_FAILED")

    response = client.post(
        f"/admin/tasks/{created.id}/retry",
        json={"stage": "asr", "confirm_possible_charge": True},
        headers=headers,
    )

    assert response.status_code == 200
    assert repository.get(created.id).status is TaskStatus.QUEUED
    assert repository.get(created.id).stage is TaskStage.ASR


def test_full_delete_removes_only_selected_task_media_and_vault_directory(
    tmp_path,
) -> None:
    app, client, headers, settings = admin_client(tmp_path)
    repository = app.state.task_repository
    created = repository.create_capture(
        source=CaptureSource.RECORDING,
        fingerprint="delete-task",
    )
    repository.claim_next("worker-a")
    vault_dir = settings.vault_root / "2026" / "08" / created.id
    vault_dir.mkdir(parents=True)
    (vault_dir / "note.md").write_text("synthetic", encoding="utf-8")
    for stage in TaskStage:
        artifact = str(vault_dir) if stage is TaskStage.WRITING else f"artifact/{stage.value}"
        repository.complete_stage(created.id, stage, artifact)
    media_dir = settings.media_tmp_dir / created.id
    media_dir.mkdir(parents=True)
    (media_dir / "source.wav").write_bytes(b"synthetic")
    unrelated = settings.vault_root / "keep.md"
    unrelated.write_text("keep", encoding="utf-8")

    response = client.request(
        "DELETE",
        f"/admin/tasks/{created.id}",
        json={"delete_vault": True},
        headers=headers,
    )

    assert response.status_code == 204
    assert not media_dir.exists()
    assert not vault_dir.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert repository.list_tasks() == ()
