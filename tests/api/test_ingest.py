from __future__ import annotations

import io
import sqlite3
import wave

from fastapi.testclient import TestClient
from link2vault.config import Settings
from link2vault.main import create_app


def wav_bytes(seconds: float = 0.1) -> bytes:
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(16_000)
        output.writeframes(b"\x00\x00" * int(16_000 * seconds))
    return buffer.getvalue()


def enrolled_client(
    tmp_path,
    **setting_overrides: object,
) -> tuple[TestClient, dict[str, str]]:
    values: dict[str, object] = {
        "data_dir": tmp_path / "state",
        "media_tmp_dir": tmp_path / "media",
        "public_base_url": "https://example.com",
        "token_pepper": "test-token-pepper-value",
        "csrf_signing_key": "test-csrf-signing-key-value",
    }
    values.update(setting_overrides)
    settings = Settings(**values)
    client = TestClient(create_app(settings), base_url=settings.public_base_url)
    csrf = client.get("/admin/session").json()["csrf_token"]
    code = client.post(
        "/admin/enrollment-codes",
        json={"name": "Recorder"},
        headers={
            "Origin": settings.public_base_url,
            "X-CSRF-Token": csrf,
        },
    ).json()["code"]
    token = client.post("/ingest/enroll", json={"code": code}).json()["token"]
    return client, {"Authorization": f"Bearer {token}"}


def test_authenticated_recording_upload_creates_queued_task_and_final_media(
    tmp_path,
) -> None:
    client, headers = enrolled_client(tmp_path)

    response = client.post(
        "/ingest/recordings",
        headers=headers,
        files={"file": ("meeting.wav", wav_bytes(), "audio/wav")},
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["deduplicated"] is False
    assert payload["status_url"] == f"/ingest/tasks/{payload['task_id']}"
    media_files = list((tmp_path / "media" / payload["task_id"]).iterdir())
    assert [path.name for path in media_files] == ["source.wav"]
    connection = sqlite3.connect(tmp_path / "state" / "link2vault.sqlite3")
    input_ref = connection.execute(
        "SELECT input_ref FROM capture_tasks WHERE id = ?",
        (payload["task_id"],),
    ).fetchone()[0]
    connection.close()
    assert input_ref.endswith("/source.wav")


def test_invalid_recording_creates_no_task_or_orphan(tmp_path) -> None:
    client, headers = enrolled_client(tmp_path)

    response = client.post(
        "/ingest/recordings",
        headers=headers,
        files={"file": ("meeting.wav", b"not-audio", "audio/wav")},
    )

    assert response.status_code == 400
    assert list((tmp_path / "media").rglob("*")) == []


def test_quota_rejection_rolls_back_task_and_upload(tmp_path) -> None:
    client, headers = enrolled_client(tmp_path, monthly_audio_minutes=1)

    response = client.post(
        "/ingest/recordings",
        headers=headers,
        files={"file": ("meeting.wav", wav_bytes(61), "audio/wav")},
    )

    connection = sqlite3.connect(tmp_path / "state" / "link2vault.sqlite3")
    task_count = connection.execute("SELECT COUNT(*) FROM capture_tasks").fetchone()[0]
    connection.close()
    assert response.status_code == 429
    assert task_count == 0
    assert list((tmp_path / "media").rglob("*")) == []


def test_authenticated_link_share_text_is_queued(tmp_path) -> None:
    client, headers = enrolled_client(tmp_path)
    share_url = "https://" + "v." + "douyin.com/example/"

    response = client.post(
        "/ingest/links",
        headers=headers,
        json={"share_text": f"复制打开抖音 {share_url}"},
    )

    assert response.status_code == 202
    assert response.json()["deduplicated"] is False
    connection = sqlite3.connect(tmp_path / "state" / "link2vault.sqlite3")
    input_ref = connection.execute("SELECT input_ref FROM capture_tasks").fetchone()[0]
    connection.close()
    assert input_ref == share_url


def test_ingest_requires_bearer_header(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path / "state", media_tmp_dir=tmp_path / "media")
    client = TestClient(create_app(settings))

    response = client.post(
        "/ingest/links",
        json={"share_text": "no link"},
    )

    assert response.status_code == 401
