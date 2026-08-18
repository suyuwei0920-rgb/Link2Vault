from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from link2vault.config import Settings
from link2vault.main import create_app
from link2vault.security.tokens import EnrollmentService
from link2vault.storage.device_repository import DeviceRepository

NOW = datetime(2026, 8, 18, 9, 0, tzinfo=UTC)
PEPPER = b"unit-test-pepper-not-for-production"


def build_service(tmp_path, now: datetime = NOW) -> EnrollmentService:
    return EnrollmentService(
        DeviceRepository(tmp_path),
        pepper=PEPPER,
        clock=lambda: now,
    )


def test_enrollment_code_is_one_time_and_returns_token_once(tmp_path) -> None:
    service = build_service(tmp_path)
    enrollment = service.issue_code("Personal iPhone")

    issued = service.exchange(enrollment.code)

    assert issued.device.name == "Personal iPhone"
    assert issued.token
    assert service.verify(issued.token).id == issued.device.id
    with pytest.raises(ValueError, match="invalid or expired"):
        service.exchange(enrollment.code)


def test_enrollment_code_expires_after_five_minutes(tmp_path) -> None:
    service = build_service(tmp_path)
    enrollment = service.issue_code("Meeting phone")
    expired_service = build_service(tmp_path, NOW + timedelta(minutes=5, seconds=1))

    with pytest.raises(ValueError, match="invalid or expired"):
        expired_service.exchange(enrollment.code)


def test_database_stores_only_hmac_digests(tmp_path) -> None:
    service = build_service(tmp_path)
    enrollment = service.issue_code("Android recorder")
    issued = service.exchange(enrollment.code)

    connection = sqlite3.connect(tmp_path / "link2vault.sqlite3")
    code_rows = connection.execute(
        "SELECT code_digest FROM enrollment_codes"
    ).fetchall()
    token_rows = connection.execute("SELECT token_digest FROM devices").fetchall()
    connection.close()

    stored_values = {value for row in code_rows + token_rows for value in row}
    assert enrollment.code not in stored_values
    assert issued.token not in stored_values
    assert all(len(value) == 64 for value in stored_values)


def test_revoking_one_device_does_not_revoke_another(tmp_path) -> None:
    service = build_service(tmp_path)
    first = service.exchange(service.issue_code("iPhone").code)
    second = service.exchange(service.issue_code("Xiaomi").code)

    service.revoke(first.device.id)

    with pytest.raises(ValueError, match="unauthorized"):
        service.verify(first.token)
    assert service.verify(second.token).id == second.device.id


def test_unknown_and_revoked_bearer_tokens_have_the_same_response(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, token_pepper=PEPPER.decode())
    client = TestClient(create_app(settings), base_url=settings.public_base_url)
    csrf_token = client.get("/admin/session").json()["csrf_token"]
    admin_headers = {
        "Origin": settings.public_base_url,
        "X-CSRF-Token": csrf_token,
    }
    code = client.post(
        "/admin/enrollment-codes",
        json={"name": "Test phone"},
        headers=admin_headers,
    ).json()["code"]
    enrolled = client.post("/ingest/enroll", json={"code": code}).json()
    device_id = enrolled["device"]["id"]
    token = enrolled["token"]

    accepted = client.get(
        "/ingest/device",
        headers={"Authorization": f"Bearer {token}"},
    )
    client.delete(f"/admin/devices/{device_id}", headers=admin_headers)
    revoked = client.get(
        "/ingest/device",
        headers={"Authorization": f"Bearer {token}"},
    )
    unknown = client.get(
        "/ingest/device",
        headers={"Authorization": "Bearer definitely-unknown"},
    )

    assert accepted.status_code == 200
    assert revoked.status_code == unknown.status_code == 401
    assert revoked.json() == unknown.json() == {
        "detail": {"code": "UNAUTHORIZED", "message": "Device authorization failed"}
    }


def test_long_lived_token_is_ignored_in_query_and_cookie(tmp_path) -> None:
    settings = Settings(data_dir=tmp_path, token_pepper=PEPPER.decode())
    client = TestClient(create_app(settings))

    query = client.get("/ingest/device?token=anything")
    cookie_client = TestClient(create_app(settings))
    cookie_client.cookies.set("device_token", "anything")
    cookie = cookie_client.get("/ingest/device")

    assert query.status_code == 401
    assert cookie.status_code == 401
