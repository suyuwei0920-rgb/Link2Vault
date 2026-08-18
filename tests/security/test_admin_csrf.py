from __future__ import annotations

from fastapi.testclient import TestClient
from link2vault.config import Settings
from link2vault.main import create_app

PUBLIC_URL = "https://example.com"
ORIGIN = {"Origin": PUBLIC_URL}


def build_client(tmp_path) -> TestClient:
    settings = Settings(
        data_dir=tmp_path,
        public_base_url=PUBLIC_URL,
        token_pepper="test-token-pepper-value",
        csrf_signing_key="test-csrf-signing-key-value",
    )
    return TestClient(create_app(settings), base_url=PUBLIC_URL)


def test_admin_mutation_rejects_missing_and_wrong_origin(tmp_path) -> None:
    client = build_client(tmp_path)

    missing = client.post("/admin/enrollment-codes", json={"name": "Phone"})
    wrong = client.post(
        "/admin/enrollment-codes",
        json={"name": "Phone"},
        headers={"Origin": "https://" + "attacker." + "example"},
    )

    assert missing.status_code == 403
    assert wrong.status_code == 403
    assert missing.json() == wrong.json()


def test_admin_mutation_rejects_missing_or_mismatched_double_submit_token(
    tmp_path,
) -> None:
    client = build_client(tmp_path)
    session = client.get("/admin/session").json()

    missing = client.post(
        "/admin/enrollment-codes",
        json={"name": "Phone"},
        headers=ORIGIN,
    )
    mismatch = client.post(
        "/admin/enrollment-codes",
        json={"name": "Phone"},
        headers={**ORIGIN, "X-CSRF-Token": f"{session['csrf_token']}wrong"},
    )

    assert missing.status_code == 403
    assert mismatch.status_code == 403
    assert missing.json() == mismatch.json()


def test_valid_same_origin_double_submit_token_allows_admin_mutation(tmp_path) -> None:
    client = build_client(tmp_path)
    token = client.get("/admin/session").json()["csrf_token"]

    response = client.post(
        "/admin/enrollment-codes",
        json={"name": "Personal phone"},
        headers={**ORIGIN, "X-CSRF-Token": token},
    )

    assert response.status_code == 200
    assert response.json()["device_name"] == "Personal phone"


def test_admin_session_cookie_is_secure_strict_and_returns_no_credentials(
    tmp_path,
) -> None:
    client = build_client(tmp_path)

    response = client.get("/admin/session")

    cookie = response.headers["set-cookie"]
    assert response.status_code == 200
    assert set(response.json()) == {"csrf_token", "expires_in_seconds"}
    assert "l2v_csrf=" in cookie
    assert "Secure" in cookie
    assert "SameSite=strict" in cookie
    assert "HttpOnly" not in cookie


def test_ingest_enrollment_is_not_subject_to_admin_csrf_middleware(tmp_path) -> None:
    client = build_client(tmp_path)
    token = client.get("/admin/session").json()["csrf_token"]
    code = client.post(
        "/admin/enrollment-codes",
        json={"name": "Recorder"},
        headers={**ORIGIN, "X-CSRF-Token": token},
    ).json()["code"]

    response = client.post("/ingest/enroll", json={"code": code})

    assert response.status_code == 200
    assert response.json()["token"]
