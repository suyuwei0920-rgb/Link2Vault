import pytest
from fastapi.testclient import TestClient
from link2vault.config import Settings
from link2vault.main import create_app


def test_health_exposes_only_status_and_version() -> None:
    response = TestClient(create_app()).get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": "0.1.0"}


def test_settings_reject_unknown_prefixed_environment_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LINK2VAULT_UNSUPPORTED", "value")

    with pytest.raises(ValueError, match="LINK2VAULT_UNSUPPORTED"):
        Settings()
