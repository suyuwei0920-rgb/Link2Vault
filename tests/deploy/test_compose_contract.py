from __future__ import annotations

from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = REPOSITORY_ROOT / "deploy/docker/compose.yml"
CADDYFILE_PATH = REPOSITORY_ROOT / "deploy/docker/Caddyfile.example"
ENV_EXAMPLE_PATH = REPOSITORY_ROOT / "deploy/docker/.env.example"
DOCKERFILE_PATH = REPOSITORY_ROOT / "apps/api/Dockerfile"


def load_compose() -> dict[str, object]:
    with COMPOSE_PATH.open(encoding="utf-8") as compose_file:
        compose = yaml.safe_load(compose_file)
    assert isinstance(compose, dict)
    return compose


def test_compose_exposes_only_caddy_and_isolates_application_services() -> None:
    compose = load_compose()
    services = compose["services"]

    assert set(services) == {"api", "worker", "caddy"}
    assert services["caddy"]["ports"] == [
        "127.0.0.1:${LINK2VAULT_HTTP_PORT:-8080}:8080"
    ]
    assert "ports" not in services["api"]
    assert "ports" not in services["worker"]
    assert set(services["api"]["networks"]) == {"internal"}
    assert set(services["worker"]["networks"]) == {"internal"}
    assert set(services["caddy"]["networks"]) == {"edge", "internal"}
    assert compose["networks"]["internal"]["internal"] is True
    assert compose["networks"]["edge"]["internal"] is False


def test_application_containers_have_a_hardened_filesystem_boundary() -> None:
    services = load_compose()["services"]

    for service_name in ("api", "worker"):
        service = services[service_name]
        assert service["read_only"] is True
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["cap_drop"] == ["ALL"]
        assert service["tmpfs"]


def test_named_data_volumes_use_explicit_application_mount_points() -> None:
    compose = load_compose()
    services = compose["services"]
    expected_mounts = {
        "app-data:/var/lib/link2vault/app",
        "vault-data:/var/lib/link2vault/vault",
        "media-tmp:/var/lib/link2vault/media-tmp",
    }

    assert set(compose["volumes"]) == {"app-data", "vault-data", "media-tmp"}
    assert set(services["api"]["volumes"]) == expected_mounts
    assert set(services["worker"]["volumes"]) == expected_mounts


def test_worker_is_single_concurrency_and_does_not_run_the_api_command() -> None:
    services = load_compose()["services"]

    assert services["worker"]["command"] != services["api"]["command"]
    assert services["worker"]["environment"]["LINK2VAULT_WORKER_CONCURRENCY"] == (
        "${LINK2VAULT_WORKER_CONCURRENCY:-1}"
    )


def test_api_healthcheck_calls_the_minimal_health_endpoint() -> None:
    healthcheck = load_compose()["services"]["api"]["healthcheck"]

    assert healthcheck["test"][0] == "CMD"
    assert "/healthz" in " ".join(healthcheck["test"])


def test_caddy_routes_encode_the_public_trust_boundary() -> None:
    caddyfile = CADDYFILE_PATH.read_text(encoding="utf-8")

    assert "request_body" in caddyfile
    assert "max_size {$LINK2VAULT_MAX_UPLOAD_MB:1024}MB" in caddyfile
    assert "handle /healthz" in caddyfile
    assert "handle /admin/*" in caddyfile
    assert "basic_auth" in caddyfile
    assert "handle /ingest/*" in caddyfile
    assert caddyfile.count("reverse_proxy api:8000") == 3

    ingest_block = caddyfile.split("handle /ingest/*", maxsplit=1)[1].split(
        "}", maxsplit=1
    )[0]
    assert "basic_auth" not in ingest_block


def test_non_root_caddy_strips_packaged_file_capability_before_exec() -> None:
    caddy = load_compose()["services"]["caddy"]
    command = caddy["command"]

    assert caddy["entrypoint"] == ["/bin/sh", "-c"]
    assert isinstance(command, list) and len(command) == 1
    assert "cp /usr/bin/caddy /tmp/caddy" in command[0]
    assert "exec /tmp/caddy run" in command[0]
    assert any("exec" in mount for mount in caddy["tmpfs"] if mount.startswith("/tmp:"))


def test_examples_contain_only_safe_defaults_and_empty_operator_values() -> None:
    values = dict(
        line.split("=", maxsplit=1)
        for line in ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )

    assert values == {
        "LINK2VAULT_APP_ENV": "production",
        "LINK2VAULT_MAX_UPLOAD_MB": "1024",
        "LINK2VAULT_MAX_AUDIO_MINUTES_PER_JOB": "240",
        "LINK2VAULT_MONTHLY_AUDIO_MINUTES_LIMIT": "600",
        "LINK2VAULT_WORKER_CONCURRENCY": "1",
        "LINK2VAULT_MEDIA_RETENTION_SUCCESS_HOURS": "24",
        "LINK2VAULT_MEDIA_RETENTION_FAILED_DAYS": "7",
        "LINK2VAULT_LOG_RETENTION_DAYS": "14",
        "LINK2VAULT_HTTP_PORT": "8080",
        "LINK2VAULT_ADMIN_USER": "",
        "LINK2VAULT_ADMIN_PASSWORD_HASH": "",
    }


def test_runtime_image_is_locked_multistage_and_non_root() -> None:
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")

    assert dockerfile.count("FROM python:3.12-slim") == 2
    assert "uv sync --frozen --no-dev" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "COPY ." not in dockerfile
