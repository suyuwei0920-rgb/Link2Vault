from __future__ import annotations

import base64
import json
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = REPOSITORY_ROOT / "deploy/docker/compose.yml"
CADDYFILE_PATH = REPOSITORY_ROOT / "deploy/docker/Caddyfile.example"
ENV_EXAMPLE_PATH = REPOSITORY_ROOT / "deploy/docker/.env.example"
DOCKERFILE_PATH = REPOSITORY_ROOT / "apps/api/Dockerfile"
DOCKERIGNORE_PATH = REPOSITORY_ROOT / ".dockerignore"
SAFE_DEFAULT_ADMIN_HASH = (
    "$2a$14$EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
)
RENDERED_SAFE_DEFAULT_ADMIN_HASH = (
    "$$2a$$14$$EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
)


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


def test_caddy_adapts_an_oversize_rejection_before_any_proxy() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker is required to validate the Caddy adapter output")
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--env",
            "LINK2VAULT_MAX_UPLOAD_MB=1",
            "--volume",
            f"{CADDYFILE_PATH}:/etc/caddy/Caddyfile:ro",
            "caddy:2.10.2-alpine",
            "caddy",
            "adapt",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    handlers: list[dict[str, object]] = []

    def collect_handlers(value: object) -> None:
        if isinstance(value, dict):
            if "handler" in value:
                handlers.append(value)
            for child in value.values():
                collect_handlers(child)
        elif isinstance(value, list):
            for child in value:
                collect_handlers(child)

    collect_handlers(json.loads(completed.stdout))
    rejection_indexes = [
        index
        for index, handler in enumerate(handlers)
        if handler.get("handler") == "static_response"
        and handler.get("status_code") == 413
    ]
    assert rejection_indexes, "Caddy must reject a declared oversize body"
    rejection_index = rejection_indexes[0]
    first_proxy_index = next(
        index
        for index, handler in enumerate(handlers)
        if handler.get("handler") == "reverse_proxy"
    )

    assert rejection_index < first_proxy_index
    assert any(
        handler.get("handler") == "request_body"
        and handler.get("max_size") == 1_000_000
        for handler in handlers
    )
    authentication = next(
        handler for handler in handlers if handler.get("handler") == "authentication"
    )
    fallback_account = authentication["providers"]["http_basic"]["accounts"][0]
    assert fallback_account == {
        "password": "$2a$14$EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
        "username": "example-admin",
    }


def test_non_root_caddy_strips_packaged_file_capability_before_exec() -> None:
    caddy = load_compose()["services"]["caddy"]
    command = caddy["command"]

    assert caddy["entrypoint"] == ["/bin/sh", "-c"]
    assert isinstance(command, list) and len(command) == 1
    assert "cp /usr/bin/caddy /tmp/caddy" in command[0]
    assert "exec /tmp/caddy run" in command[0]
    assert any("exec" in mount for mount in caddy["tmpfs"] if mount.startswith("/tmp:"))


def test_caddy_uses_only_compose_v2_compatible_interpolated_environment() -> None:
    caddy = load_compose()["services"]["caddy"]

    assert "env_file" not in caddy
    assert caddy["environment"] == {
        "LINK2VAULT_ADMIN_USER": "${LINK2VAULT_ADMIN_USER:-example-admin}",
        "LINK2VAULT_ADMIN_PASSWORD_HASH": (
            "${LINK2VAULT_ADMIN_PASSWORD_HASH:-"
            "$$2a$$14$$EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE}"
        ),
        "LINK2VAULT_MAX_UPLOAD_MB": "${LINK2VAULT_MAX_UPLOAD_MB:-1024}",
    }


def test_clean_checkout_compose_config_resolves_safe_caddy_defaults() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose v2 is required for the deployment contract")

    completed = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_PATH), "config"],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    caddy_environment = yaml.safe_load(completed.stdout)["services"]["caddy"][
        "environment"
    ]
    assert caddy_environment == {
        "LINK2VAULT_ADMIN_PASSWORD_HASH": RENDERED_SAFE_DEFAULT_ADMIN_HASH,
        "LINK2VAULT_ADMIN_USER": "example-admin",
        "LINK2VAULT_MAX_UPLOAD_MB": "1024",
    }


def test_explicit_env_file_overrides_reach_caddy(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose v2 is required for the deployment contract")

    environment_file = tmp_path / "operator.env"
    environment_file.write_text(
        "LINK2VAULT_ADMIN_USER=test-admin\n"
        "LINK2VAULT_ADMIN_PASSWORD_HASH=DUMMY_NOT_A_REAL_HASH\n"
        "LINK2VAULT_MAX_UPLOAD_MB=1\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(environment_file),
            "-f",
            str(COMPOSE_PATH),
            "config",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    caddy_environment = yaml.safe_load(completed.stdout)["services"]["caddy"][
        "environment"
    ]
    assert caddy_environment == {
        "LINK2VAULT_ADMIN_PASSWORD_HASH": "DUMMY_NOT_A_REAL_HASH",
        "LINK2VAULT_ADMIN_USER": "test-admin",
        "LINK2VAULT_MAX_UPLOAD_MB": "1",
    }


def test_empty_admin_env_file_values_remain_fail_closed(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose v2 is required for the deployment contract")

    environment_file = tmp_path / "empty-admin.env"
    environment_file.write_text(
        "LINK2VAULT_ADMIN_USER=\n"
        "LINK2VAULT_ADMIN_PASSWORD_HASH=\n"
        "LINK2VAULT_MAX_UPLOAD_MB=\n",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(environment_file),
            "-f",
            str(COMPOSE_PATH),
            "config",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    caddy_environment = yaml.safe_load(completed.stdout)["services"]["caddy"][
        "environment"
    ]
    assert caddy_environment == {
        "LINK2VAULT_ADMIN_PASSWORD_HASH": RENDERED_SAFE_DEFAULT_ADMIN_HASH,
        "LINK2VAULT_ADMIN_USER": "example-admin",
        "LINK2VAULT_MAX_UPLOAD_MB": "1024",
    }


def test_configured_compose_enforces_auth_and_upload_limit(tmp_path: Path) -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker Compose v2 is required for the runtime contract")
    daemon = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, check=False
    )
    if daemon.returncode != 0:
        pytest.skip(f"Docker daemon is unavailable: {daemon.stderr.strip()}")

    password = "phase1-contract-test-password"
    password_hash = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "caddy:2.10.2-alpine",
            "caddy",
            "hash-password",
            "--plaintext",
            password,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        host_port = listener.getsockname()[1]
    environment_file = tmp_path / "runtime.env"
    environment_file.write_text(
        "LINK2VAULT_ADMIN_USER=contract-admin\n"
        f"LINK2VAULT_ADMIN_PASSWORD_HASH='{password_hash}'\n"
        "LINK2VAULT_MAX_UPLOAD_MB=1\n"
        f"LINK2VAULT_HTTP_PORT={host_port}\n",
        encoding="utf-8",
    )
    project_name = f"link2vault-contract-{uuid.uuid4().hex[:12]}"
    compose = [
        "docker",
        "compose",
        "--env-file",
        str(environment_file),
        "--project-name",
        project_name,
        "-f",
        str(COMPOSE_PATH),
    ]
    started = subprocess.run(
        [*compose, "up", "-d", "--build"],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    base_url = f"http://127.0.0.1:{host_port}"
    try:
        assert started.returncode == 0, started.stderr
        deadline = time.monotonic() + 30
        while True:
            try:
                with urlopen(f"{base_url}/healthz", timeout=2) as response:
                    if response.status == 200:
                        break
            except OSError:
                if time.monotonic() >= deadline:
                    logs = subprocess.run(
                        [*compose, "logs", "--no-color"],
                        cwd=REPOSITORY_ROOT,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    pytest.fail(f"stack did not become healthy:\n{logs.stdout}")
                time.sleep(0.25)

        with pytest.raises(HTTPError) as unauthorized:
            urlopen(f"{base_url}/admin/example", timeout=5)
        assert unauthorized.value.code == 401

        authorization = base64.b64encode(
            f"contract-admin:{password}".encode()
        ).decode()
        authorized_request = Request(
            f"{base_url}/admin/example",
            headers={"Authorization": f"Basic {authorization}"},
        )
        with pytest.raises(HTTPError) as authorized:
            urlopen(authorized_request, timeout=5)
        assert authorized.value.code == 404
        assert json.loads(authorized.value.read()) == {"detail": "Not Found"}

        oversize_request = Request(
            f"{base_url}/ingest/example",
            data=b"x" * 1_000_001,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        with pytest.raises(HTTPError) as oversize:
            urlopen(oversize_request, timeout=10)
        assert oversize.value.code == 413
    finally:
        subprocess.run(
            [*compose, "down", "--volumes"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )


def test_dockerignore_exports_only_the_required_build_inputs(tmp_path: Path) -> None:
    assert DOCKERIGNORE_PATH.is_file(), "the root Docker build context must be bounded"
    if shutil.which("docker") is None:
        pytest.skip("Docker is required to pressure-test the build context")
    daemon = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, check=False
    )
    if daemon.returncode != 0:
        pytest.skip(f"Docker daemon is unavailable: {daemon.stderr.strip()}")

    context = tmp_path / "context"
    required_files = {
        "pyproject.toml": "[project]\nname='context-test'\nversion='0.0.0'\n",
        "uv.lock": "version = 1\n",
        "apps/api/link2vault/__init__.py": "__version__ = '0.0.0'\n",
        "apps/api/link2vault/main.py": "APP = 'test'\n",
        "apps/api/link2vault/subpackage/worker.py": "WORKER = 'test'\n",
    }
    excluded_files = {
        ".git/config": "private repository metadata\n",
        ".env.production": "TOKEN=private\n",
        ".venv/private.txt": "private environment\n",
        ".superpowers/plan.md": "private plan\n",
        "data/private.txt": "private data\n",
        "vault/private.md": "private vault\n",
        "media-tmp/private.m4a": "private media\n",
        "recordings/private.wav": "private recording\n",
        "transcripts/private.vtt": "private transcript\n",
        "release.zip": "private archive\n",
        "mobile.apk": "private application\n",
        "signing.pem": "private signing material\n",
        "docs/guide.md": "unrelated documentation\n",
        "tests/test_unrelated.py": "unrelated test\n",
        "unrelated/source.py": "unrelated source\n",
        "apps/api/link2vault/.env": "TOKEN=private\n",
        "apps/api/link2vault/nested/.env.local": "TOKEN=private\n",
        "apps/api/link2vault/private.pem": "private signing material\n",
        "apps/api/link2vault/nested/secret.key": "private signing material\n",
        "apps/api/link2vault/recording.m4a": "private recording\n",
        "apps/api/link2vault/nested/audio.wav": "private audio\n",
        "apps/api/link2vault/release.zip": "private archive\n",
        "apps/api/link2vault/mobile.apk": "private application\n",
        "apps/api/link2vault/__pycache__/main.cpython-312.pyc": "private cache\n",
        "apps/api/link2vault/.pytest_cache/v/cache/nodeids": "private cache\n",
        "apps/api/link2vault/transcript.vtt": "private transcript\n",
        "apps/api/link2vault/database.sqlite": "private database\n",
    }
    for relative_path, content in (required_files | excluded_files).items():
        path = context / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    shutil.copy2(DOCKERIGNORE_PATH, context / ".dockerignore")
    dockerfile = context / "Dockerfile.context-test"
    dockerfile.write_text("FROM scratch\nCOPY . /\n", encoding="utf-8")
    exported = tmp_path / "exported"
    completed = subprocess.run(
        [
            "docker",
            "build",
            "--file",
            str(dockerfile),
            "--output",
            f"type=local,dest={exported}",
            str(context),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    for relative_path in required_files:
        assert (exported / relative_path).is_file()
    for relative_path in excluded_files:
        assert not (exported / relative_path).exists()


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
