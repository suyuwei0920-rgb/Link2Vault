# Docker deployment boundary

This Phase 1 deployment targets Ubuntu 22.04 or 24.04 with Docker Engine and
Docker Compose v2. Caddy is the only service with a host port. The API and the
idle Worker placeholder share an internal Docker network and cannot publish a
container port directly.

## Configure

From the repository root, create an ignored runtime environment file:

```bash
cp deploy/docker/.env.example deploy/docker/.env
```

Compose requires this service environment file. The broadly compatible short
`env_file` syntax resolves it as `deploy/docker/.env`; Compose validation and
startup intentionally fail when the required operator file is missing.

Generate a bcrypt password hash locally with Caddy's interactive command, then
set `LINK2VAULT_ADMIN_USER` and `LINK2VAULT_ADMIN_PASSWORD_HASH` in `.env`.
Keep the hash single-quoted so its dollar signs remain literal. The committed
Compose fallback is deliberately unusable example material; replace it before
using `/admin/*`.

```bash
docker run --rm -it caddy:2.10.2-alpine caddy hash-password
```

`/healthz` is public and returns only service status and version. `/admin/*`
requires Caddy Basic Auth. `/ingest/*` is forwarded without Basic Auth because
the Phase 2 application will validate its bearer token. All request bodies are
limited by `LINK2VAULT_MAX_UPLOAD_MB`.

The host binding is loopback-only on port 8080. Put any wider network exposure
behind an operator-controlled firewall or load balancer; never publish the API
or Worker port. If another local service already owns 8080, set
`LINK2VAULT_HTTP_PORT` to an unused loopback port for local validation.

## Validate and start

```bash
docker compose -f deploy/docker/compose.yml config --quiet
docker compose -f deploy/docker/compose.yml up -d --build
curl --fail http://127.0.0.1:8080/healthz
docker compose -f deploy/docker/compose.yml down
```

`down` removes the containers and network but preserves the named volumes
`app-data`, `vault-data`, and `media-tmp`. Back up and inspect those volumes
before any explicit volume-removal operation.

The Worker intentionally runs a non-busy idle command with concurrency `1` in
Phase 1. Phase 2 must replace that command with the real Worker entry point; it
must not increase concurrency until resource and failure behavior are measured.
