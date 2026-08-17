# Docker deployment boundary

This Phase 1 deployment targets Ubuntu 22.04 or 24.04 with Docker Engine and
Docker Compose v2. Caddy is the only service with a host port. The API and the
idle Worker placeholder share an internal Docker network and cannot publish a
container port directly. The API remains internal-only; the Worker additionally
joins a dedicated outbound-capable network for future Douyin, ASR, LLM, and
Bark calls. Caddy joins only the edge and internal networks.

## Configure

The clean checkout starts with fail-closed example credentials and a 1024 MB
request limit. For operator overrides, create an ignored runtime environment
file from the repository root:

```bash
cp deploy/docker/.env.example deploy/docker/operator.env
```

Compose can discover a project-directory `.env` implicitly. Link2Vault
deliberately uses the non-default, ignored `operator.env` name so every override
is explicit. Pass it with the broadly supported
`--env-file deploy/docker/operator.env` option. Empty admin values use the
committed unusable example credentials rather than disabling authentication.

Generate a bcrypt password hash locally with Caddy's interactive command, then
set `LINK2VAULT_ADMIN_USER` and `LINK2VAULT_ADMIN_PASSWORD_HASH` in
`operator.env`.
Keep the hash single-quoted so its dollar signs remain literal. The committed
Compose fallback is deliberately unusable example material; replace it before
using `/admin/*`.

```bash
docker run --rm -it caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d caddy hash-password
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

Clean-checkout smoke validation uses the safe defaults and requires no local
environment file:

```bash
docker compose -f deploy/docker/compose.yml config --quiet
docker compose -f deploy/docker/compose.yml up -d --build
curl --fail http://127.0.0.1:8080/healthz
docker compose -f deploy/docker/compose.yml down
```

After configuring operator values, include `--env-file` on every Compose command
that must use them:

```bash
docker compose --env-file deploy/docker/operator.env -f deploy/docker/compose.yml config --quiet
docker compose --env-file deploy/docker/operator.env -f deploy/docker/compose.yml up -d --build
curl --fail http://127.0.0.1:8080/healthz
docker compose --env-file deploy/docker/operator.env -f deploy/docker/compose.yml down
```

`down` removes the containers and network but preserves the named volumes
`app-data`, `vault-data`, and `media-tmp`. Back up and inspect those volumes
before any explicit volume-removal operation.

The Worker intentionally runs a non-busy idle command with concurrency `1` in
Phase 1. Phase 2 must replace that command with the real Worker entry point; it
must not increase concurrency until resource and failure behavior are measured.

## Update immutable image pins

The readable image tags in `apps/api/Dockerfile` and `deploy/docker/compose.yml`
are paired with immutable multi-architecture manifest digests. Before updating
a tag or digest, inspect the official manifest and confirm it includes the
target `linux/amd64` and `linux/arm64` platforms:

```bash
docker buildx imagetools inspect ghcr.io/astral-sh/uv:0.12.1
docker buildx imagetools inspect python:3.12-slim
docker buildx imagetools inspect caddy:2.10.2-alpine
```

Update the readable tag and its top-level `Digest` together, rebuild without
cache, and rerun the Compose contract and configured runtime tests. Never copy
an architecture-specific child digest into the multi-architecture pin.
