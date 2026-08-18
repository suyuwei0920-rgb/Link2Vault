# Docker 安装与运行

部署目标是 Ubuntu 22.04/24.04、Docker Engine 和 Docker Compose v2。Caddy
是唯一绑定主机端口的服务；API 只在内部网络，Worker 通过单独的出站网络访问
抖音、ASR、清洗和通知服务。

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

首次生产运行还必须填写：

- `LINK2VAULT_ASR_PROVIDER=tencent`；
- 腾讯云 SecretId、SecretKey、地域和私有 COS 桶；
- `LINK2VAULT_CLEANER_PROVIDER=deepseek`、DeepSeek API 根地址和密钥；
- 可选的 Bark API 根地址与设备 Key。

COS 桶必须保持私有，并给 `temporary/` 前缀配置 1 天生命周期规则作为删除失败时的
兜底。腾讯适配器每次先查询预付费资源包：免费录音识别包足够时使用普通引擎，
否则仅在已购录音识别 2.0 包足够时使用 2.0 引擎；无法确认余额或两者均不足时
任务失败并停止。

`/healthz` 公开且只返回状态和版本。`/admin/*` 使用 Caddy Basic Auth，写操作
还要求同源 CSRF 令牌。`/ingest/*` 不使用 Basic Auth，因为应用会验证每台设备的
Bearer Token。请求体受 `LINK2VAULT_MAX_UPLOAD_MB` 限制。

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

Worker 默认单并发运行真实的断点续跑管线。不要在测量腾讯限额、内存占用和失败重试
行为前提高并发。

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
