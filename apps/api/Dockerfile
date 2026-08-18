FROM ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded AS uv

FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS builder

COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /opt/link2vault
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY apps/api/link2vault ./apps/api/link2vault

FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS runtime

ENV PATH="/opt/link2vault/.venv/bin:$PATH" \
    PYTHONPATH="/opt/link2vault/apps/api" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 link2vault \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin link2vault \
    && apt-get update \
    && apt-get install --yes --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p \
        /var/lib/link2vault/app \
        /var/lib/link2vault/vault \
        /var/lib/link2vault/media-tmp \
    && chown -R 10001:10001 /var/lib/link2vault

COPY --from=builder --chown=10001:10001 /opt/link2vault/.venv /opt/link2vault/.venv
COPY --from=builder --chown=10001:10001 /opt/link2vault/apps/api/link2vault /opt/link2vault/apps/api/link2vault
COPY --chown=10001:10001 packages/providers/link2vault_providers /opt/link2vault/apps/api/link2vault_providers
COPY --chown=10001:10001 apps/api/link2vault-worker /opt/link2vault/bin/link2vault-worker

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "link2vault.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
