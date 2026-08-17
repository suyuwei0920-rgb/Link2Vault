FROM ghcr.io/astral-sh/uv:0.12.1 AS uv

FROM python:3.12-slim AS builder

COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /opt/link2vault
COPY pyproject.toml uv.lock README.md ./
COPY apps/api/link2vault ./apps/api/link2vault
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim AS runtime

ENV PATH="/opt/link2vault/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 link2vault \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin link2vault \
    && mkdir -p \
        /var/lib/link2vault/app \
        /var/lib/link2vault/vault \
        /var/lib/link2vault/media-tmp \
    && chown -R 10001:10001 /var/lib/link2vault

COPY --from=builder --chown=10001:10001 /opt/link2vault/.venv /opt/link2vault/.venv

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "link2vault.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
