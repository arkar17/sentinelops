# Images for the api (and migrate) service, the probe worker and the notifier.
FROM python:3.14-slim AS base

COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY alembic.ini ./
COPY migrations ./migrations
COPY src ./src
RUN uv sync --frozen --no-dev

RUN useradd --system --uid 10001 --no-create-home sentinelops

# Probe worker: applies an egress firewall as root (needs CAP_NET_ADMIN), then drops to 10001.
FROM base AS worker
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
COPY docker/worker-entrypoint.sh /usr/local/bin/worker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/worker-entrypoint.sh"]
CMD ["python", "-m", "sentinelops.worker"]

# Notifier: default-deny egress firewall (database, SMTP relay, Telegram ranges only), then 10001.
FROM base AS notifier
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*
COPY docker/notifier-entrypoint.sh /usr/local/bin/notifier-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/notifier-entrypoint.sh"]
CMD ["python", "-m", "sentinelops.notifier"]

FROM base AS api
USER sentinelops
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
# Forwarded headers are interpreted by the app only for configured trusted proxies.
CMD ["uvicorn", "--factory", "sentinelops.api.app:create_app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers", "--no-server-header"]
