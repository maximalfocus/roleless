FROM ghcr.io/astral-sh/uv:0.8.11 AS uv

FROM python:3.13.7-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy
COPY --from=uv /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY scripts ./scripts
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/src" \
    ROLELESS_DB_PATH="/tmp/roleless/roleless.db"
RUN groupadd --system --gid 999 roleless \
    && useradd --system --uid 999 --gid roleless --home-dir /nonexistent roleless
USER roleless
CMD ["uvicorn", "roleless.secure:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

FROM python:3.13.7-slim AS console
WORKDIR /app
COPY console ./console
RUN groupadd --system --gid 999 roleless \
    && useradd --system --uid 999 --gid roleless --home-dir /nonexistent roleless
USER roleless
CMD ["python", "-m", "http.server", "8080", "--bind", "0.0.0.0", "--directory", "/app/console"]

FROM python:3.13.7-slim AS verification
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_LINK_MODE=copy
COPY --from=uv /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project
COPY src ./src
COPY tests ./tests
COPY scripts ./scripts
COPY compose.yaml ./
COPY console ./console
ENV PATH="/app/.venv/bin:$PATH" PYTHONPATH="/app/src"
