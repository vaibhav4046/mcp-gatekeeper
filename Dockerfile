# syntax=docker/dockerfile:1
FROM python:3.11-slim-bookworm AS build
COPY --from=ghcr.io/astral-sh/uv:0.13.6 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.11-slim-bookworm
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin gatekeeper \
    && mkdir -p /app/traces && chown 10001 /app/traces
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 GATEKEEPER_TRACE_DIR=/app/traces
USER 10001
EXPOSE 8000
ENTRYPOINT ["mcp-gatekeeper"]
CMD ["serve", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8000"]
