# syntax=docker/dockerfile:1
FROM python:3.15-slim AS builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
RUN python -m venv /opt/venv
# Install only the pinned runtime dependencies from pyproject.toml (no dev extra). The project
# metadata is stripped to a dependency-only stub so this layer is cached until pins change.
COPY pyproject.toml ./
RUN /opt/venv/bin/python - <<'PY' > requirements.txt
import tomllib
with open("pyproject.toml", "rb") as f:
    print("\n".join(tomllib.load(f)["project"]["dependencies"]))
PY
RUN /opt/venv/bin/pip install -r requirements.txt

FROM python:3.15-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/srv/backend PATH="/opt/venv/bin:$PATH"
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv/backend
COPY alembic.ini healthcheck.py docker-entrypoint.sh ./
COPY app ./app
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["python", "/srv/backend/healthcheck.py"]
ENTRYPOINT ["./docker-entrypoint.sh"]
