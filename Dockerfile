# ─────────────────────────────────────────────────────────────────────────────
# ASOC Dockerfile — Multi-stage build
# Stage "api":    FastAPI server
# Stage "worker": Kafka consumer worker
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim AS base

WORKDIR /app

# System deps for psycopg2, cryptography, torch
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libpq-dev curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.2

# Copy dependency files first (Docker layer cache)
COPY pyproject.toml poetry.lock* ./

# Install Python dependencies (no dev deps in production)
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main

# Copy source code
COPY . .

# ── API stage ─────────────────────────────────────────────────────────────────
FROM base AS api

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "4", "--log-level", "info"]

# ── Worker stage ──────────────────────────────────────────────────────────────
FROM base AS worker

HEALTHCHECK --interval=60s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "from data.kafka.consumer import _build_consumer; c = _build_consumer(); c.close()" || exit 1

CMD ["python", "-m", "data.kafka.consumer"]
