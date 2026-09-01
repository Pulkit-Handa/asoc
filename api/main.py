"""
ASOC FastAPI Application — Production
=======================================
All middleware wired in correct order:
  1. CorrelationMiddleware   — inject/propagate X-Correlation-ID
  2. AuditMiddleware         — SOC2 compliance trail to PostgreSQL
  3. JWTAuthMiddleware       — Bearer token + API key validation
  4. RateLimitMiddleware     — per-IP sliding window (Redis-backed in prod)
  5. CORSMiddleware          — browser security headers

Startup sequence:
  1. Validate config (Pydantic Settings — fails fast on bad config)
  2. Setup structured logging + OpenTelemetry
  3. Init PostgreSQL (run Alembic if needed)
  4. Warm up embedding model (HuggingFace, local)
  5. Warm up SecBERT classifier
  6. Register Prometheus metrics
"""
import logging

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from api.middleware.audit import AuditMiddleware
from api.middleware.auth import JWTAuthMiddleware
from api.middleware.correlation import CorrelationMiddleware
from api.middleware.rate_limiter import RateLimitMiddleware
from api.routers import admin, alerts, auth, health, incidents, lessons, reviews, stream
from agents.shared.telemetry import setup_logging, setup_tracing
from config.settings import cfg

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle handler."""
    # ── STARTUP ───────────────────────────────────────────────────────────────
    setup_logging(cfg.log_level, use_json=cfg.log_format == "json")
    setup_tracing(cfg.otel_service_name, cfg.otel_endpoint)

    logger.info(
        "ASOC API starting: env=%s llm=%s embedding=%s",
        cfg.asoc_env, cfg.llm_provider, cfg.embedding_model,
    )

    # Validate PostgreSQL + run migrations
    from data.postgres.session import init_db
    init_db()
    logger.info("PostgreSQL: tables ready")

    # Warm up embedding model (downloads on first run, cached after)
    from agents.shared.embedding import warm_up as embedding_warm_up
    embedding_warm_up()

    # Warm up SecBERT
    from agents.triage.models import SecBERTClassifier
    SecBERTClassifier()
    logger.info("SecBERT: classifier ready")

    # Initialise ClickHouse schema
    try:
        from agents.forensics.clickhouse_client import init_schema
        init_schema()
        logger.info("ClickHouse: schema ready")
    except Exception as exc:
        logger.warning("ClickHouse init failed (non-fatal in dev): %s", exc)

    # Register Sentry if configured
    if cfg.sentry_dsn:
        try:
            import sentry_sdk
            sentry_sdk.init(dsn=cfg.sentry_dsn, environment=cfg.asoc_env.value)
            logger.info("Sentry error tracking enabled")
        except ImportError:
            logger.warning("sentry-sdk not installed — error tracking disabled")

    logger.info("ASOC API ready ✓")

    yield  # Application runs here

    # ── SHUTDOWN ──────────────────────────────────────────────────────────────
    logger.info("ASOC API shutting down...")
    from data.kafka.producer import flush as kafka_flush
    kafka_flush(timeout=5.0)
    logger.info("ASOC API shutdown complete")


app = FastAPI(
    title="ASOC — Autonomous SOC API",
    description=(
        "Self-Evolving Multi-Agent Security Operations Platform. "
        "Processes security alerts through a four-agent AI pipeline with "
        "automatic lesson learning and blast-radius-aware escalation."
    ),
    version="1.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware (order matters — outermost runs first on request, last on response) ──
app.add_middleware(CorrelationMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(JWTAuthMiddleware)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=cfg.rate_limit_requests,
    window_seconds=cfg.rate_limit_window_sec,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "X-Correlation-ID", "user-agent", "Content-Type", "Accept"],
    expose_headers=["X-Correlation-ID"],
)

# ── Prometheus ────────────────────────────────────────────────────────────────
Instrumentator(
    should_group_status_codes=False,
    excluded_handlers=["/health", "/metrics"],
).instrument(app).expose(app, endpoint="/metrics")

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health.router,     prefix="",           tags=["Health"])
app.include_router(auth.router,       prefix="/auth",      tags=["Auth"])
app.include_router(alerts.router,     prefix="/alerts",    tags=["Alerts"])
app.include_router(incidents.router,  prefix="/incidents", tags=["Incidents"])
app.include_router(lessons.router,    prefix="/lessons",   tags=["Lessons"])
app.include_router(reviews.router,    prefix="/reviews",   tags=["Lesson Reviews"])
app.include_router(stream.router,     prefix="/stream",    tags=["Stream"])
