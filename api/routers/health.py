"""
Health Check Router
===================
Used by Kubernetes liveness and readiness probes.
Returns 200 if all critical services are reachable, 503 otherwise.
"""
import logging
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/health")
async def health():
    """
    Liveness probe — just confirms the process is alive.
    Kubernetes restarts the pod if this returns non-200.
    """
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@router.get("/health/ready")
async def readiness():
    """
    Readiness probe — confirms all dependencies are reachable.
    Kubernetes stops sending traffic if this fails.
    """
    checks = {}
    all_ok = True

    # Check PostgreSQL
    try:
        from data.postgres.session import engine
        with engine.connect() as conn:
            conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        checks["postgres"] = "ok"
    except Exception as exc:
        checks["postgres"] = f"error: {exc}"
        all_ok = False

    # Check Redis
    try:
        from agents.blast_radius.topology import _get_redis
        _get_redis().ping()
        checks["redis"] = "ok"
    except Exception as exc:
        checks["redis"] = f"error: {exc}"
        all_ok = False

    # Check ChromaDB
    try:
        from agents.shared.chroma_client import get_chroma_client
        get_chroma_client().heartbeat()
        checks["chromadb"] = "ok"
    except Exception as exc:
        checks["chromadb"] = f"error: {exc}"
        all_ok = False

    status_code = 200 if all_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status":    "ready" if all_ok else "degraded",
            "checks":    checks,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )
