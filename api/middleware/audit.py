"""
Audit Logging Middleware
=========================
Writes an immutable audit record for every significant API action.

Required for:
  SOC2 Type I/II  — all security system access must be logged
  ISO 27001       — audit trail of all privileged actions
  GDPR            — data access logging for PII-containing endpoints
  Enterprise SOCs — "who did what, when, and what changed"

Every record contains:
  - WHO   (user_id, IP address, user agent)
  - WHAT  (HTTP method + path)
  - WHEN  (UTC timestamp to millisecond)
  - RESULT (status code, response time)
  - CONTEXT (correlation_id for cross-log tracing)

Records are written to the audit_logs table in PostgreSQL.
This table should be made append-only at the DB level:
  REVOKE UPDATE, DELETE ON audit_logs FROM asoc_app_user;

Paths that are NOT audited (too high volume, no security relevance):
  /health, /health/ready, /metrics, /docs, /redoc, /openapi.json
"""
import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from agents.shared.telemetry import get_correlation_id

logger = logging.getLogger(__name__)

_SKIP_PATHS = frozenset({
    "/health", "/health/ready", "/metrics",
    "/docs", "/redoc", "/openapi.json",
})

# Paths that modify security data — always audit regardless of status
_HIGH_VALUE_PATHS = frozenset({
    "/alerts", "/incidents", "/lessons", "/auth",
})


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        t0 = time.monotonic()
        status_code = 500

        try:
            response   = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            user_id    = getattr(request.state, "user", "anonymous")
            client_ip  = request.client.host if request.client else "unknown"

            # Always write structured log (goes to log aggregator)
            logger.info(
                "API_ACCESS",
                extra={
                    "event_type":     "api_access",
                    "method":         request.method,
                    "path":           request.url.path,
                    "status_code":    status_code,
                    "response_ms":    elapsed_ms,
                    "user_id":        user_id,
                    "client_ip":      client_ip,
                    "correlation_id": get_correlation_id(),
                    "user_agent":     request.headers.get("user-agent", ""),
                },
            )

            # Write to DB for compliance-sensitive paths
            is_mutating = request.method in ("POST", "PUT", "PATCH", "DELETE")
            is_sensitive = any(request.url.path.startswith(p) for p in _HIGH_VALUE_PATHS)

            if is_mutating or is_sensitive:
                _write_audit_record_async(
                    user_id=str(user_id),
                    action=f"{request.method} {request.url.path}",
                    resource=request.url.path,
                    client_ip=client_ip,
                    status_code=status_code,
                    response_ms=elapsed_ms,
                    correlation_id=get_correlation_id(),
                )


def _write_audit_record_async(
    user_id: str,
    action: str,
    resource: str,
    client_ip: str,
    status_code: int,
    response_ms: int,
    correlation_id: str,
) -> None:
    """
    Fire-and-forget audit record write.
    Uses a try/except so audit failures never block the response.
    """
    try:
        from datetime import datetime, timezone
        from data.postgres.session import get_session
        from data.postgres.models import AuditLog

        with get_session() as session:
            session.add(AuditLog(
                user_id=user_id,
                action=action,
                resource=resource,
                client_ip=client_ip,
                status_code=status_code,
                response_ms=response_ms,
                correlation_id=correlation_id,
                created_at=datetime.now(timezone.utc),
            ))
    except Exception as exc:
        # Audit write failure must not affect the response.
        # But we must log it — audit gaps are a compliance issue.
        logger.error("AUDIT WRITE FAILED: %s — action=%s user=%s", exc, action, user_id)
