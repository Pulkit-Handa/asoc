"""
Correlation ID Middleware
=========================
Injects a unique X-Correlation-ID header into every request and response.
Every log line in the same request automatically includes this ID
via the ContextVar in agents/shared/telemetry.py.

This is mandatory for production SOC systems:
  - Compliance audits need to trace a single alert through every log line
  - Support teams need to find "what happened to alert_abc123"
  - The ID is also propagated in the SSE stream so the dashboard can correlate

If the client sends X-Correlation-ID (e.g. your SIEM integration), we
honour their ID. Otherwise we generate a UUID4.
"""
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from agents.shared.telemetry import set_correlation_id, set_user_id

HEADER_NAME = "X-Correlation-ID"


class CorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Honour client-provided ID (SIEM/SOAR integrations send these)
        cid = request.headers.get(HEADER_NAME) or f"req_{uuid4().hex[:16]}"
        set_correlation_id(cid)

        # Inject user_id from JWT state if available
        if hasattr(request.state, "user"):
            set_user_id(str(request.state.user))

        response = await call_next(request)
        response.headers[HEADER_NAME] = cid
        return response
