"""
JWT Authentication Middleware
==============================
Validates Bearer tokens on every request except health check and docs.
Supports both JWT tokens (for dashboard users) and static API keys
(for SIEM/webhook integrations).

Set these environment variables:
  JWT_SECRET   — secret key for signing tokens (change in production!)
  API_KEYS     — comma-separated list of valid static API keys
"""
import os
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware

JWT_SECRET    = os.getenv("JWT_SECRET", "asoc-dev-secret-change-in-production")
JWT_ALGORITHM = "HS256"
API_KEYS      = set(filter(None, os.getenv("API_KEYS", "").split(",")))

# Paths that don't require authentication
PUBLIC_PATHS = {"/", "/health", "/metrics", "/docs", "/redoc", "/openapi.json"}


class JWTAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip auth for public paths
        if request.url.path in PUBLIC_PATHS or request.url.path.startswith("/docs"):
            return await call_next(request)

        # Skip auth in development mode
        if os.getenv("ASOC_DEV_MODE", "false").lower() == "true":
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")

        if not auth_header:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authorization header required"},
            )

        # Support: "Bearer <jwt>" or "ApiKey <key>"
        scheme, _, credential = auth_header.partition(" ")

        if scheme.lower() == "apikey":
            if credential not in API_KEYS:
                return JSONResponse(status_code=403, content={"detail": "Invalid API key"})
            return await call_next(request)

        if scheme.lower() == "bearer":
            try:
                payload = jwt.decode(credential, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                request.state.user = payload.get("sub", "unknown")
            except JWTError as exc:
                return JSONResponse(
                    status_code=401,
                    content={"detail": f"Invalid token: {exc}"},
                )
            return await call_next(request)

        return JSONResponse(
            status_code=401,
            content={"detail": "Use 'Bearer <token>' or 'ApiKey <key>'"},
        )


def create_access_token(subject: str, expires_minutes: int = 480) -> str:
    """Create a signed JWT token. Used by /auth/login endpoint."""
    from datetime import datetime, timedelta, timezone
    payload = {
        "sub": subject,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expires_minutes),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
