"""
Rate Limiter — Redis-Backed Sliding Window (Multi-Instance Safe)
================================================================
Old version used a Python dict — one dict per process, reset on restart,
broken the moment you run two API pods.

This version uses Redis sorted sets (one key per IP per minute window).
Every pod reads and writes the same counter.

Algorithm: sliding window log
  - Key: asoc:ratelimit:{ip}
  - Sorted set score = timestamp (ms)
  - ZRANGEBYSCORE removes entries older than window_seconds
  - ZCARD counts current requests in window
  - If count >= max_requests → 429
  - TTL set to window_seconds + 10s buffer (auto-cleanup)

Fallback: if Redis is down, allow the request (fail open).
A rate limiter being down is better than blocking legitimate SOC alerts.
"""
import logging
import time
from typing import Callable

import redis
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from config.settings import cfg

logger = logging.getLogger(__name__)

_SKIP_PATHS = frozenset({"/health", "/health/ready", "/metrics"})


def _get_redis() -> redis.Redis:
    return redis.Redis(
        host=cfg.redis_host,
        port=cfg.redis_port,
        db=cfg.redis_db_ratelimit,
        password=cfg.redis_password.get_secret_value() if cfg.redis_password else None,
        socket_timeout=0.1,       # 100ms — rate limiter must be fast
        socket_connect_timeout=0.1,
        decode_responses=True,
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 1000, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests   = max_requests
        self.window_seconds = window_seconds

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"

        try:
            allowed, current = self._check_rate_limit(client_ip)
        except Exception as exc:
            # Redis is down — fail open (allow request, log warning)
            logger.warning("Rate limiter Redis error (failing open): %s", exc)
            return await call_next(request)

        if not allowed:
            logger.warning(
                "RATE LIMIT EXCEEDED: ip=%s requests=%d limit=%d",
                client_ip, current, self.max_requests,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded: {self.max_requests} requests per {self.window_seconds}s",
                    "current": current,
                    "limit": self.max_requests,
                },
                headers={"Retry-After": str(self.window_seconds)},
            )

        return await call_next(request)

    def _check_rate_limit(self, client_ip: str) -> tuple[bool, int]:
        """
        Sliding window check using Redis sorted set.
        Returns (allowed, current_count).
        Entire operation is atomic via a Lua script.
        """
        r   = _get_redis()
        key = f"asoc:ratelimit:{client_ip}"
        now = int(time.time() * 1000)
        window_start = now - (self.window_seconds * 1000)

        # Atomic Lua script: remove stale entries, count, add new entry
        lua_script = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window_start = tonumber(ARGV[2])
        local max_requests = tonumber(ARGV[3])
        local ttl = tonumber(ARGV[4])

        -- Remove entries outside the window
        redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

        -- Count current entries
        local count = redis.call('ZCARD', key)

        if count < max_requests then
            -- Add this request
            redis.call('ZADD', key, now, now .. '-' .. math.random(1000000))
            redis.call('EXPIRE', key, ttl)
            return {1, count + 1}
        else
            return {0, count}
        end
        """

        result = r.eval(
            lua_script, 1, key,
            now, window_start, self.max_requests, self.window_seconds + 10,
        )
        allowed = bool(result[0])
        current = int(result[1])
        return allowed, current
