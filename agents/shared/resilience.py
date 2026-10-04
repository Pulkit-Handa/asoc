"""
Resilience Module
=================
Circuit breakers and retry logic for every external service call.

Without this, a 10-second ClickHouse blip at 3am drops 50,000 alerts.
With this, it retries with backoff, falls back gracefully, and recovers
automatically when the service comes back.

Circuit breaker states:
  CLOSED   → Normal operation. Requests pass through.
  OPEN     → Service is down. Requests fail immediately (no timeout wait).
             Auto-recovers after RECOVERY_TIMEOUT seconds.
  HALF_OPEN → Testing if service recovered. One probe request allowed.

Usage:
    from agents.shared.resilience import with_circuit_breaker, with_retry

    @with_retry(max_attempts=3, service="chromadb")
    @with_circuit_breaker(service="chromadb")
    def query_lessons(text: str):
        return collection.query(query_texts=[text], n_results=3)
"""
from __future__ import annotations

import asyncio
import functools
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


# ── Circuit Breaker ───────────────────────────────────────────────────────────

class BreakerState(Enum):
    CLOSED    = "CLOSED"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class CircuitBreaker:
    service:          str
    failure_threshold: int   = 5      # Failures before OPEN
    recovery_timeout:  float = 30.0   # Seconds to wait before HALF_OPEN probe
    success_threshold: int   = 2      # Successes in HALF_OPEN before CLOSED

    _state:           BreakerState = field(default=BreakerState.CLOSED, init=False)
    _failure_count:   int          = field(default=0, init=False)
    _success_count:   int          = field(default=0, init=False)
    _last_failure_at: float        = field(default=0.0, init=False)

    def call(self, fn: Callable, *args, **kwargs) -> Any:
        if self._state == BreakerState.OPEN:
            if time.monotonic() - self._last_failure_at >= self.recovery_timeout:
                logger.info("Circuit HALF_OPEN: probing %s", self.service)
                self._state = BreakerState.HALF_OPEN
            else:
                raise ServiceUnavailableError(
                    f"Circuit OPEN for {self.service}. "
                    f"Retry in {self.recovery_timeout - (time.monotonic() - self._last_failure_at):.0f}s"
                )

        try:
            result = fn(*args, **kwargs)
            self._on_success()
            return result
        except Exception as exc:
            self._on_failure(exc)
            raise

    def _on_success(self):
        if self._state == BreakerState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                logger.info("Circuit CLOSED: %s has recovered", self.service)
                self._state         = BreakerState.CLOSED
                self._failure_count = 0
                self._success_count = 0
        elif self._state == BreakerState.CLOSED:
            self._failure_count = 0  # Reset on success

    def _on_failure(self, exc: Exception):
        self._failure_count   += 1
        self._last_failure_at  = time.monotonic()
        self._success_count    = 0

        if self._state == BreakerState.HALF_OPEN or self._failure_count >= self.failure_threshold:
            logger.error(
                "Circuit OPEN: %s failed %d times. Last error: %s",
                self.service, self._failure_count, exc,
            )
            self._state = BreakerState.OPEN

    @property
    def state(self) -> BreakerState:
        return self._state


class ServiceUnavailableError(Exception):
    """Raised when a circuit breaker is OPEN."""
    pass


# Global registry: one breaker per service
_breakers: dict[str, CircuitBreaker] = {}


def get_breaker(service: str, **kwargs) -> CircuitBreaker:
    if service not in _breakers:
        _breakers[service] = CircuitBreaker(service=service, **kwargs)
    return _breakers[service]


# ── Retry with Exponential Backoff ────────────────────────────────────────────

def retry(
    fn: Optional[F] = None,
    *,
    max_attempts: int = 3,
    base_delay: float = 0.5,
    max_delay: float  = 10.0,
    backoff: float    = 2.0,
    exceptions: tuple = (Exception,),
    service: str      = "unknown",
) -> F:
    """
    Decorator: retry with exponential backoff.

    Usage:
        @retry(max_attempts=3, service="chromadb")
        def my_function():
            ...
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = base_delay
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except ServiceUnavailableError:
                    raise  # Don't retry an open circuit
                except exceptions as exc:
                    last_exc = exc
                    if attempt == max_attempts:
                        logger.error(
                            "RETRY EXHAUSTED: service=%s fn=%s attempts=%d error=%s",
                            service, func.__name__, max_attempts, exc,
                        )
                        raise
                    logger.warning(
                        "RETRY %d/%d: service=%s fn=%s error=%s delay=%.1fs",
                        attempt, max_attempts, service, func.__name__, exc, delay,
                    )
                    time.sleep(delay)
                    delay = min(delay * backoff, max_delay)
            raise last_exc  # Unreachable but satisfies type checkers

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            delay = base_delay
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return await func(*args, **kwargs)
                except ServiceUnavailableError:
                    raise
                except exceptions as exc:
                    last_exc = exc
                    if attempt == max_attempts:
                        logger.error(
                            "RETRY EXHAUSTED: service=%s fn=%s attempts=%d error=%s",
                            service, func.__name__, max_attempts, exc,
                        )
                        raise
                    logger.warning(
                        "RETRY %d/%d: service=%s fn=%s error=%s delay=%.1fs",
                        attempt, max_attempts, service, func.__name__, exc, delay,
                    )
                    await asyncio.sleep(delay)
                    delay = min(delay * backoff, max_delay)
            raise last_exc

        import asyncio as _asyncio
        if _asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore
        return wrapper  # type: ignore

    if fn is not None:
        return decorator(fn)
    return decorator  # type: ignore


def with_fallback(fallback_value: Any, service: str = "unknown"):
    """
    Decorator: return fallback_value instead of raising on failure.
    Use for non-critical operations (e.g., lesson retrieval failing
    should not block alert triage — use empty lessons list as fallback).

    Usage:
        @with_fallback(fallback_value=[], service="chromadb")
        def retrieve_lessons(text):
            return collection.query(...)
    """
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                logger.warning(
                    "FALLBACK: service=%s fn=%s error=%s returning default",
                    service, func.__name__, exc,
                )
                return fallback_value

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as exc:
                logger.warning(
                    "FALLBACK: service=%s fn=%s error=%s returning default",
                    service, func.__name__, exc,
                )
                return fallback_value

        import asyncio as _asyncio
        if _asyncio.iscoroutinefunction(func):
            return async_wrapper  # type: ignore
        return wrapper  # type: ignore

    return decorator


def get_all_breaker_status() -> dict[str, str]:
    """Return current state of all circuit breakers. Exposed via /health/ready."""
    return {name: b.state.value for name, b in _breakers.items()}
