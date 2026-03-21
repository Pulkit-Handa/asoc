"""
Telemetry — Structured Logging + Distributed Tracing
======================================================
Every log line in production is a JSON object. Every alert has a
trace ID that links logs across the API, Triage Agent, Forensics Agent,
Blast Radius Agent, and Critic Agent into a single waterfall diagram
in Jaeger/Grafana Tempo.

Why this matters for MNCs/GCCs:
  - Compliance teams need to audit exactly what happened to each alert
  - SRE teams need to find why a specific alert took 4 seconds instead of 2
  - Without trace IDs, correlating logs across 3+ microservices is guesswork

Setup:
  - Set OTEL_ENDPOINT=http://jaeger:4317 in .env for Jaeger/Grafana Tempo
  - Leave blank to disable tracing (logs still work without it)
  - ASOC_ENV=production automatically enables JSON log format
"""
from __future__ import annotations

import json
import logging
import sys
import traceback
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Optional

# Context vars — these propagate through async code automatically
_correlation_id: ContextVar[str] = ContextVar("correlation_id", default="")
_alert_id:       ContextVar[str] = ContextVar("alert_id",       default="")
_user_id:        ContextVar[str] = ContextVar("user_id",        default="")


def set_correlation_id(cid: str) -> None:
    _correlation_id.set(cid)


def set_alert_id(aid: str) -> None:
    _alert_id.set(aid)


def set_user_id(uid: str) -> None:
    _user_id.set(uid)


def get_correlation_id() -> str:
    return _correlation_id.get()


def get_alert_id() -> str:
    return _alert_id.get()


# ── Structured JSON Log Formatter ────────────────────────────────────────────

class JSONLogFormatter(logging.Formatter):
    """
    Emits each log record as a single JSON line.
    Includes correlation_id and alert_id from context vars automatically.

    Compatible with: Elasticsearch, Splunk, Loki, Google Cloud Logging,
    Datadog, CloudWatch.
    """
    SERVICE_NAME: str = "asoc"

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "level":          record.levelname,
            "logger":         record.name,
            "message":        record.getMessage(),
            "service":        self.SERVICE_NAME,
            "module":         record.module,
            "function":       record.funcName,
            "line":           record.lineno,
        }

        # Inject trace context
        if cid := _correlation_id.get():
            log_obj["correlation_id"] = cid
        if aid := _alert_id.get():
            log_obj["alert_id"] = aid
        if uid := _user_id.get():
            log_obj["user_id"] = uid

        # Exception info
        if record.exc_info:
            log_obj["exception"] = {
                "type":    record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]),
                "stack":   traceback.format_exception(*record.exc_info),
            }

        # Any extra fields passed via logger.info("msg", extra={"key": "val"})
        for key, val in record.__dict__.items():
            if key not in {
                "name", "msg", "args", "created", "filename", "funcName",
                "levelname", "levelno", "lineno", "module", "msecs",
                "message", "pathname", "process", "processName",
                "relativeCreated", "stack_info", "thread", "threadName",
                "exc_info", "exc_text",
            } and not key.startswith("_"):
                log_obj[key] = val

        return json.dumps(log_obj, default=str)


# ── OpenTelemetry Tracing ─────────────────────────────────────────────────────

_tracer = None


def setup_tracing(service_name: str, endpoint: str) -> None:
    """
    Initialise OpenTelemetry tracing with OTLP gRPC export.
    Call once from api/main.py on startup.

    If endpoint is empty, tracing is disabled (no-op).
    """
    global _tracer

    if not endpoint:
        logging.getLogger(__name__).info("OTel tracing disabled (no OTEL_ENDPOINT set)")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        resource = Resource(attributes={"service.name": service_name})
        provider = TracerProvider(resource=resource)
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        logging.getLogger(__name__).info("OTel tracing enabled: endpoint=%s", endpoint)

    except ImportError:
        logging.getLogger(__name__).warning(
            "opentelemetry packages not installed — tracing disabled. "
            "Install with: poetry add opentelemetry-sdk opentelemetry-exporter-otlp"
        )


def get_tracer():
    """Return the configured tracer, or a no-op tracer if not configured."""
    if _tracer:
        return _tracer
    try:
        from opentelemetry import trace
        return trace.get_tracer("asoc-noop")
    except ImportError:
        return _NoopTracer()


class _NoopTracer:
    """Fallback when OTel is not installed — zero-cost no-op."""
    def start_as_current_span(self, name: str, **kwargs):
        from contextlib import contextmanager

        @contextmanager
        def _noop():
            yield _NoopSpan()

        return _noop()


class _NoopSpan:
    def set_attribute(self, *args, **kwargs): pass
    def record_exception(self, *args, **kwargs): pass
    def set_status(self, *args, **kwargs): pass


# ── Logging Setup ─────────────────────────────────────────────────────────────

def setup_logging(level: str = "INFO", use_json: bool = True) -> None:
    """
    Configure the root logger. Call once from api/main.py and worker main.

    use_json=True  → structured JSON (production, Kubernetes, log aggregators)
    use_json=False → human-readable text (development)
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Remove existing handlers
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)

    if use_json:
        handler.setFormatter(JSONLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)-8s [%(name)s:%(lineno)d] %(message)s",
                datefmt="%H:%M:%S",
            )
        )

    root.addHandler(handler)

    # Reduce noisy third-party loggers
    for noisy in ("urllib3", "httpcore", "httpx", "asyncio", "confluent_kafka"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
