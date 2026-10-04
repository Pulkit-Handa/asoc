"""
Dead Letter Queue (DLQ) Handler
================================
When an alert fails processing (pipeline crash, model error, DB timeout),
instead of silently dropping it, we:
  1. Retry up to cfg.kafka_max_retries times with exponential backoff
  2. If all retries fail, publish to security.dlq Kafka topic
  3. Write a record to the dlq_incidents PostgreSQL table
  4. Expose /admin/dlq for operators to replay or dismiss failed alerts

This is mandatory for production SOC systems. Silently dropping alerts
means attackers can potentially trigger errors to evade detection.

DLQ topics:
  security.dlq            — all failed alerts with error context
  security.dlq.replay     — operator-triggered replays (re-enters pipeline)
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from agents.orchestrator.state import SOCState
from config.settings import cfg

logger = logging.getLogger(__name__)


@dataclass
class DLQRecord:
    alert_id:     str
    raw_message:  str
    error_type:   str
    error_message: str
    attempt:      int
    topic:        str
    partition:    int
    offset:       int
    failed_at:    str
    payload:      dict


def should_retry(attempt: int) -> bool:
    return attempt < cfg.kafka_max_retries


def send_to_dlq(
    raw_message: str,
    error: Exception,
    attempt: int,
    topic: str,
    partition: int,
    offset: int,
    alert_id: str = "unknown",
    payload: dict | None = None,
) -> None:
    """
    Write a failed alert to the DLQ Kafka topic and log it.
    Called by the Kafka consumer after all retries are exhausted.
    """
    record = DLQRecord(
        alert_id=alert_id,
        raw_message=raw_message[:4096],     # Truncate large payloads
        error_type=type(error).__name__,
        error_message=str(error)[:1024],
        attempt=attempt,
        topic=topic,
        partition=partition,
        offset=offset,
        failed_at=datetime.now(timezone.utc).isoformat(),
        payload=payload or {},
    )

    logger.error(
        "DLQ: alert=%s error=%s attempt=%d/%d topic=%s offset=%d",
        alert_id,
        record.error_type,
        attempt,
        cfg.kafka_max_retries,
        topic,
        offset,
        extra={"event_type": "dlq_send"},
    )

    # Publish to DLQ Kafka topic
    _publish_to_kafka_dlq(record)

    # Write to PostgreSQL for operator visibility
    _write_dlq_postgres(record)


def _publish_to_kafka_dlq(record: DLQRecord) -> None:
    """Publish DLQ record to Kafka. Fire-and-forget with best-effort."""
    try:
        from data.kafka.producer import _publish
        _publish(
            topic=cfg.kafka_dlq_topic,
            payload=asdict(record),
            key=record.alert_id,
        )
    except Exception as exc:
        # DLQ write failing must still be logged — don't raise
        logger.critical(
            "DLQ KAFKA WRITE FAILED: alert=%s error=%s — alert is LOST",
            record.alert_id, exc,
        )


def _write_dlq_postgres(record: DLQRecord) -> None:
    """Write DLQ record to PostgreSQL for the /admin/dlq API endpoint."""
    try:
        from data.postgres.session import get_session
        from data.postgres.models import Incident, IncidentStatus

        with get_session() as session:
            # Create a stub incident so the alert appears in the system
            existing = session.execute(
                __import__("sqlalchemy").select(Incident).where(
                    Incident.alert_id == record.alert_id
                )
            ).scalar_one_or_none()

            if not existing:
                session.add(Incident(
                    alert_id=record.alert_id,
                    threat_category="PROCESSING_FAILED",
                    decision="ESCALATE",       # Failed = escalate to human by default
                    status=IncidentStatus.ESCALATED,
                    escalation_reason=f"Pipeline failed: {record.error_type}: {record.error_message}",
                ))
    except Exception as exc:
        logger.error("DLQ POSTGRES WRITE FAILED: %s", exc)


def build_retry_state(raw: dict, attempt: int) -> dict:
    """Add retry metadata to an alert state dict before re-processing."""
    return {
        **raw,
        "_retry_attempt": attempt,
        "_retry_at": datetime.now(timezone.utc).isoformat(),
    }
