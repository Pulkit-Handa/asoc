"""
Kafka Producer
==============
Publishes messages to ASOC Kafka topics.
Used by:
  - External SIEM integrations pushing raw logs
  - API ingest endpoint (when Kafka mode is enabled)
  - Agent decision output for audit trail
"""
import json
import logging
import os
from functools import lru_cache
from typing import Any, Dict

from confluent_kafka import Producer, KafkaException

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP    = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
RAW_LOGS_TOPIC     = "security.raw_logs"
DECISIONS_TOPIC    = "security.decisions"
LESSONS_TOPIC      = "security.lessons"
THREAT_INTEL_TOPIC = "security.threat_intel"


@lru_cache(maxsize=1)
def _get_producer() -> Producer:
    return Producer({
        "bootstrap.servers":    KAFKA_BOOTSTRAP,
        "acks":                 "all",           # Wait for all replicas
        "retries":              5,
        "retry.backoff.ms":     200,
        "linger.ms":            5,               # Micro-batching
        "compression.type":     "lz4",
        "message.max.bytes":    10 * 1024 * 1024,
    })


def _delivery_callback(err, msg):
    if err:
        logger.error("Kafka delivery failed: topic=%s error=%s", msg.topic(), err)
    else:
        logger.debug("Kafka delivered: topic=%s partition=%d offset=%d",
                     msg.topic(), msg.partition(), msg.offset())


def publish_alert(alert: Dict[str, Any], key: str | None = None) -> None:
    """Publish a raw alert to the security.raw_logs topic."""
    _publish(RAW_LOGS_TOPIC, alert, key=key or alert.get("host_id", ""))


def publish_decision(decision: Dict[str, Any]) -> None:
    """Publish an agent decision to the security.decisions topic."""
    _publish(DECISIONS_TOPIC, decision, key=decision.get("alert_id", ""))


def publish_lesson(lesson: Dict[str, Any]) -> None:
    """Publish a Critic Agent lesson to the security.lessons topic."""
    _publish(LESSONS_TOPIC, lesson, key=lesson.get("category", ""))


def _publish(topic: str, payload: Dict[str, Any], key: str = "") -> None:
    producer = _get_producer()
    try:
        producer.produce(
            topic=topic,
            key=key.encode("utf-8"),
            value=json.dumps(payload).encode("utf-8"),
            callback=_delivery_callback,
        )
        producer.poll(0)   # Trigger delivery callbacks without blocking
    except KafkaException as exc:
        logger.error("Failed to publish to %s: %s", topic, exc)
        raise


def flush(timeout: float = 5.0) -> None:
    """Flush all pending messages. Call at shutdown."""
    _get_producer().flush(timeout=timeout)
