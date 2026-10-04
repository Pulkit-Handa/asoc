"""
SSE Stream Router — Redis Pub/Sub (Multi-Instance Safe)
========================================================
Replaces the in-memory dict with Redis pub/sub channels.

WHY THIS MATTERS:
  Old: _sse_channels = {}  → lives in ONE process's memory
       Alert hits API pod 1, dashboard subscribes to pod 2 → dead silence.

  New: Redis pub/sub channel per alert_id
       Alert pipeline publishes to Redis. Any API pod can serve the stream.
       Works with 1 pod or 100 pods — no code change.

Channel naming: asoc:stream:{alert_id}
Each message is a JSON-encoded event dict.
Sentinel: {"type": "done"} closes the stream.

Dashboard connects with:
  const es = new EventSource(`/stream/${alertId}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  es.addEventListener('agent_step', e => handleStep(JSON.parse(e.data)));
  es.addEventListener('done', () => es.close());
"""
import asyncio
import json
import logging

import redis.asyncio as aioredis
from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from config.settings import cfg

logger = logging.getLogger(__name__)
router = APIRouter()

CHANNEL_PREFIX   = "asoc:stream:"
STREAM_TIMEOUT_S = 120   # Close stream if no events for 2 minutes


def get_redis_pubsub_client() -> aioredis.Redis:
    return aioredis.Redis(
        host=cfg.redis_host,
        port=cfg.redis_port,
        db=cfg.redis_db_pubsub,
        password=cfg.redis_password.get_secret_value() if cfg.redis_password else None,
        decode_responses=True,
    )


async def publish_event(alert_id: str, event: dict) -> None:
    """
    Called by the pipeline runner to push events to the stream.
    Any API pod subscribed to this alert_id receives it instantly.
    """
    r = get_redis_pubsub_client()
    channel = f"{CHANNEL_PREFIX}{alert_id}"
    try:
        await r.publish(channel, json.dumps(event))
    finally:
        await r.aclose()


async def publish_done(alert_id: str) -> None:
    """Signal the SSE client that the pipeline is complete."""
    await publish_event(alert_id, {"type": "done"})


@router.get("/{alert_id}")
async def stream_alert(alert_id: str):
    """
    Subscribe to real-time agent reasoning for a specific alert.
    Safe to call from any API pod — Redis delivers events regardless of which
    pod ran the pipeline.
    """
    return StreamingResponse(
        _sse_generator(alert_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


async def _sse_generator(alert_id: str):
    channel = f"{CHANNEL_PREFIX}{alert_id}"
    r       = get_redis_pubsub_client()
    pubsub  = r.pubsub()

    try:
        await pubsub.subscribe(channel)
        logger.debug("SSE subscribed: alert=%s channel=%s", alert_id, channel)

        while True:
            try:
                message = await asyncio.wait_for(
                    pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0),
                    timeout=STREAM_TIMEOUT_S,
                )

                if message is None:
                    # No message yet — send keepalive comment
                    yield ": keepalive\n\n"
                    continue

                data = message.get("data", "")
                if not data:
                    continue

                try:
                    event = json.loads(data)
                except json.JSONDecodeError:
                    continue

                if event.get("type") == "done":
                    yield "event: done\ndata: {}\n\n"
                    break

                yield f"event: agent_step\ndata: {json.dumps(event)}\n\n"

            except asyncio.TimeoutError:
                logger.info("SSE timeout: alert=%s no events for %ds", alert_id, STREAM_TIMEOUT_S)
                yield "event: timeout\ndata: {}\n\n"
                break

    except Exception as exc:
        logger.error("SSE error: alert=%s error=%s", alert_id, exc)
        yield f'event: error\ndata: {json.dumps({"message": str(exc)})}\n\n'

    finally:
        await pubsub.unsubscribe(channel)
        await r.aclose()
        logger.debug("SSE closed: alert=%s", alert_id)
