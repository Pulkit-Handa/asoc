"""
Alerts Router (Production)
==========================
POST /alerts         — ingest alert, run pipeline, publish SSE via Redis
GET  /alerts/{id}    — fetch alert status from PostgreSQL
"""
import logging
import time
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from agents.orchestrator.state import SOCState
from agents.shared.telemetry import set_alert_id
from api.routers.auth import get_current_user
from api.routers.stream import publish_done, publish_event
from config.settings import cfg

logger = logging.getLogger(__name__)
router = APIRouter()

# No more in-memory dict — all pub/sub goes through Redis (see stream.py)


class AlertIngest(BaseModel):
    raw_log:      str       = Field(..., description="Raw log text from SIEM/firewall/endpoint")
    src_ip:       str | None = None
    dst_ip:       str | None = None
    user:         str | None = None
    process_hash: str | None = None
    host_id:      str | None = None
    source:       str = "manual"


class AlertResponse(BaseModel):
    alert_id:   str
    status:     str
    stream_url: str
    message:    str


@router.post("", response_model=AlertResponse, status_code=202)
async def ingest_alert(
    payload: AlertIngest,
    background: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
):
    alert_id = f"alert_{uuid4().hex[:12]}"
    set_alert_id(alert_id)

    initial_state: SOCState = {
        "alert_id":           alert_id,
        "raw_log":            payload.raw_log,
        "src_ip":             payload.src_ip,
        "dst_ip":             payload.dst_ip,
        "user":               payload.user,
        "process_hash":       payload.process_hash,
        "host_id":            payload.host_id,
        "ingested_at":        datetime.now(timezone.utc).isoformat(),
        "threat_category":    "",
        "severity_score":     0.0,
        "confidence_score":   0.0,
        "mitre_techniques":   [],
        "lessons_retrieved":  [],
        "kill_chain_graph":   {},
        "lateral_movement":   False,
        "blast_radius":       0,
        "exposure_score":     0.0,
        "crown_jewels_reachable": [],
        "decision":           "MONITOR",
        "post_mortem":        None,
        "lesson_stored":      False,
        "lesson_id":          None,
        "escalation_reason":  None,
        "processing_time_ms": None,
    }

    background.add_task(_run_pipeline, alert_id, initial_state, current_user.get("username", "api"))

    return AlertResponse(
        alert_id=alert_id,
        status="accepted",
        stream_url=f"/stream/{alert_id}",
        message=f"Alert queued. Subscribe to /stream/{alert_id} for real-time reasoning.",
    )


@router.get("/{alert_id}")
async def get_alert(
    alert_id: str,
    current_user: dict = Depends(get_current_user),
):
    from data.postgres.session import get_session
    from data.postgres.models import Incident
    from sqlalchemy import select

    with get_session() as session:
        row = session.execute(
            select(Incident).where(Incident.alert_id == alert_id)
        ).scalar_one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    return {
        "alert_id":          row.alert_id,
        "threat_category":   row.threat_category,
        "severity_score":    row.severity_score,
        "confidence_score":  row.confidence_score,
        "blast_radius":      row.blast_radius,
        "exposure_score":    row.exposure_score,
        "decision":          row.decision,
        "mitre_techniques":  row.mitre_techniques,
        "status":            row.status,
        "confirmed_outcome": row.confirmed_outcome,
        "escalation_reason": row.escalation_reason,
        "processing_time_ms": row.processing_time_ms,
        "created_at":        row.created_at.isoformat() if row.created_at else None,
    }


async def _run_pipeline(alert_id: str, initial_state: SOCState, submitted_by: str):
    """Background task: run LangGraph pipeline, publish each step to Redis."""
    from agents.orchestrator.graph import soc_app
    from data.postgres.session import get_session
    from data.postgres.models import Incident

    set_alert_id(alert_id)
    t0 = time.monotonic()

    try:
        config = {"configurable": {"thread_id": alert_id}}

        async for chunk in soc_app.astream(initial_state, config=config):
            for node_name, node_state in chunk.items():
                event = {
                    "type":      "agent_step",
                    "node":      node_name,
                    "alert_id":  alert_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "state": {
                        "threat_category":  node_state.get("threat_category"),
                        "confidence_score": node_state.get("confidence_score"),
                        "severity_score":   node_state.get("severity_score"),
                        "decision":         node_state.get("decision"),
                        "blast_radius":     node_state.get("blast_radius"),
                        "exposure_score":   node_state.get("exposure_score"),
                        "mitre_techniques": node_state.get("mitre_techniques"),
                        "lesson_stored":    node_state.get("lesson_stored"),
                        "escalation_reason": node_state.get("escalation_reason"),
                    },
                }
                await publish_event(alert_id, event)

        # Get final state from LangGraph
        final_state = await soc_app.aget_state(config=config)
        values = final_state.values if hasattr(final_state, "values") else {}
        elapsed_ms = int((time.monotonic() - t0) * 1000)

        # Persist to PostgreSQL (optimized to not block event loop)
        def _persist():
            with get_session() as session:
                session.merge(Incident(
                    alert_id=alert_id,
                    threat_category=values.get("threat_category", "UNKNOWN"),
                    severity_score=values.get("severity_score", 0.0),
                    confidence_score=values.get("confidence_score", 0.0),
                    blast_radius=values.get("blast_radius", 0),
                    exposure_score=values.get("exposure_score", 0.0),
                    decision=values.get("decision", "MONITOR"),
                    mitre_techniques=",".join(values.get("mitre_techniques", [])),
                    escalation_reason=values.get("escalation_reason"),
                    processing_time_ms=elapsed_ms,
                    src_ip=values.get("src_ip"),
                    host_id=values.get("host_id"),
                ))
        await run_in_threadpool(_persist)

        logger.info(
            "PIPELINE COMPLETE: alert=%s decision=%s conf=%.3f exposure=%.3f ms=%d",
            alert_id,
            values.get("decision", "?"),
            values.get("confidence_score", 0),
            values.get("exposure_score", 0),
            elapsed_ms,
        )

    except Exception as exc:
        logger.error("PIPELINE ERROR: alert=%s error=%s", alert_id, exc, exc_info=True)
        await publish_event(alert_id, {"type": "error", "message": str(exc), "alert_id": alert_id})

    finally:
        await publish_done(alert_id)
