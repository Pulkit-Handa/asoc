"""
Incidents Router
================
GET  /incidents              — list recent incidents with filters
GET  /incidents/{alert_id}   — get single incident details
POST /incidents/{alert_id}/outcome — analyst submits confirmed outcome
                                     (triggers Critic Agent lesson generation)
"""
import logging
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from data.postgres.models import Incident, AnalystFeedback, IncidentStatus
from data.postgres.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Pydantic schemas ─────────────────────────────────────────────────────────

class OutcomeSubmission(BaseModel):
    confirmed_outcome: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "FALSE_NEGATIVE"]
    override_decision: Optional[str] = None
    annotation:        Optional[str] = None
    analyst_id:        str = "analyst"


class IncidentOut(BaseModel):
    alert_id:          str
    threat_category:   str
    severity_score:    float
    confidence_score:  float
    blast_radius:      int
    exposure_score:    float
    decision:          str
    mitre_techniques:  str
    status:            str
    confirmed_outcome: Optional[str]
    escalation_reason: Optional[str]
    created_at:        datetime

    class Config:
        from_attributes = True


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("", response_model=list[IncidentOut])
def list_incidents(
    status:   Optional[str] = Query(None, description="Filter by status: OPEN, ESCALATED, RESOLVED"),
    decision: Optional[str] = Query(None, description="Filter by decision: ESCALATE, MONITOR, AUTO_CLOSE"),
    limit:    int            = Query(50, le=500),
    offset:   int            = Query(0),
    db:       Session        = Depends(get_db),
):
    """List incidents, newest first. Use status= and decision= to filter."""
    query = select(Incident).order_by(desc(Incident.created_at))

    if status:
        query = query.where(Incident.status == status.upper())
    if decision:
        query = query.where(Incident.decision == decision.upper())

    rows = db.execute(query.offset(offset).limit(limit)).scalars().all()
    return rows


@router.get("/{alert_id}", response_model=IncidentOut)
def get_incident(alert_id: str, db: Session = Depends(get_db)):
    """Fetch a single incident by alert_id."""
    row = db.execute(
        select(Incident).where(Incident.alert_id == alert_id)
    ).scalar_one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {alert_id} not found")
    return row


@router.post("/{alert_id}/outcome", status_code=200)
async def submit_outcome(
    alert_id:  str,
    payload:   OutcomeSubmission,
    background: BackgroundTasks,
    db:        Session = Depends(get_db),
):
    """
    Analyst submits the confirmed outcome for an incident.
    This is the trigger for the Critic Agent to generate a Lesson Learned
    if the system made a mistake.

    confirmed_outcome options:
      TRUE_POSITIVE  — system was right, it was a real threat
      FALSE_POSITIVE — system escalated/monitored a non-threat
      FALSE_NEGATIVE — system AUTO_CLOSED a real threat (most important to catch)
    """
    # Update incident record
    row = db.execute(
        select(Incident).where(Incident.alert_id == alert_id)
    ).scalar_one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail=f"Incident {alert_id} not found")

    row.confirmed_outcome = payload.confirmed_outcome
    row.status            = IncidentStatus.RESOLVED

    if payload.override_decision:
        row.decision = payload.override_decision

    # Store analyst feedback record
    feedback = AnalystFeedback(
        alert_id=alert_id,
        analyst_id=payload.analyst_id,
        confirmed_outcome=payload.confirmed_outcome,
        override_decision=payload.override_decision,
        annotation=payload.annotation,
        created_at=datetime.now(timezone.utc),
    )
    db.add(feedback)
    db.commit()

    logger.info(
        "OUTCOME SUBMITTED: alert=%s outcome=%s analyst=%s",
        alert_id, payload.confirmed_outcome, payload.analyst_id,
    )

    # Trigger Critic Agent asynchronously if system was wrong
    if payload.confirmed_outcome in ("FALSE_POSITIVE", "FALSE_NEGATIVE"):
        import asyncio
        
        minimal_state = {
            "alert_id":        row.alert_id,
            "threat_category": row.threat_category,
            "decision":        row.decision,
            "confidence_score": row.confidence_score,
            "severity_score":  row.severity_score,
            "blast_radius":    row.blast_radius,
            "exposure_score":  row.exposure_score,
            "mitre_techniques": row.mitre_techniques.split(",") if row.mitre_techniques else [],
            "kill_chain_graph": {},
            "post_mortem":     None,
            "lesson_stored":   False,
            "lesson_id":       None,
            "confirmed_outcome": payload.confirmed_outcome,
            # All other SOCState fields with defaults
            "raw_log": "", "src_ip": None, "dst_ip": None, "user": None,
            "process_hash": None, "host_id": None, "ingested_at": "",
            "lessons_retrieved": [], "lateral_movement": False,
            "crown_jewels_reachable": [], "escalation_reason": None,
            "processing_time_ms": None,
        }
        
        background.add_task(_run_critic_async, minimal_state)

    return {
        "alert_id":         alert_id,
        "confirmed_outcome": payload.confirmed_outcome,
        "lesson_triggered": payload.confirmed_outcome in ("FALSE_POSITIVE", "FALSE_NEGATIVE"),
        "message":          "Outcome recorded. Critic Agent will generate a lesson if applicable.",
    }


def _run_critic_async(minimal_state: dict):
    """Background task: run Critic Agent to generate lesson from analyst feedback."""
    try:
        from agents.critic.agent import critic_node
        result = critic_node(minimal_state)
        if result.get("lesson_stored"):
            logger.info("Critic Agent stored lesson for alert=%s", minimal_state["alert_id"])
    except Exception as exc:
        logger.error("Critic Agent failed for alert=%s: %s", minimal_state["alert_id"], exc)
