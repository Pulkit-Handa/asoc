"""
Shared orchestrator nodes: decision logic and human escalation handler.
"""
import logging
from datetime import datetime, timezone

from agents.orchestrator.state import SOCState
from data.postgres.models import Incident, IncidentStatus
from data.postgres.session import get_session

logger = logging.getLogger(__name__)

EXPOSURE_ESCALATE_THRESHOLD = 0.40


def decision_node(state: SOCState) -> SOCState:
    """
    Final automated decision combining blast radius and confidence signals.
    
    Decision matrix:
      exposure > 0.40            → ESCALATE  (hard override)
      severity ≥ 0.80            → ESCALATE
      confidence ≥ 0.90 AND
        severity < 0.40          → AUTO_CLOSE
      otherwise                  → MONITOR
    """
    exposure  = state.get("exposure_score", 0.0)
    severity  = state.get("severity_score", 0.0)
    confidence = state.get("confidence_score", 0.0)
    lateral   = state.get("lateral_movement", False)

    reason = None

    if exposure > EXPOSURE_ESCALATE_THRESHOLD:
        decision = "ESCALATE"
        reason = f"Blast radius exposure_score={exposure:.3f} exceeds threshold {EXPOSURE_ESCALATE_THRESHOLD}"
    elif lateral:
        decision = "ESCALATE"
        reason = "Lateral movement detected across network communities"
    elif severity >= 0.80:
        decision = "ESCALATE"
        reason = f"High severity_score={severity:.3f}"
    elif confidence >= 0.90 and severity < 0.40:
        decision = "AUTO_CLOSE"
    else:
        decision = "MONITOR"

    logger.info(
        "DECISION: alert=%s → %s (conf=%.3f sev=%.3f exp=%.3f)",
        state["alert_id"], decision, confidence, severity, exposure,
    )

    # Persist incident record
    _persist_incident(state, decision)

    return {**state, "decision": decision, "escalation_reason": reason}


def human_escalation_node(state: SOCState) -> SOCState:
    """
    Routes alert to the human analyst queue.
    Writes to the escalation topic and sets decision = ESCALATE.
    """
    logger.warning(
        "ESCALATION: alert=%s conf=%.3f reason=%s",
        state["alert_id"],
        state.get("confidence_score", 0.0),
        state.get("escalation_reason", "Low confidence"),
    )

    reason = state.get("escalation_reason") or (
        f"Confidence {state.get('confidence_score', 0.0):.3f} below "
        f"Risk Gate threshold"
    )

    _persist_incident(state, "ESCALATE")

    return {
        **state,
        "decision": "ESCALATE",
        "escalation_reason": reason,
    }


def _persist_incident(state: SOCState, decision: str) -> None:
    """Write incident record to PostgreSQL."""
    try:
        with get_session() as session:
            incident = Incident(
                alert_id=state["alert_id"],
                threat_category=state.get("threat_category", "UNKNOWN"),
                severity_score=state.get("severity_score", 0.0),
                confidence_score=state.get("confidence_score", 0.0),
                blast_radius=state.get("blast_radius", 0),
                exposure_score=state.get("exposure_score", 0.0),
                decision=decision,
                mitre_techniques=",".join(state.get("mitre_techniques", [])),
                status=IncidentStatus.ESCALATED
                    if decision == "ESCALATE"
                    else IncidentStatus.OPEN,
                created_at=datetime.now(timezone.utc),
            )
            session.add(incident)
            session.commit()
    except Exception as exc:
        logger.error("Failed to persist incident %s: %s", state["alert_id"], exc)
