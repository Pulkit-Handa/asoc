"""
Admin Router
============
Operations endpoints for SOC engineers and platform admins.
All endpoints require ADMIN role.

GET  /admin/dlq                — list failed alerts in the DLQ
POST /admin/dlq/{alert_id}/replay — reprocess a failed alert
POST /admin/topology/sync      — trigger immediate topology refresh
GET  /admin/topology/status    — last sync time + node/edge counts
GET  /admin/circuit-breakers   — current state of all circuit breakers
POST /admin/circuit-breakers/{service}/reset — manually reset an open breaker
GET  /admin/audit-logs         — compliance audit trail (paginated)
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select, text
from sqlalchemy.orm import Session

from api.routers.auth import UserRole, require_role
from config.settings import cfg
from data.postgres.session import get_db

logger = logging.getLogger(__name__)
router = APIRouter()

_require_admin = require_role(UserRole.ADMIN)


# ── DLQ ───────────────────────────────────────────────────────────────────────

@router.get("/dlq")
def list_dlq(
    limit: int = Query(50, le=200),
    db:    Session = Depends(get_db),
    _: dict = Depends(_require_admin),
):
    """List incidents that failed processing and landed in the DLQ."""
    from data.postgres.models import Incident

    rows = db.execute(
        select(Incident)
        .where(Incident.threat_category == "PROCESSING_FAILED")
        .order_by(desc(Incident.created_at))
        .limit(limit)
    ).scalars().all()

    return [
        {
            "alert_id":          r.alert_id,
            "escalation_reason": r.escalation_reason,
            "created_at":        r.created_at.isoformat() if r.created_at else None,
            "status":            r.status,
        }
        for r in rows
    ]


@router.post("/dlq/{alert_id}/replay", status_code=202)
async def replay_dlq_alert(
    alert_id: str,
    db:       Session = Depends(get_db),
    user: dict = Depends(_require_admin),
):
    """
    Reprocess a failed alert. Sends it back through the full LangGraph pipeline.
    The incident record is reset so the new result overwrites the PROCESSING_FAILED stub.
    """
    from data.postgres.models import Incident, IncidentStatus
    from data.kafka.producer import publish_alert

    row = db.execute(
        select(Incident).where(Incident.alert_id == alert_id)
    ).scalar_one_or_none()

    if not row:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found in DLQ")

    # Reset the stub
    row.threat_category  = "REPLAYING"
    row.status           = IncidentStatus.OPEN
    row.escalation_reason = f"Replayed by {user['username']} at {datetime.now(timezone.utc).isoformat()}"
    db.commit()

    # Republish to Kafka for reprocessing
    publish_alert(
        alert={"alert_id": alert_id, "log": f"REPLAY: {row.escalation_reason}", "format": "raw"},
        key=alert_id,
    )

    logger.info("DLQ REPLAY: alert=%s by=%s", alert_id, user["username"])
    return {"status": "replayed", "alert_id": alert_id}


# ── Topology ──────────────────────────────────────────────────────────────────

@router.post("/topology/sync")
def trigger_topology_sync(_: dict = Depends(_require_admin)):
    """
    Immediately refresh the network topology from cfg.topology_source.
    Normally runs as a CronJob every hour. Use this after a network change.
    """
    try:
        from data.topology.sync import sync_topology, get_last_sync_time
        nodes, edges = sync_topology()
        return {
            "status":    "synced",
            "nodes":     nodes,
            "edges":     edges,
            "source":    cfg.topology_source,
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        logger.error("Topology sync failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/topology/status")
def topology_status(_: dict = Depends(_require_admin)):
    """Show current topology stats and last sync time."""
    try:
        from agents.blast_radius.topology import load_topology
        from data.topology.sync import get_last_sync_time

        G = load_topology()
        crown_jewels = [
            n for n, d in G.nodes(data=True) if d.get("crown_jewel")
        ]

        return {
            "nodes":         G.number_of_nodes(),
            "edges":         G.number_of_edges(),
            "crown_jewels":  len(crown_jewels),
            "source":        cfg.topology_source,
            "last_sync":     get_last_sync_time() or "never",
            "sync_interval": cfg.topology_sync_interval_sec,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Circuit Breakers ──────────────────────────────────────────────────────────

@router.get("/circuit-breakers")
def list_circuit_breakers(_: dict = Depends(_require_admin)):
    """
    Show the current state of all circuit breakers.
    OPEN means that service is unreachable — investigate immediately.
    """
    from agents.shared.resilience import get_all_breaker_status
    return get_all_breaker_status()


@router.post("/circuit-breakers/{service}/reset")
def reset_circuit_breaker(
    service: str,
    _: dict = Depends(_require_admin),
):
    """
    Manually reset a circuit breaker to CLOSED.
    Only do this after confirming the service has recovered.
    """
    from agents.shared.resilience import _breakers, BreakerState

    breaker = _breakers.get(service)
    if not breaker:
        raise HTTPException(status_code=404, detail=f"No breaker for service: {service!r}")

    breaker._state         = BreakerState.CLOSED
    breaker._failure_count = 0
    breaker._success_count = 0

    logger.info("BREAKER RESET: service=%s", service)
    return {"status": "reset", "service": service, "state": "CLOSED"}


# ── Audit Logs ────────────────────────────────────────────────────────────────

@router.get("/audit-logs")
def list_audit_logs(
    user_id: Optional[str] = Query(None),
    action:  Optional[str] = Query(None),
    limit:   int = Query(100, le=1000),
    offset:  int = Query(0),
    db:      Session = Depends(get_db),
    _: dict = Depends(_require_admin),
):
    """
    SOC2 compliance audit trail. Paginated. Filter by user or action.
    This log should be exported nightly to your SIEM or immutable cold storage.
    """
    from data.postgres.models import AuditLog

    query = select(AuditLog).order_by(desc(AuditLog.created_at))

    if user_id:
        query = query.where(AuditLog.user_id == user_id)
    if action:
        query = query.where(AuditLog.action.contains(action))

    rows = db.execute(query.offset(offset).limit(limit)).scalars().all()

    return [
        {
            "id":             r.id,
            "user_id":        r.user_id,
            "action":         r.action,
            "resource":       r.resource,
            "client_ip":      r.client_ip,
            "status_code":    r.status_code,
            "response_ms":    r.response_ms,
            "correlation_id": r.correlation_id,
            "created_at":     r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]
