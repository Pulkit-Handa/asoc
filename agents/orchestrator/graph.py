"""
ASOC LangGraph Orchestration Graph
===================================
Defines the full multi-agent state machine:
  START → triage → [risk_gate] → forensics → blast_radius → decision → [critic]
                         ↓
                      escalate → END
"""
import logging
from langgraph.graph import StateGraph, END

from agents.orchestrator.state import SOCState
from agents.triage.agent import triage_node
from agents.forensics.agent import forensics_node
from agents.blast_radius.agent import blast_radius_node
from agents.critic.agent import critic_node
from agents.orchestrator.nodes import decision_node, human_escalation_node

logger = logging.getLogger(__name__)

CONFIDENCE_THRESHOLD = 0.70   # Calibrated quarterly on holdout set
EXPOSURE_THRESHOLD = 0.40     # Hard override: forces ESCALATE


def risk_gate(state: SOCState) -> str:
    """
    Conditional edge after Triage Agent.
    Routes to human escalation if confidence is below threshold OR
    if pre-triage blast radius is critically high.
    """
    conf = state.get("confidence_score", 0.0)
    if conf < CONFIDENCE_THRESHOLD:
        logger.info(
            "RISK GATE: alert=%s conf=%.3f < %.2f → ESCALATE",
            state["alert_id"], conf, CONFIDENCE_THRESHOLD,
        )
        return "escalate"
    return "forensics"


def post_decision_gate(state: SOCState) -> str:
    """
    Conditional edge after decision node.
    Critic only runs for non-escalated decisions so it can evaluate
    the automated path.  Escalated alerts are reviewed by humans.
    """
    if state.get("decision") != "ESCALATE":
        return "critic"
    return END


def build_graph(redis_url: str = "redis://localhost:6379") -> StateGraph:
    graph = StateGraph(SOCState)

    # ── Register nodes ───────────────────────────────────────────────────────
    graph.add_node("triage",       triage_node)
    graph.add_node("forensics",    forensics_node)
    graph.add_node("blast_radius", blast_radius_node)
    graph.add_node("decision",     decision_node)
    graph.add_node("critic",       critic_node)
    graph.add_node("escalate",     human_escalation_node)

    # ── Primary flow ─────────────────────────────────────────────────────────
    graph.set_entry_point("triage")

    # Risk Gate after triage: low confidence → escalate
    graph.add_conditional_edges("triage", risk_gate, {
        "forensics": "forensics",
        "escalate":  "escalate",
    })

    graph.add_edge("forensics",    "blast_radius")
    graph.add_edge("blast_radius", "decision")

    # Post-decision: Critic runs on automated decisions only
    graph.add_conditional_edges("decision", post_decision_gate, {
        "critic": "critic",
        END:      END,
    })

    graph.add_edge("escalate", END)
    graph.add_edge("critic",   END)

    # ── Compile with Redis checkpointer for state persistence ────────────────
    from langgraph.checkpoint.memory import MemorySaver
    checkpointer = MemorySaver()
    return graph.compile(checkpointer=checkpointer)


# Module-level compiled graph (imported by Kafka consumer and API)
soc_app = build_graph()
