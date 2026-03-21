"""
Critic Agent — The Self-Correction Loop (Production)
=====================================================
Changes from v1.1:
  - Lessons go to lesson_reviews table first (quality gate)
  - Auto-approves only when cfg.lesson_review_required=False
  - Uses cfg values instead of hard-coded os.getenv calls
  - Circuit breaker on LLM call (LLM downtime must not break pipeline)
  - Structured logging with alert_id context
"""
import logging
from datetime import datetime, timezone
from uuid import uuid4

from agents.orchestrator.state import SOCState
from agents.shared.llm_client import get_llm
from agents.shared.resilience import retry, with_fallback
from agents.shared.telemetry import set_alert_id
from config.settings import cfg

logger = logging.getLogger(__name__)

POST_MORTEM_PROMPT = """\
You are a senior SOC analyst reviewing a security incident where our automated \
detection system made an error.

Incident Details:
  Alert ID:          {alert_id}
  Threat Category:   {threat_category}
  Our Decision:      {our_decision}
  Confirmed Outcome: {confirmed_outcome}
  MITRE Techniques:  {mitre_techniques}
  Kill Chain Summary: {kill_chain_summary}
  Confidence Score:  {confidence_score:.3f}
  Blast Radius:      {blast_radius} assets

In 2-3 sentences, write a specific, actionable lesson learned that will help
our automated system correctly classify this type of alert in the future.
Focus on the concrete indicators that should change the classification.
Be specific about log fields, timing patterns, or network behaviours.
Do NOT reference this specific alert ID — write the lesson as a general rule.
"""


@with_fallback(
    fallback_value={"post_mortem": None, "lesson_stored": False, "lesson_id": None},
    service="critic_agent",
)
def critic_node(state: SOCState) -> dict:
    """
    LangGraph node: Critic Agent.
    Only runs if confirmed_outcome indicates an error.
    Writes lesson to review queue (not directly to ChromaDB).
    """
    alert_id = state["alert_id"]
    set_alert_id(alert_id)

    confirmed_outcome = state.get("confirmed_outcome")
    our_decision      = state.get("decision", "UNKNOWN")

    # Only generate lesson if we were wrong
    was_wrong = confirmed_outcome in ("FALSE_POSITIVE", "FALSE_NEGATIVE")
    if not was_wrong:
        logger.debug("Critic skipped: alert=%s outcome=%s (correct decision)", alert_id, confirmed_outcome)
        return {**state, "post_mortem": None, "lesson_stored": False, "lesson_id": None}

    # Build kill chain summary
    graph_data = state.get("kill_chain_graph", {})
    nodes = [n.get("id", "") for n in graph_data.get("nodes", [])]
    edges = graph_data.get("edges", [])
    kill_chain_summary = (
        f"{len(nodes)} nodes, {len(edges)} edges. "
        f"Key hosts: {', '.join(nodes[:5])}" if nodes else "No kill chain data"
    )

    prompt = POST_MORTEM_PROMPT.format(
        alert_id=alert_id,
        threat_category=state.get("threat_category", "UNKNOWN"),
        our_decision=our_decision,
        confirmed_outcome=confirmed_outcome,
        mitre_techniques=", ".join(state.get("mitre_techniques", [])),
        kill_chain_summary=kill_chain_summary,
        confidence_score=state.get("confidence_score", 0.0),
        blast_radius=state.get("blast_radius", 0),
    )

    post_mortem = _generate_lesson(prompt)

    if not post_mortem:
        logger.warning("Critic Agent generated empty lesson for alert=%s", alert_id)
        return {**state, "post_mortem": None, "lesson_stored": False, "lesson_id": None}

    lesson_id = _enqueue_lesson(
        alert_id=alert_id,
        category=state.get("threat_category", "UNKNOWN"),
        lesson_text=post_mortem,
    )

    logger.info(
        "LESSON QUEUED: alert=%s category=%s lesson_id=%s auto_approved=%s",
        alert_id, state.get("threat_category"), lesson_id,
        not cfg.lesson_review_required,
    )

    return {
        **state,
        "post_mortem":  post_mortem,
        "lesson_stored": True,
        "lesson_id":     lesson_id,
    }


@retry(max_attempts=3, base_delay=2.0, service="llm")
def _generate_lesson(prompt: str) -> str | None:
    """Call the LLM to generate a lesson. Retries 3 times with backoff."""
    llm = get_llm()
    from langchain_core.messages import HumanMessage
    response = llm.invoke([HumanMessage(content=prompt)])
    return response.content.strip()


def _enqueue_lesson(alert_id: str, category: str, lesson_text: str) -> str:
    """
    Write lesson to the review queue.
    Auto-approves if cfg.lesson_review_required=False.
    """
    from data.postgres.session import get_session
    from data.postgres.models import LessonReview, LessonReviewStatus

    with get_session() as session:
        review = LessonReview(
            alert_id=alert_id,
            category=category,
            lesson_text=lesson_text,
            source="critic",
            status=LessonReviewStatus.PENDING,
        )
        session.add(review)
        session.flush()  # Get ID before commit
        review_id = review.id

    # Auto-approve in dev/staging
    if not cfg.lesson_review_required:
        _auto_approve(review_id, alert_id, category, lesson_text)
        return f"critic_auto_{review_id}"

    return f"review_{review_id}"


def _auto_approve(review_id: int, alert_id: str, category: str, lesson_text: str) -> None:
    """
    Bypass review queue in non-production environments.
    Writes directly to ChromaDB and Lesson table.
    """
    from agents.shared.chroma_client import get_lessons_collection
    from data.postgres.session import get_session
    from data.postgres.models import Lesson, LessonReview, LessonReviewStatus

    lesson_id = f"critic_{uuid4().hex[:12]}"

    # ChromaDB
    try:
        collection = get_lessons_collection()
        collection.add(
            documents=[lesson_text],
            metadatas=[{
                "category":   category,
                "source":     "critic",
                "alert_id":   alert_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }],
            ids=[lesson_id],
        )
    except Exception as exc:
        logger.error("Critic auto-approve ChromaDB write failed: %s", exc)

    # PostgreSQL
    with get_session() as session:
        session.add(Lesson(
            lesson_id=lesson_id,
            alert_id=alert_id,
            category=category,
            lesson_text=lesson_text,
            source="critic",
            created_by="critic_agent_auto",
        ))
        review = session.get(LessonReview, review_id)
        if review:
            review.status      = LessonReviewStatus.APPROVED
            review.reviewer_id = "auto"
            review.reviewed_at = datetime.now(timezone.utc)
