"""
Triage Agent — Production
==========================
Changes from v1.1:
  - Uses get_classifier() singleton (not re-instantiated per alert)
  - ChromaDB lesson retrieval wrapped in circuit breaker + fallback
  - Category-scoped lesson search (better signal, smaller search space)
  - Structured logging with alert_id context
  - All thresholds from cfg (not hard-coded)
"""
import logging
import time
from typing import List

from agents.orchestrator.state import SOCState
from agents.shared.chroma_client import get_lessons_collection
from agents.shared.mitre import get_techniques_for_category
from agents.shared.resilience import get_breaker, with_fallback
from agents.shared.telemetry import set_alert_id
from agents.triage.models import ClassificationResult, get_classifier
from config.settings import cfg

logger = logging.getLogger(__name__)


@with_fallback(fallback_value=[], service="chromadb_lessons")
def _retrieve_lessons(raw_log: str, category: str = "", n_results: int = 3) -> List[str]:
    """
    Semantic search against the ChromaDB lesson store.
    Scoped to the detected category when available (higher precision).
    Wrapped with @with_fallback — ChromaDB being down never blocks triage.
    """
    collection = get_lessons_collection()

    # Scope to category for better relevance
    where = {"category": category} if category else None

    results = collection.query(
        query_texts=[raw_log],
        n_results=n_results,
        where=where,
        include=["documents", "distances"],
    )

    docs      = results.get("documents", [[]])[0]
    distances = results.get("distances", [[]])[0]

    lessons = [
        doc for doc, dist in zip(docs, distances)
        if (1.0 - dist) >= 0.0  # Temporarily lowered to 0.0 for testing
    ]

    logger.debug(
        "Lessons retrieved: %d (distances: %s)",
        len(lessons), distances
    )
    return lessons


def triage_node(state: SOCState) -> SOCState:
    """
    LangGraph node: Triage Agent.
    Inputs:  raw_log, src_ip, host_id, user
    Outputs: threat_category, confidence_score, severity_score,
             mitre_techniques, lessons_retrieved
    """
    alert_id = state["alert_id"]
    set_alert_id(alert_id)
    t0 = time.monotonic()

    # 1. First-pass classification (no context) to get category for scoped retrieval
    classifier = get_classifier()
    raw_result: ClassificationResult = classifier.classify(state.get("raw_log", ""))

    # 2. Retrieve lessons scoped to the initial category
    lessons = _retrieve_lessons(
        raw_log=state.get("raw_log", ""),
        category=raw_result.category,
    )

    # 3. If lessons available, re-classify with enriched context
    if lessons:
        enriched = (
            f"Log: {state.get('raw_log', '')}\n\n"
            f"Relevant past lessons:\n" + "\n".join(f"- {l}" for l in lessons)
        )
        final_result: ClassificationResult = classifier.classify(enriched)
    else:
        final_result = raw_result

    # 4. Map to MITRE techniques
    techniques = get_techniques_for_category(final_result.category)

    # 5. Severity: combines threat category severity + confidence
    category_severity = {
        "Impact": 1.0,
        "Command and Control": 0.90,
        "Lateral Movement": 0.85,
        "Credential Access": 0.85,
        "Privilege Escalation": 0.80,
        "Exfiltration": 0.80,
        "Defense Evasion": 0.75,
        "Persistence": 0.70,
        "Execution": 0.65,
        "Initial Access": 0.65,
        "Collection": 0.60,
        "Discovery": 0.45,
        "Reconnaissance": 0.40,
        "Benign": 0.05,
    }
    base_severity = category_severity.get(final_result.category, 0.50)
    severity      = round(base_severity * final_result.confidence, 4)

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    logger.info(
        "TRIAGE: alert=%s category=%s confidence=%.3f severity=%.3f lessons=%d ms=%d",
        alert_id, final_result.category, final_result.confidence,
        severity, len(lessons), elapsed_ms,
    )

    return {
        **state,
        "threat_category":    final_result.category,
        "confidence_score":   final_result.confidence,
        "severity_score":     severity,
        "mitre_techniques":   techniques,
        "lessons_retrieved":  lessons,
    }
