"""
ASOC SOCState — The canonical state object flowing through the LangGraph pipeline.
Every field is populated progressively as the alert passes through agent nodes.
"""
from typing import TypedDict, List, Optional, Literal


DecisionType = Literal["ESCALATE", "MONITOR", "AUTO_CLOSE"]


class SOCState(TypedDict):
    # ── Input ────────────────────────────────────────────────────────────────
    alert_id: str
    raw_log: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    user: Optional[str]
    process_hash: Optional[str]
    host_id: Optional[str]
    ingested_at: str                    # ISO-8601 timestamp

    # ── Triage Agent outputs ─────────────────────────────────────────────────
    threat_category: str                # e.g. "Lateral Movement", "Phishing"
    severity_score: float               # S ∈ [0, 1]
    confidence_score: float             # S ∈ [0, 1] — THE RISK GATE
    mitre_techniques: List[str]         # ["T1021", "T1534"]
    lessons_retrieved: List[str]        # top-3 semantic matches from ChromaDB

    # ── Forensics Agent outputs ──────────────────────────────────────────────
    kill_chain_graph: dict              # nx.node_link_data(G)
    lateral_movement: bool              # Louvain community detection flag

    # ── Blast Radius Agent outputs ───────────────────────────────────────────
    blast_radius: int                   # reachable asset count
    exposure_score: float               # normalized ∈ [0, 1]
    crown_jewels_reachable: List[str]   # list of critical asset IDs reached

    # ── Decision ─────────────────────────────────────────────────────────────
    decision: DecisionType              # ESCALATE | MONITOR | AUTO_CLOSE

    # ── Critic Agent outputs (post-incident) ─────────────────────────────────
    post_mortem: Optional[str]          # LLM-generated lesson text
    lesson_stored: bool                 # whether lesson was written to ChromaDB
    lesson_id: Optional[str]           # UUID of stored lesson

    # ── Audit trail ─────────────────────────────────────────────────────────
    escalation_reason: Optional[str]    # Why was this escalated?
    processing_time_ms: Optional[int]   # End-to-end latency
