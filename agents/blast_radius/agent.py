"""
Blast Radius Agent
==================
Computes how many assets are reachable from the compromised host using
Breadth-First Search over the enterprise network topology graph.

Analogous to Value at Risk (VaR) in financial systems:
  - exposure_score = 0.0  → isolated host, low urgency
  - exposure_score > 0.40 → crown-jewel assets reachable → force ESCALATE
  - exposure_score = 1.0  → domain controller or DB reachable
"""
import logging
import os
from typing import List

import networkx as nx
import redis

from agents.orchestrator.state import SOCState
from agents.blast_radius.topology import load_topology, is_crown_jewel

logger = logging.getLogger(__name__)

ESCALATE_EXPOSURE_THRESHOLD = 0.40
CROWN_JEWEL_WEIGHT = 10          # Crown-jewel assets count 10x in exposure calc


def compute_blast_radius(
    compromised_host: str,
    topology: nx.Graph,
    total_assets: int,
) -> tuple[int, float, List[str]]:
    """
    BFS from compromised_host over the network topology.
    Returns (reachable_count, exposure_score, crown_jewel_ids_reached).
    """
    if compromised_host not in topology:
        logger.warning("Host %s not found in topology graph", compromised_host)
        return 0, 0.0, []

    reachable_tree = nx.bfs_tree(topology, compromised_host)
    reachable_nodes = list(reachable_tree.nodes)

    crown_jewels = [n for n in reachable_nodes if is_crown_jewel(n)]

    # Weighted exposure: crown-jewel hosts count CROWN_JEWEL_WEIGHT × normal hosts
    weighted_count = len(reachable_nodes) + CROWN_JEWEL_WEIGHT * len(crown_jewels)
    exposure = min(1.0, weighted_count / max(total_assets, 1))

    return len(reachable_nodes), round(exposure, 4), crown_jewels


def blast_radius_node(state: SOCState) -> SOCState:
    """
    LangGraph node: Blast Radius Agent.

    Inputs:  kill_chain_graph (uses first compromised node)
    Outputs: blast_radius, exposure_score, crown_jewels_reachable, decision
    """
    alert_id = state["alert_id"]

    # Identify compromised host from kill-chain graph's first node
    graph_data = state.get("kill_chain_graph", {})
    nodes = graph_data.get("nodes", [])
    compromised_host = nodes[0]["id"] if nodes else state.get("src_ip", "unknown")

    topology      = load_topology()
    total_assets  = topology.number_of_nodes() or 1

    asset_count, exposure, crown_jewels = compute_blast_radius(
        compromised_host=compromised_host,
        topology=topology,
        total_assets=total_assets,
    )

    # Hard override: high exposure forces ESCALATE regardless of confidence
    current_decision = state.get("decision", "MONITOR")
    if exposure > ESCALATE_EXPOSURE_THRESHOLD:
        new_decision      = "ESCALATE"
        escalation_reason = (
            f"Blast radius exposure {exposure:.3f} exceeds threshold "
            f"{ESCALATE_EXPOSURE_THRESHOLD}. "
            f"Crown jewels reachable: {crown_jewels or 'none'}"
        )
        logger.warning(
            "BLAST RADIUS ESCALATE: alert=%s host=%s exposure=%.3f crown_jewels=%s",
            alert_id, compromised_host, exposure, crown_jewels,
        )
    else:
        new_decision      = current_decision
        escalation_reason = state.get("escalation_reason")

    logger.info(
        "BLAST RADIUS: alert=%s host=%s assets=%d exposure=%.3f decision=%s",
        alert_id, compromised_host, asset_count, exposure, new_decision,
    )

    return {
        **state,
        "blast_radius":          asset_count,
        "exposure_score":        exposure,
        "crown_jewels_reachable": crown_jewels,
        "decision":              new_decision,
        "escalation_reason":     escalation_reason,
    }
