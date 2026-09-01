"""
Forensics Agent
===============
Builds a directed kill-chain graph from correlated events in ClickHouse.
Uses Louvain community detection to identify lateral movement clusters.
"""
import logging

import networkx as nx
from networkx.algorithms import community as nx_community

from agents.orchestrator.state import SOCState
from agents.forensics.clickhouse_client import query_correlated_events

logger = logging.getLogger(__name__)

LOOKBACK_HOURS = 72


def extract_techniques(graph: nx.DiGraph) -> list[str]:
    """Extract unique MITRE technique IDs from edge attributes."""
    techniques = set()
    for _, _, data in graph.edges(data=True):
        if mitre_id := data.get("technique"):
            techniques.add(mitre_id)
    return sorted(techniques)


def build_kill_chain(
    alert_id: str,
    src_ip:   str | None,
    user:     str | None,
    process_hash: str | None,
    lookback_hours: int = LOOKBACK_HOURS,
) -> nx.DiGraph:
    """
    Query ClickHouse for all events correlated by source IP, user account,
    or process hash within the lookback window. Build a directed temporal graph
    where nodes are hosts/IPs and edges represent observed event flows.
    """
    events = query_correlated_events(
        src_ip=src_ip,
        user=user,
        process_hash=process_hash,
        lookback_hours=lookback_hours,
    )

    G = nx.DiGraph()

    for event in events:
        src  = event.get("src_ip") or event.get("host_id", "unknown")
        dst  = event.get("dst_ip") or event.get("dst_host", "unknown")
        tech = event.get("mitre_id", "")
        ts   = event.get("timestamp", "")

        G.add_node(src, type="source")
        G.add_node(dst, type="destination")
        G.add_edge(
            src, dst,
            technique=tech,
            timestamp=str(ts),
            event_id=event.get("event_id", ""),
            user=event.get("user_account", ""),
        )

    logger.info(
        "FORENSICS: alert=%s nodes=%d edges=%d events=%d",
        alert_id, G.number_of_nodes(), G.number_of_edges(), len(events),
    )

    return G


def forensics_node(state: SOCState) -> SOCState:
    """
    LangGraph node: Forensics Agent.

    Inputs:  alert_id, src_ip, user, process_hash
    Outputs: kill_chain_graph (node_link_data), mitre_techniques, lateral_movement
    """
    alert_id     = state["alert_id"]
    src_ip       = state.get("src_ip")
    user         = state.get("user")
    process_hash = state.get("process_hash")

    G = build_kill_chain(
        alert_id=alert_id,
        src_ip=src_ip,
        user=user,
        process_hash=process_hash,
    )

    # Detect lateral movement: multiple communities = segmented compromise
    if G.number_of_nodes() > 1:
        undirected = G.to_undirected()
        communities = list(nx_community.louvain_communities(undirected))
        lateral_movement = len(communities) > 1
    else:
        lateral_movement = False

    # Merge newly discovered MITRE techniques with Triage Agent's findings
    forensic_techniques = extract_techniques(G)
    combined_techniques = list(
        set(state.get("mitre_techniques", [])) | set(forensic_techniques)
    )

    return {
        **state,
        "kill_chain_graph":  nx.node_link_data(G),
        "mitre_techniques":  combined_techniques,
        "lateral_movement":  lateral_movement,
    }
