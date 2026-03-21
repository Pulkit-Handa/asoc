"""
Network Topology Management
============================
Loads the enterprise network graph from Redis (seeded by scripts/seed_topology.py).
The graph models network reachability between hosts, not just adjacency.

Crown-jewel assets (domain controllers, databases, PKI servers) are
tagged in the topology and trigger hard ESCALATE when reachable.
"""
import json
import logging
import os
from functools import lru_cache
from typing import Set

import networkx as nx
import redis

logger = logging.getLogger(__name__)

TOPOLOGY_KEY  = "asoc:network_topology"
CROWN_JEWEL_KEY = "asoc:crown_jewels"

# Default crown-jewel patterns (overridden by topology data)
_DEFAULT_CROWN_JEWEL_PATTERNS = {
    "dc-", "domain-controller", "pdc", "bdc",  # Domain controllers
    "db-", "database", "postgres", "mysql", "mssql",  # Databases
    "pki-", "ca-", "certificate",  # PKI
    "vault", "hsm", "secrets",  # Secret stores
    "backup-", "nas-", "san-",  # Backup infrastructure
}


@lru_cache(maxsize=1)
def _get_redis() -> redis.Redis:
    return redis.Redis(
        host=os.getenv("REDIS_HOST", "localhost"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        decode_responses=True,
    )


def load_topology() -> nx.Graph:
    """
    Load network topology from Redis.
    Falls back to a small synthetic topology for local dev.
    """
    r = _get_redis()
    data = r.get(TOPOLOGY_KEY)

    if data:
        try:
            graph_data = json.loads(data)
            G = nx.node_link_graph(graph_data)
            logger.debug("Loaded topology: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
            return G
        except Exception as exc:
            logger.error("Failed to parse topology from Redis: %s", exc)

    logger.warning("No topology in Redis — using synthetic dev topology")
    return _build_synthetic_topology()


def _build_synthetic_topology() -> nx.Graph:
    """Synthetic network for local development and testing."""
    G = nx.Graph()

    # DMZ segment
    G.add_nodes_from(["web-01", "web-02", "lb-01"])
    G.add_edges_from([("web-01", "lb-01"), ("web-02", "lb-01")])

    # Internal segment
    G.add_nodes_from(["app-01", "app-02", "app-03"])
    G.add_edges_from([
        ("lb-01", "app-01"), ("lb-01", "app-02"),
        ("app-01", "app-02"), ("app-02", "app-03"),
    ])

    # Data segment (crown jewels)
    G.add_nodes_from(["db-primary", "db-replica", "dc-01"])
    G.add_edges_from([
        ("app-01", "db-primary"), ("app-02", "db-primary"),
        ("db-primary", "db-replica"), ("app-03", "dc-01"),
    ])

    # Mark crown jewels
    for node in ["db-primary", "db-replica", "dc-01"]:
        G.nodes[node]["crown_jewel"] = True

    return G


def get_crown_jewels() -> Set[str]:
    """Return the set of known crown-jewel asset IDs."""
    r = _get_redis()
    data = r.smembers(CROWN_JEWEL_KEY)
    return set(data) if data else set()


def is_crown_jewel(host_id: str) -> bool:
    """
    Returns True if the given host is a crown-jewel asset.
    Checks both the explicit crown-jewel set and hostname pattern matching.
    """
    # Check explicit registry first
    crown_jewels = get_crown_jewels()
    if host_id in crown_jewels:
        return True

    # Check topology node attribute
    try:
        topo = load_topology()
        if topo.nodes.get(host_id, {}).get("crown_jewel"):
            return True
    except Exception:
        pass

    # Pattern-based fallback
    host_lower = host_id.lower()
    return any(pattern in host_lower for pattern in _DEFAULT_CROWN_JEWEL_PATTERNS)


def save_topology(G: nx.Graph) -> None:
    """Persist topology graph to Redis."""
    r = _get_redis()
    data = json.dumps(nx.node_link_data(G))
    r.set(TOPOLOGY_KEY, data)
    # Invalidate cache
    
    logger.info("Topology saved: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
