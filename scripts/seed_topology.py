"""
Seed Script — Network Topology + MITRE Lessons
================================================
Run once after `docker-compose up` to populate:
  1. Redis: enterprise network topology graph
  2. ChromaDB: MITRE ATT&CK technique descriptions as baseline lessons

Usage:
    python scripts/seed_topology.py
"""
import json
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import networkx as nx

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ── Network Topology ──────────────────────────────────────────────────────────

def build_example_topology() -> nx.Graph:
    """
    Build a realistic enterprise network topology for testing.
    Replace this with data from your actual network discovery tool
    (Nmap, Qualys, AWS VPC flow, etc.)
    """
    G = nx.Graph()

    # Define all nodes with metadata
    nodes = [
        # DMZ
        ("lb-01",        {"segment": "dmz",      "crown_jewel": False, "role": "load_balancer"}),
        ("web-01",       {"segment": "dmz",      "crown_jewel": False, "role": "web_server"}),
        ("web-02",       {"segment": "dmz",      "crown_jewel": False, "role": "web_server"}),
        # Application tier
        ("app-01",       {"segment": "app",      "crown_jewel": False, "role": "app_server"}),
        ("app-02",       {"segment": "app",      "crown_jewel": False, "role": "app_server"}),
        ("app-03",       {"segment": "app",      "crown_jewel": False, "role": "app_server"}),
        ("cache-01",     {"segment": "app",      "crown_jewel": False, "role": "cache"}),
        # Data tier (CROWN JEWELS)
        ("db-primary",   {"segment": "data",     "crown_jewel": True,  "role": "database"}),
        ("db-replica",   {"segment": "data",     "crown_jewel": True,  "role": "database"}),
        ("vault-01",     {"segment": "data",     "crown_jewel": True,  "role": "secrets_store"}),
        # Identity (CROWN JEWELS)
        ("dc-01",        {"segment": "identity", "crown_jewel": True,  "role": "domain_controller"}),
        ("dc-02",        {"segment": "identity", "crown_jewel": True,  "role": "domain_controller"}),
        ("pki-01",       {"segment": "identity", "crown_jewel": True,  "role": "certificate_authority"}),
        # Infrastructure
        ("backup-01",    {"segment": "infra",    "crown_jewel": True,  "role": "backup_server"}),
        ("monitoring-01",{"segment": "infra",    "crown_jewel": False, "role": "monitoring"}),
        ("jump-01",      {"segment": "mgmt",     "crown_jewel": False, "role": "jump_host"}),
    ]
    G.add_nodes_from(nodes)

    # Network edges (who can reach whom)
    edges = [
        ("lb-01", "web-01"), ("lb-01", "web-02"),
        ("web-01", "app-01"), ("web-02", "app-02"),
        ("app-01", "app-02"), ("app-02", "app-03"),
        ("app-01", "db-primary"), ("app-02", "db-primary"), ("app-03", "db-primary"),
        ("app-01", "cache-01"),
        ("db-primary", "db-replica"),
        ("app-01", "dc-01"), ("app-02", "dc-01"),
        ("dc-01", "dc-02"), ("dc-01", "pki-01"),
        ("db-primary", "backup-01"), ("app-01", "backup-01"),
        ("jump-01", "dc-01"), ("jump-01", "db-primary"),
        ("monitoring-01", "app-01"), ("monitoring-01", "db-primary"),
        ("dc-01", "vault-01"),
    ]
    G.add_edges_from(edges)

    return G


def seed_topology():
    from agents.blast_radius.topology import save_topology, CROWN_JEWEL_KEY, _get_redis

    logger.info("Building network topology...")
    G = build_example_topology()

    logger.info("Saving topology: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges())
    save_topology(G)

    # Register crown jewels in Redis set
    r = _get_redis()
    crown_jewels = [n for n, d in G.nodes(data=True) if d.get("crown_jewel")]
    if crown_jewels:
        r.delete(CROWN_JEWEL_KEY)
        r.sadd(CROWN_JEWEL_KEY, *crown_jewels)
        logger.info("Crown jewels registered: %s", crown_jewels)


# ── MITRE Baseline Lessons ────────────────────────────────────────────────────

MITRE_BASELINE_LESSONS = [
    {
        "text": "Lateral movement via T1021 (Remote Services) often precedes credential access. Watch for SMB connections from non-admin workstations to servers, especially outside business hours.",
        "category": "Lateral Movement",
        "mitre": "T1021",
    },
    {
        "text": "T1003 (Credential Dumping) via LSASS memory access should trigger ESCALATE even at medium confidence when the accessing process is not a known security tool. Mimikatz variants obfuscate process names.",
        "category": "Credential Access",
        "mitre": "T1003",
    },
    {
        "text": "DNS tunneling (T1048) for exfiltration manifests as high-frequency queries to a single domain with long subdomains (>50 chars). Low per-query payload often bypasses volume-based detection.",
        "category": "Exfiltration",
        "mitre": "T1048",
    },
    {
        "text": "T1053 (Scheduled Task) creation by non-SYSTEM accounts during business hours warrants investigation. Ransomware frequently creates scheduled tasks for persistence before detonation.",
        "category": "Persistence",
        "mitre": "T1053",
    },
    {
        "text": "PowerShell with -EncodedCommand or -WindowStyle Hidden (T1059) combined with network connections to external IPs is a high-confidence indicator of C2 activity, not routine automation.",
        "category": "Execution",
        "mitre": "T1059",
    },
    {
        "text": "Log clearing (T1070) immediately following a privilege escalation event is a strong indicator that an attacker achieved their objective and is covering tracks. Treat as critical even if confidence is moderate.",
        "category": "Defense Evasion",
        "mitre": "T1070",
    },
    {
        "text": "Kerberoasting (T1558) produces a spike in TGS requests for service accounts. A single host requesting tickets for 5+ service accounts within 60 seconds is anomalous.",
        "category": "Credential Access",
        "mitre": "T1558",
    },
    {
        "text": "Ransomware impact (T1486) is preceded by shadow copy deletion (vssadmin delete shadows) and backup service disruption. These pre-encryption signals should trigger immediate ESCALATE.",
        "category": "Impact",
        "mitre": "T1486",
    },
]


def seed_lessons():
    from agents.shared.chroma_client import get_lessons_collection
    from uuid import uuid4
    from datetime import datetime, timezone

    collection = get_lessons_collection()
    logger.info("Seeding %d baseline MITRE lessons into ChromaDB...", len(MITRE_BASELINE_LESSONS))

    for lesson in MITRE_BASELINE_LESSONS:
        lesson_id = f"baseline_{uuid4().hex[:8]}"
        try:
            collection.add(
                documents=[lesson["text"]],
                metadatas=[{
                    "category":   lesson["category"],
                    "mitre":      lesson["mitre"],
                    "source":     "baseline",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }],
                ids=[lesson_id],
            )
            logger.info("  ✓ %s — %s", lesson["category"], lesson["mitre"])
        except Exception as exc:
            logger.warning("  ✗ Failed to seed lesson: %s", exc)

    total = collection.count()
    logger.info("ChromaDB now contains %d lessons", total)


if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("ASOC Seed Script")
    logger.info("=" * 50)

    try:
        seed_topology()
        logger.info("✓ Network topology seeded into Redis")
    except Exception as exc:
        logger.error("✗ Topology seed failed: %s", exc)

    try:
        seed_lessons()
        logger.info("✓ Baseline lessons seeded into ChromaDB")
    except Exception as exc:
        logger.error("✗ Lessons seed failed: %s", exc)

    logger.info("Seed complete. Run `make simulate` to test the full pipeline.")
