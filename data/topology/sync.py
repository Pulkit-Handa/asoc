"""
Topology Sync Job
=================
Keeps the Redis network topology graph up to date.
The Blast Radius Agent reads this graph on every alert.
A stale graph means incorrect exposure scores.

Run as a Kubernetes CronJob every hour (cfg.topology_sync_interval_sec).
Can also be triggered manually via POST /admin/topology/sync.

Supported sources (set TOPOLOGY_SOURCE in .env):
  static  — uses the seeded topology (good for dev/demo)
  aws     — discovers from AWS VPC Flow Logs + EC2 inventory
  nmap    — runs nmap discovery against configured CIDR ranges
  qualys  — imports from Qualys VMDR asset inventory API

For each source, implement a _fetch_{source}() function that returns
a networkx.Graph with nodes having at minimum:
  - "segment" attribute (dmz, app, data, identity, infra)
  - "crown_jewel" attribute (bool)
  - "role" attribute (web_server, database, domain_controller, etc.)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import networkx as nx

from agents.blast_radius.topology import save_topology, CROWN_JEWEL_KEY, _get_redis
from config.settings import cfg

logger = logging.getLogger(__name__)


def sync_topology() -> tuple[int, int]:
    """
    Fetch the latest topology from the configured source and update Redis.
    Returns (node_count, edge_count).
    """
    source = cfg.topology_source
    logger.info("Starting topology sync: source=%s", source)

    fetcher = {
        "static":  _fetch_static,
        "aws":     _fetch_aws,
        "nmap":    _fetch_nmap,
        "qualys":  _fetch_qualys,
    }.get(source)

    if not fetcher:
        raise ValueError(f"Unknown TOPOLOGY_SOURCE: {source!r}. Use: static, aws, nmap, qualys")

    graph = fetcher()

    if graph.number_of_nodes() == 0:
        logger.error("Topology sync returned empty graph — not updating Redis")
        return 0, 0

    save_topology(graph)
    _update_crown_jewels(graph)

    nodes = graph.number_of_nodes()
    edges = graph.number_of_edges()

    logger.info(
        "Topology synced: source=%s nodes=%d edges=%d",
        source, nodes, edges,
    )
    _record_sync_time()

    return nodes, edges


def _update_crown_jewels(graph: nx.Graph) -> None:
    r = _get_redis()
    crown_jewels = [n for n, d in graph.nodes(data=True) if d.get("crown_jewel")]
    if crown_jewels:
        r.delete(CROWN_JEWEL_KEY)
        r.sadd(CROWN_JEWEL_KEY, *crown_jewels)
        logger.info("Crown jewels updated: %d assets", len(crown_jewels))


def _record_sync_time() -> None:
    r = _get_redis()
    r.set("asoc:topology:last_sync", datetime.now(timezone.utc).isoformat())


def get_last_sync_time() -> Optional[str]:
    try:
        r = _get_redis()
        val = r.get("asoc:topology:last_sync")
        return val.decode() if val else None
    except Exception:
        return None


# ── Source implementations ────────────────────────────────────────────────────

def _fetch_static() -> nx.Graph:
    """
    Returns the hardcoded dev topology.
    Also used as the fallback when other sources fail.
    """
    from scripts.seed_topology import build_example_topology
    return build_example_topology()


def _fetch_aws() -> nx.Graph:
    """
    Discover topology from AWS:
      - EC2 instances (roles from tags)
      - Security group rules (edges = allowed traffic)
      - Crown jewels = instances tagged Crown_Jewel=true or
        running RDS, DynamoDB, Secrets Manager

    Requires: boto3 installed, AWS credentials configured
    """
    try:
        import boto3
    except ImportError:
        raise ImportError(
            "boto3 is required for AWS topology discovery. "
            "Install with: poetry add boto3"
        )

    logger.info("Fetching topology from AWS EC2 + Security Groups...")
    G = nx.Graph()

    ec2 = boto3.client("ec2", region_name=cfg.topology_source)

    # Fetch all running EC2 instances
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                instance_id = instance["InstanceId"]
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                segment     = tags.get("Segment", "app")
                role        = tags.get("Role", "ec2_instance")
                crown_jewel = tags.get("Crown_Jewel", "false").lower() == "true"

                G.add_node(instance_id, segment=segment, role=role, crown_jewel=crown_jewel)

    # Fetch security group rules to build edges
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    sg_to_instances: dict[str, list[str]] = {}

    for instance_id in G.nodes():
        r = ec2.describe_instances(InstanceIds=[instance_id])
        sg_ids = [sg["GroupId"] for sg in r["Reservations"][0]["Instances"][0].get("SecurityGroups", [])]
        for sg_id in sg_ids:
            sg_to_instances.setdefault(sg_id, []).append(instance_id)

    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            source_instances = sg_to_instances.get(sg["GroupId"], [])
            for pair in rule.get("UserIdGroupPairs", []):
                target_instances = sg_to_instances.get(pair.get("GroupId", ""), [])
                for src in source_instances:
                    for dst in target_instances:
                        if src != dst and G.has_node(src) and G.has_node(dst):
                            G.add_edge(src, dst)

    logger.info("AWS topology: %d instances, %d connections", G.number_of_nodes(), G.number_of_edges())
    return G


def _fetch_nmap() -> nx.Graph:
    """
    Stub: Run nmap discovery against configured CIDR ranges.
    Requires: python-nmap installed, nmap binary on PATH,
              NMAP_TARGETS env var set to comma-separated CIDRs
    """
    import os
    targets = os.getenv("NMAP_TARGETS", "")
    if not targets:
        logger.warning("NMAP_TARGETS not set — falling back to static topology")
        return _fetch_static()

    try:
        import nmap
    except ImportError:
        raise ImportError("python-nmap required: poetry add python-nmap")

    logger.info("Running nmap discovery on: %s", targets)
    nm = nmap.PortScanner()
    G  = nx.Graph()

    for target in targets.split(","):
        nm.scan(hosts=target.strip(), arguments="-sn -T4")
        for host in nm.all_hosts():
            hostname = nm[host].hostname() or host
            G.add_node(hostname, segment="discovered", crown_jewel=False, role="host",
                       ip=host)

    logger.info("Nmap topology: %d hosts discovered", G.number_of_nodes())
    return G


def _fetch_qualys() -> nx.Graph:
    """
    Stub: Import from Qualys VMDR asset inventory.
    Requires: QUALYS_USERNAME, QUALYS_PASSWORD, QUALYS_PLATFORM env vars
    """
    import os
    logger.warning("Qualys topology source not yet implemented — falling back to static")
    return _fetch_static()
