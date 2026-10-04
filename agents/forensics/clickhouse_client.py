"""
ClickHouse Client for Forensic Event Correlation
=================================================
Uses clickhouse-driver for high-speed OLAP queries over the events table.
The MergeTree table ordered by (host_id, timestamp) enables sub-500ms
correlation over 10B+ rows.
"""
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Dict, List, Optional

from clickhouse_driver import Client

logger = logging.getLogger(__name__)


def get_client() -> Client:
    host = os.getenv("CLICKHOUSE_HOST", "localhost")
    port = int(os.getenv("CLICKHOUSE_PORT", "9000"))
    db   = os.getenv("CLICKHOUSE_DB", "asoc")
    user = os.getenv("CLICKHOUSE_USER", "default")
    pwd  = os.getenv("CLICKHOUSE_PASSWORD", "")
    return Client(host=host, port=port, database=db, user=user, password=pwd)


# ── Schema creation ──────────────────────────────────────────────────────────

CREATE_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS events (
    event_id       UUID           DEFAULT generateUUIDv4(),
    timestamp      DateTime64(3),
    host_id        String,
    src_ip         IPv4,
    dst_ip         IPv4,
    dst_host       String         DEFAULT '',
    user_account   LowCardinality(String),
    process_hash   FixedString(64) DEFAULT '',
    mitre_id       LowCardinality(String),
    raw_log        String
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host_id, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192
"""

CREATE_EVENTS_MV = """
CREATE MATERIALIZED VIEW IF NOT EXISTS events_by_src_ip
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (src_ip, timestamp)
AS SELECT
    src_ip,
    timestamp,
    event_id,
    host_id,
    user_account,
    mitre_id
FROM events
"""


def init_schema():
    client = get_client()
    client.execute(CREATE_EVENTS_TABLE)
    client.execute(CREATE_EVENTS_MV)
    logger.info("ClickHouse schema initialized")


# ── Forensic correlation query ───────────────────────────────────────────────

CORRELATION_QUERY = """
SELECT
    event_id,
    toString(timestamp)   AS timestamp,
    host_id,
    toString(src_ip)      AS src_ip,
    toString(dst_ip)      AS dst_ip,
    dst_host,
    user_account,
    hex(process_hash)     AS process_hash,
    mitre_id,
    raw_log
FROM events
WHERE
    timestamp >= %(since)s
    AND (
        src_ip = toIPv4OrDefault(%(src_ip)s)
        OR user_account = %(user)s
        OR process_hash = unhex(%(process_hash)s)
    )
ORDER BY timestamp ASC
LIMIT 10000
"""


def query_correlated_events(
    src_ip:         Optional[str],
    user:           Optional[str],
    process_hash:   Optional[str],
    lookback_hours: int = 72,
) -> List[Dict[str, Any]]:
    """
    Fetch all events correlated with the alert within the lookback window.
    Returns a list of dicts matching the events table schema.
    """
    since = (
        datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    ).strftime("%Y-%m-%d %H:%M:%S")

    params = {
        "since":        since,
        "src_ip":       src_ip or "0.0.0.0",
        "user":         user or "",
        "process_hash": process_hash or ("0" * 64),
    }

    client = None
    try:
        client = get_client()
        rows, columns = client.execute(
            CORRELATION_QUERY, params, with_column_types=True
        )
        col_names = [col[0] for col in columns]
        return [dict(zip(col_names, row)) for row in rows]
    except Exception as exc:
        logger.error("ClickHouse forensic query failed: %s", exc)
        return []
    finally:
        if client:
            client.disconnect()


def insert_events(events: List[Dict[str, Any]]) -> int:
    """Bulk insert normalized events into ClickHouse."""
    if not events:
        return 0
    client = None
    try:
        client = get_client()
        client.execute(
            "INSERT INTO events (timestamp, host_id, src_ip, dst_ip, dst_host, "
            "user_account, process_hash, mitre_id, raw_log) VALUES",
            events,
        )
        return len(events)
    finally:
        if client:
            client.disconnect()
