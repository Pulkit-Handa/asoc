-- ASOC ClickHouse Schema v1
-- Run at startup via docker-entrypoint-initdb.d

CREATE DATABASE IF NOT EXISTS asoc;

-- Main events table: MergeTree ordered by (host_id, timestamp)
-- Supports sub-500ms forensic correlation queries over billions of rows
CREATE TABLE IF NOT EXISTS asoc.events (
    event_id      UUID           DEFAULT generateUUIDv4(),
    timestamp     DateTime64(3)  DEFAULT now64(),
    host_id       String,
    src_ip        IPv4           DEFAULT toIPv4('0.0.0.0'),
    dst_ip        IPv4           DEFAULT toIPv4('0.0.0.0'),
    dst_host      String         DEFAULT '',
    user_account  LowCardinality(String) DEFAULT '',
    process_hash  String         DEFAULT '',
    mitre_id      LowCardinality(String) DEFAULT '',
    raw_log       String         DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host_id, timestamp)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Materialized view: index by src_ip for fast lateral movement queries
CREATE MATERIALIZED VIEW IF NOT EXISTS asoc.events_by_src
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (src_ip, timestamp)
AS SELECT
    event_id,
    timestamp,
    src_ip,
    host_id,
    user_account,
    mitre_id
FROM asoc.events;

-- Materialized view: index by user_account for credential abuse queries
CREATE MATERIALIZED VIEW IF NOT EXISTS asoc.events_by_user
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (user_account, timestamp)
AS SELECT
    event_id,
    timestamp,
    user_account,
    src_ip,
    host_id,
    mitre_id
FROM asoc.events
WHERE user_account != '';

-- Agent decisions table: audit trail of all automated decisions
CREATE TABLE IF NOT EXISTS asoc.asoc_decisions (
    alert_id        String,
    timestamp       DateTime64(3) DEFAULT now64(),
    threat_category LowCardinality(String),
    decision        LowCardinality(String),
    confidence_score Float32,
    severity_score   Float32,
    blast_radius     UInt32,
    exposure_score   Float32,
    mitre_techniques String,
    lesson_hit       UInt8  DEFAULT 0,
    processing_ms    UInt32 DEFAULT 0
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, decision)
TTL toDateTime(timestamp) + INTERVAL 365 DAY;
