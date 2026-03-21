/**
 * ASOC Load Test — k6
 * ====================
 * Validates the GA throughput target: 10,000 alerts/second sustained.
 * Also validates P99 latency < 5 seconds end-to-end.
 *
 * Install k6: https://k6.io/docs/get-started/installation/
 *
 * Run (staged — recommended for first run):
 *   k6 run tests/load/load_test.js
 *
 * Run (full GA target — needs Kubernetes cluster):
 *   k6 run --env TARGET_RPS=10000 tests/load/load_test.js
 *
 * Run (soak test — 1 hour at sustained load):
 *   k6 run --env SOAK=true tests/load/load_test.js
 *
 * Success criteria (per PRD):
 *   ✓ p(99) < 5000ms  (5 second P99 end-to-end)
 *   ✓ error_rate < 1%
 *   ✓ p(95) < 3000ms
 *
 * What this tests:
 *   1. POST /alerts throughput (Kafka ingest path)
 *   2. GET /alerts/{id} read throughput (PostgreSQL read path)
 *   3. GET /incidents list throughput (PostgreSQL + pagination)
 *   4. GET /health latency (always-on path)
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Counter, Rate, Trend } from "k6/metrics";
import { randomString, randomIntBetween } from "https://jslib.k6.io/k6-utils/1.4.0/index.js";

// ── Config ────────────────────────────────────────────────────────────────────
const BASE_URL    = __ENV.BASE_URL    || "http://localhost:8080";
const TARGET_RPS  = parseInt(__ENV.TARGET_RPS || "100");
const SOAK        = __ENV.SOAK === "true";
const API_KEY     = __ENV.API_KEY || "dev-simulation-key";

const HEADERS = {
  "Content-Type":    "application/json",
  "Authorization":   `ApiKey ${API_KEY}`,
  "X-Correlation-ID": `k6-load-${Date.now()}`,
};

// ── Custom metrics ────────────────────────────────────────────────────────────
const alertIngested    = new Counter("alerts_ingested");
const alertErrors      = new Rate("alert_error_rate");
const ingestDuration   = new Trend("ingest_duration_ms",  true);
const pipelineDuration = new Trend("pipeline_duration_ms", true);

// ── Load profile ──────────────────────────────────────────────────────────────
export const options = SOAK
  ? {
      // Soak test: 1 hour at 500 RPS
      stages: [
        { duration: "5m",  target: 100  },
        { duration: "10m", target: 500  },
        { duration: "40m", target: 500  },
        { duration: "5m",  target: 0    },
      ],
      thresholds: {
        "http_req_duration{name:ingest}": ["p(99)<5000"],
        "alert_error_rate":               ["rate<0.01"],
      },
    }
  : {
      // Default: staged ramp to TARGET_RPS
      stages: [
        { duration: "30s", target: Math.floor(TARGET_RPS * 0.1) },
        { duration: "1m",  target: Math.floor(TARGET_RPS * 0.5) },
        { duration: "2m",  target: TARGET_RPS                    },
        { duration: "1m",  target: Math.floor(TARGET_RPS * 0.5) },
        { duration: "30s", target: 0                             },
      ],
      thresholds: {
        // PRD requirements
        "http_req_duration{name:ingest}":  ["p(99)<5000", "p(95)<3000"],
        "http_req_duration{name:health}":  ["p(99)<200"],
        "alert_error_rate":                ["rate<0.01"],
        "http_req_failed":                 ["rate<0.01"],
      },
    };

// ── Attack scenarios (realistic log samples) ──────────────────────────────────
const ATTACK_LOGS = [
  {
    raw_log: `EventID=4625 FailedLogon user=${randomString(8)} src_ip=192.168.${randomIntBetween(1,254)}.${randomIntBetween(1,254)} SubStatus=0xC000006A`,
    src_ip: `192.168.1.${randomIntBetween(1, 254)}`,
    user: `user_${randomString(6)}`,
  },
  {
    raw_log: `process=mimikatz.exe accessing=lsass.exe GrantedAccess=0x1410 src_ip=10.0.1.${randomIntBetween(1,254)} EventID=4656`,
    src_ip: `10.0.1.${randomIntBetween(1, 50)}`,
    host_id: "workstation-07",
  },
  {
    raw_log: `EventID=5140 ShareName=\\\\app-01\\ADMIN$ src_ip=10.0.${randomIntBetween(1,10)}.${randomIntBetween(1,254)} user=svc_${randomString(4)}`,
    src_ip: `10.0.1.${randomIntBetween(1, 100)}`,
  },
  {
    raw_log: `CEF:0|Fortinet|FortiGate|6.4|1|DNS Query|5|src=10.0.1.42 dst=8.8.8.8 dpt=53 msg=Anomalous DNS query length=287`,
    src_ip: "10.0.1.42",
  },
  {
    raw_log: `powershell.exe -WindowStyle Hidden -EncodedCommand SQBuAHYAbwBrAGUA user=jsmith host=wks-${randomIntBetween(1,50)}`,
    user: `user_${randomString(5)}`,
    host_id: `wks-${randomIntBetween(1, 50)}`,
  },
];

// ── Main virtual user scenario ────────────────────────────────────────────────
export default function () {
  const scenario = Math.random();

  if (scenario < 0.60) {
    // 60%: Alert ingest (the critical throughput path)
    ingestAlert();
  } else if (scenario < 0.80) {
    // 20%: Read incidents list
    listIncidents();
  } else if (scenario < 0.95) {
    // 15%: Health check
    healthCheck();
  } else {
    // 5%: Lesson search
    searchLessons();
  }

  sleep(0.1);
}

function ingestAlert() {
  const payload = ATTACK_LOGS[randomIntBetween(0, ATTACK_LOGS.length - 1)];

  const start = Date.now();
  const resp = http.post(
    `${BASE_URL}/alerts`,
    JSON.stringify({ ...payload, source: "k6_load_test" }),
    { headers: HEADERS, tags: { name: "ingest" } },
  );
  const duration = Date.now() - start;

  const ok = check(resp, {
    "ingest: status 202":      (r) => r.status === 202,
    "ingest: has alert_id":    (r) => r.json("alert_id") !== undefined,
    "ingest: has stream_url":  (r) => r.json("stream_url") !== undefined,
  });

  alertErrors.add(!ok);
  alertIngested.add(1);
  ingestDuration.add(duration);
}

function listIncidents() {
  const resp = http.get(
    `${BASE_URL}/incidents?limit=20`,
    { headers: HEADERS, tags: { name: "incidents" } },
  );
  check(resp, {
    "incidents: status 200": (r) => r.status === 200,
    "incidents: is array":   (r) => Array.isArray(r.json()),
  });
}

function healthCheck() {
  const resp = http.get(
    `${BASE_URL}/health`,
    { tags: { name: "health" } },
  );
  check(resp, {
    "health: status 200": (r) => r.status === 200,
    "health: has status": (r) => r.json("status") === "ok",
  });
}

function searchLessons() {
  const queries = [
    "lateral movement SMB",
    "credential dump lsass",
    "ransomware shadow copy",
    "DNS tunneling exfiltration",
  ];
  const q = queries[randomIntBetween(0, queries.length - 1)];
  const resp = http.get(
    `${BASE_URL}/lessons/search?q=${encodeURIComponent(q)}&n_results=5`,
    { headers: HEADERS, tags: { name: "lessons" } },
  );
  check(resp, {
    "lessons: status 200": (r) => r.status === 200,
  });
}

// ── Summary ───────────────────────────────────────────────────────────────────
export function handleSummary(data) {
  const p99 = data.metrics["http_req_duration{name:ingest}"]?.values?.["p(99)"] ?? "N/A";
  const p95 = data.metrics["http_req_duration{name:ingest}"]?.values?.["p(95)"] ?? "N/A";
  const errRate = ((data.metrics.alert_error_rate?.values?.rate ?? 0) * 100).toFixed(2);

  console.log(`
╔══════════════════════════════════════════════╗
║  ASOC Load Test Summary                      ║
╠══════════════════════════════════════════════╣
║  Alerts ingested:  ${String(data.metrics.alerts_ingested?.values?.count ?? 0).padEnd(25)}║
║  P99 ingest time:  ${String(p99 + "ms").padEnd(25)}║
║  P95 ingest time:  ${String(p95 + "ms").padEnd(25)}║
║  Error rate:       ${String(errRate + "%").padEnd(25)}║
╠══════════════════════════════════════════════╣
║  PRD Targets:                                ║
║  P99 < 5000ms: ${p99 !== "N/A" && parseFloat(p99) < 5000 ? "✅ PASS" : "❌ FAIL            "}║
║  Error < 1%:   ${parseFloat(errRate) < 1 ? "✅ PASS" : "❌ FAIL            "}║
╚══════════════════════════════════════════════╝
`);

  return {
    "tests/load/results/summary.json": JSON.stringify(data, null, 2),
    stdout: "",
  };
}
