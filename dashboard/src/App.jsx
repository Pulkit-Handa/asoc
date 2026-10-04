// ASOC Dashboard — Autonomous SOC Platform
// Full product React UI with real-time SSE agent thought stream

import { useState, useEffect, useRef, useCallback } from "react";

const API_BASE = process.env.REACT_APP_API_URL || "http://localhost:8080";

// ─── Severity color mapping ──────────────────────────────────────────────────
const SEVERITY_COLOR = (s) => {
  if (s >= 0.8) return "#ff3b3b";
  if (s >= 0.6) return "#ff8c00";
  if (s >= 0.4) return "#f5c518";
  return "#39d353";
};

const DECISION_CONFIG = {
  ESCALATE:   { color: "#ff3b3b", bg: "rgba(255,59,59,0.12)", label: "ESCALATE" },
  MONITOR:    { color: "#f5c518", bg: "rgba(245,197,24,0.12)", label: "MONITOR" },
  AUTO_CLOSE: { color: "#39d353", bg: "rgba(57,211,83,0.12)",  label: "AUTO_CLOSE" },
};

// ─── Mock Data for Demo ───────────────────────────────────────────────────────
const MOCK_ALERTS = [
  {
    alert_id: "alert_a1b2c3d4e5f6",
    threat_category: "Lateral Movement",
    severity_score: 0.87,
    confidence_score: 0.91,
    decision: "ESCALATE",
    blast_radius: 47,
    exposure_score: 0.63,
    mitre_techniques: ["T1021", "T1534"],
    ingested_at: new Date(Date.now() - 32000).toISOString(),
    status: "ESCALATED",
  },
  {
    alert_id: "alert_b7c8d9e0f1a2",
    threat_category: "Credential Access",
    severity_score: 0.74,
    confidence_score: 0.82,
    decision: "MONITOR",
    blast_radius: 12,
    exposure_score: 0.22,
    mitre_techniques: ["T1003", "T1110"],
    ingested_at: new Date(Date.now() - 78000).toISOString(),
    status: "OPEN",
  },
  {
    alert_id: "alert_c3d4e5f6a7b8",
    threat_category: "Defense Evasion",
    severity_score: 0.51,
    confidence_score: 0.88,
    decision: "MONITOR",
    blast_radius: 5,
    exposure_score: 0.11,
    mitre_techniques: ["T1070", "T1036"],
    ingested_at: new Date(Date.now() - 145000).toISOString(),
    status: "OPEN",
  },
  {
    alert_id: "alert_d1e2f3a4b5c6",
    threat_category: "Exfiltration",
    severity_score: 0.93,
    confidence_score: 0.77,
    decision: "ESCALATE",
    blast_radius: 89,
    exposure_score: 0.71,
    mitre_techniques: ["T1041", "T1048"],
    ingested_at: new Date(Date.now() - 210000).toISOString(),
    status: "ESCALATED",
  },
  {
    alert_id: "alert_e5f6a7b8c9d0",
    threat_category: "Discovery",
    severity_score: 0.29,
    confidence_score: 0.94,
    decision: "AUTO_CLOSE",
    blast_radius: 0,
    exposure_score: 0.03,
    mitre_techniques: ["T1082"],
    ingested_at: new Date(Date.now() - 390000).toISOString(),
    status: "CLOSED",
  },
];

const MOCK_AGENT_STEPS = [
  { node: "triage",       color: "#7c3aed", icon: "⬡", label: "Triage Agent" },
  { node: "forensics",    color: "#0891b2", icon: "⬡", label: "Forensics Agent" },
  { node: "blast_radius", color: "#c2410c", icon: "⬡", label: "Blast Radius Agent" },
  { node: "decision",     color: "#059669", icon: "⬡", label: "Decision Node" },
  { node: "critic",       color: "#d97706", icon: "⬡", label: "Critic Agent" },
];

const MOCK_THOUGHT_STEPS = [
  { node: "triage",       text: "Querying ChromaDB for similar lessons... retrieved 2 matches. Running SecBERT classification on enriched context.",                    ts: 0.3 },
  { node: "triage",       text: "Classification: Lateral Movement (T1021). Confidence: 0.91 | Severity: 0.87. Risk Gate: PASS (conf ≥ 0.70).",                         ts: 1.1 },
  { node: "forensics",    text: "Querying ClickHouse for correlated events: src_ip=10.0.1.42, user=svc_account within 72h window...",                                  ts: 1.8 },
  { node: "forensics",    text: "Found 23 correlated events. Built kill-chain graph: 8 nodes, 14 edges. Louvain community detection: 3 communities → LATERAL MOVEMENT CONFIRMED.", ts: 2.9 },
  { node: "blast_radius", text: "BFS from node 'app-03' over network topology. Reachable: 47 assets. Crown jewels detected: db-primary, dc-01.",                       ts: 3.5 },
  { node: "blast_radius", text: "Exposure score: 0.63 → EXCEEDS threshold 0.40. Hard override: decision = ESCALATE.",                                                  ts: 3.9 },
  { node: "decision",     text: "Final decision: ESCALATE. Reason: Blast radius exposure 0.63 > threshold, crown jewels reachable: db-primary, dc-01. Persisting incident.", ts: 4.3 },
];

const MOCK_LESSONS = [
  { id: "lesson_001", category: "Lateral Movement", text: "When PSExec executions originate from service accounts outside business hours, check for prior credential dump events from same source IP within 24h.", created_at: "2026-03-10T14:22:00Z", source: "critic" },
  { id: "lesson_002", category: "Exfiltration",     text: "DNS tunneling via long FQDN queries (>60 chars) to newly-registered domains correlates strongly with C2 exfil; prior instances were AUTO_CLOSED due to low severity baseline.", created_at: "2026-03-09T08:11:00Z", source: "critic" },
  { id: "lesson_003", category: "Credential Access",text: "LSASS access from non-standard processes (not lsass.exe children) should trigger ESCALATE even when confidence is moderate — Mimikatz variants obfuscate process names.", created_at: "2026-03-08T16:45:00Z", source: "analyst" },
  { id: "lesson_004", category: "Defense Evasion",  text: "Timestomping via SetFileTime API calls within 60s of a new binary write should be weighted as high-severity regardless of process name, as this pattern precedes most ransomware deployments.", created_at: "2026-03-07T09:30:00Z", source: "critic" },
];

const MOCK_METRICS = {
  alerts_today: 1847,
  auto_triaged: 1762,
  escalated: 85,
  avg_confidence: 0.847,
  lesson_hit_rate: 0.43,
  false_positive_rate: 0.12,
  avg_triage_ms: 1840,
  lessons_stored: 312,
};

// ─── Helper Components ────────────────────────────────────────────────────────
function Badge({ label, color, bg }) {
  return (
    <span style={{
      display: "inline-flex", alignItems: "center",
      padding: "2px 8px", borderRadius: 4,
      fontSize: 11, fontFamily: "'JetBrains Mono', monospace",
      fontWeight: 700, letterSpacing: 1,
      color, background: bg || "transparent",
      border: `1px solid ${color}33`,
    }}>{label}</span>
  );
}

function MetricCard({ label, value, sub, color = "#e2e8f0" }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: 8, padding: "16px 20px",
    }}>
      <div style={{ fontSize: 11, color: "#64748b", fontFamily: "mono", letterSpacing: 1, marginBottom: 6 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: "#475569", marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function SeverityBar({ score, width = 80 }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ width, height: 4, background: "rgba(255,255,255,0.08)", borderRadius: 2, overflow: "hidden" }}>
        <div style={{ width: `${score * 100}%`, height: "100%", background: SEVERITY_COLOR(score), borderRadius: 2, transition: "width 0.4s" }} />
      </div>
      <span style={{ fontSize: 11, color: SEVERITY_COLOR(score), fontFamily: "mono", minWidth: 32 }}>
        {(score * 100).toFixed(0)}%
      </span>
    </div>
  );
}

// ─── Kill Chain Visualization (SVG) ──────────────────────────────────────────
function KillChainGraph({ alert }) {
  const nodes = [
    { id: "10.0.1.42",    x: 60,  y: 80,  type: "compromised" },
    { id: "app-01",       x: 180, y: 40,  type: "internal" },
    { id: "app-03",       x: 180, y: 120, type: "internal" },
    { id: "db-primary",   x: 300, y: 40,  type: "crown_jewel" },
    { id: "dc-01",        x: 300, y: 120, type: "crown_jewel" },
    { id: "backup-01",    x: 420, y: 80,  type: "internal" },
  ];
  const edges = [
    { src: 0, dst: 1, technique: "T1021" },
    { src: 0, dst: 2, technique: "T1534" },
    { src: 1, dst: 3, technique: "T1003" },
    { src: 2, dst: 4, technique: "T1021" },
    { src: 3, dst: 5, technique: "T1048" },
  ];
  const nodeColors = { compromised: "#ff3b3b", internal: "#7c3aed", crown_jewel: "#f59e0b" };

  return (
    <svg width="100%" viewBox="0 0 480 160" style={{ fontFamily: "'JetBrains Mono', monospace" }}>
      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#475569" />
        </marker>
      </defs>
      {edges.map((e, i) => (
        <g key={i}>
          <line
            x1={nodes[e.src].x} y1={nodes[e.src].y}
            x2={nodes[e.dst].x} y2={nodes[e.dst].y}
            stroke="#475569" strokeWidth={1.5} markerEnd="url(#arrow)" opacity={0.7}
          />
          <text
            x={(nodes[e.src].x + nodes[e.dst].x) / 2}
            y={(nodes[e.src].y + nodes[e.dst].y) / 2 - 6}
            fill="#64748b" fontSize={8} textAnchor="middle"
          >{e.technique}</text>
        </g>
      ))}
      {nodes.map((n, i) => (
        <g key={i}>
          <circle
            cx={n.x} cy={n.y} r={n.type === "crown_jewel" ? 16 : 12}
            fill={nodeColors[n.type] + "22"}
            stroke={nodeColors[n.type]} strokeWidth={n.type === "crown_jewel" ? 2 : 1.5}
          />
          {n.type === "crown_jewel" && (
            <circle cx={n.x} cy={n.y} r={19} fill="none" stroke={nodeColors[n.type]} strokeWidth={1} strokeDasharray="3 3" opacity={0.5} />
          )}
          <text x={n.x} y={n.y + 28} fill="#94a3b8" fontSize={8} textAnchor="middle">{n.id}</text>
        </g>
      ))}
    </svg>
  );
}

// ─── Agent Thought Stream ─────────────────────────────────────────────────────
function ThoughtStream({ alertId, steps }) {
  const endRef = useRef(null);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [steps]);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {steps.map((s, i) => {
        const agentStep = MOCK_AGENT_STEPS.find(a => a.node === s.node);
        return (
          <div key={i} style={{
            display: "flex", gap: 10, padding: "8px 12px",
            background: "rgba(255,255,255,0.02)", borderRadius: 6,
            borderLeft: `2px solid ${agentStep?.color || "#475569"}`,
            animation: "fadeIn 0.3s ease",
          }}>
            <span style={{ color: agentStep?.color, fontSize: 12, marginTop: 1, flexShrink: 0 }}>
              {agentStep?.label || s.node}
            </span>
            <span style={{ fontSize: 12, color: "#94a3b8", lineHeight: 1.5 }}>{s.text}</span>
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────
export default function ASOCDashboard() {
  const [tab, setTab] = useState("queue");
  const [selectedAlert, setSelectedAlert] = useState(MOCK_ALERTS[0]);
  const [thoughtSteps, setThoughtSteps] = useState([]);
  const [isStreaming, setIsStreaming] = useState(false);
  const [lessonQuery, setLessonQuery] = useState("");
  const [time, setTime] = useState(new Date());

  // Clock
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  // Simulate SSE thought stream when alert selected
  const runStream = useCallback((alert) => {
    setSelectedAlert(alert);
    setThoughtSteps([]);
    setIsStreaming(true);
    setTab("stream");

    MOCK_THOUGHT_STEPS.forEach((step, i) => {
      setTimeout(() => {
        setThoughtSteps(prev => [...prev, step]);
        if (i === MOCK_THOUGHT_STEPS.length - 1) setIsStreaming(false);
      }, step.ts * 1000);
    });
  }, []);

  const filteredLessons = MOCK_LESSONS.filter(l =>
    !lessonQuery || l.text.toLowerCase().includes(lessonQuery.toLowerCase()) ||
    l.category.toLowerCase().includes(lessonQuery.toLowerCase())
  );

  const tabs = [
    { id: "queue",   label: "Alert Queue" },
    { id: "stream",  label: "Agent Stream" },
    { id: "lessons", label: "Lesson Library" },
    { id: "metrics", label: "Metrics" },
  ];

  return (
    <div style={{
      minHeight: "100vh",
      background: "#080c14",
      color: "#e2e8f0",
      fontFamily: "'JetBrains Mono', 'Courier New', monospace",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: #0d1424; }
        ::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 2px; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes scanline {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
      `}</style>

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div style={{
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        background: "rgba(8,12,20,0.95)",
        backdropFilter: "blur(20px)",
        position: "sticky", top: 0, zIndex: 100,
        padding: "0 24px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        height: 56,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{
            width: 32, height: 32, borderRadius: 6,
            background: "linear-gradient(135deg, #7c3aed, #0891b2)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 16, fontWeight: 700,
          }}>A</div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, letterSpacing: 2, color: "#e2e8f0" }}>ASOC</div>
            <div style={{ fontSize: 9, color: "#475569", letterSpacing: 1.5 }}>AUTONOMOUS SOC PLATFORM v1.0</div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 24 }}>
          {/* Live indicator */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{
              width: 7, height: 7, borderRadius: "50%", background: "#39d353",
              animation: "pulse 2s infinite",
              boxShadow: "0 0 8px #39d353",
            }} />
            <span style={{ fontSize: 11, color: "#39d353", letterSpacing: 1 }}>LIVE</span>
          </div>
          {/* Stats */}
          <div style={{ display: "flex", gap: 16 }}>
            {[
              { label: "ALERTS/MIN", val: "31" },
              { label: "AUTO-TRIAGED", val: "95.4%" },
              { label: "AVG CONF", val: "84.7%" },
            ].map(s => (
              <div key={s.label} style={{ textAlign: "center" }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: "#7c3aed" }}>{s.val}</div>
                <div style={{ fontSize: 8, color: "#475569", letterSpacing: 1 }}>{s.label}</div>
              </div>
            ))}
          </div>
          {/* Clock */}
          <div style={{ fontSize: 12, color: "#475569", letterSpacing: 1 }}>
            {time.toUTCString().slice(17, 25)} UTC
          </div>
        </div>
      </div>

      <div style={{ display: "flex", height: "calc(100vh - 56px)" }}>

        {/* ── Sidebar ──────────────────────────────────────────────────── */}
        <div style={{
          width: 220, flexShrink: 0,
          borderRight: "1px solid rgba(255,255,255,0.06)",
          padding: "16px 0",
          background: "rgba(255,255,255,0.01)",
          display: "flex", flexDirection: "column",
        }}>
          <div style={{ padding: "0 16px 16px", fontSize: 10, color: "#475569", letterSpacing: 1.5 }}>NAVIGATION</div>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              width: "100%", textAlign: "left",
              padding: "10px 16px",
              background: tab === t.id ? "rgba(124,58,237,0.15)" : "transparent",
              borderLeft: tab === t.id ? "2px solid #7c3aed" : "2px solid transparent",
              border: "none", cursor: "pointer",
              color: tab === t.id ? "#a78bfa" : "#64748b",
              fontSize: 12, letterSpacing: 0.5,
              transition: "all 0.15s",
            }}>{t.label}</button>
          ))}

          <div style={{ marginTop: "auto", padding: "16px", borderTop: "1px solid rgba(255,255,255,0.05)" }}>
            <div style={{ fontSize: 10, color: "#475569", letterSpacing: 1, marginBottom: 8 }}>AGENT STATUS</div>
            {MOCK_AGENT_STEPS.map(a => (
              <div key={a.node} style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 5 }}>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: a.color, boxShadow: `0 0 4px ${a.color}` }} />
                <span style={{ fontSize: 10, color: "#64748b" }}>{a.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Main Content ─────────────────────────────────────────────── */}
        <div style={{ flex: 1, overflow: "auto", padding: 24 }}>

          {/* ALERT QUEUE */}
          {tab === "queue" && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
                <div>
                  <h2 style={{ fontSize: 18, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif" }}>Alert Queue</h2>
                  <p style={{ fontSize: 12, color: "#475569", marginTop: 2 }}>Real-time triage results — {MOCK_ALERTS.length} active incidents</p>
                </div>
                <button onClick={() => runStream(MOCK_ALERTS[0])} style={{
                  padding: "8px 16px", background: "rgba(124,58,237,0.2)",
                  border: "1px solid #7c3aed", borderRadius: 6,
                  color: "#a78bfa", fontSize: 12, cursor: "pointer",
                  letterSpacing: 0.5,
                }}>+ Ingest Test Alert</button>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {MOCK_ALERTS.map(alert => {
                  const dc = DECISION_CONFIG[alert.decision];
                  return (
                    <div key={alert.alert_id} onClick={() => runStream(alert)} style={{
                      background: "rgba(255,255,255,0.025)",
                      border: `1px solid rgba(255,255,255,0.07)`,
                      borderLeft: `3px solid ${SEVERITY_COLOR(alert.severity_score)}`,
                      borderRadius: 8, padding: "14px 18px",
                      cursor: "pointer", transition: "all 0.15s",
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.05)"}
                    onMouseLeave={e => e.currentTarget.style.background = "rgba(255,255,255,0.025)"}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                            <span style={{ fontSize: 13, fontWeight: 700, color: "#e2e8f0" }}>{alert.threat_category}</span>
                            <Badge label={dc.label} color={dc.color} bg={dc.bg} />
                            {alert.mitre_techniques.map(t => (
                              <Badge key={t} label={t} color="#475569" bg="rgba(71,85,105,0.15)" />
                            ))}
                          </div>
                          <div style={{ fontSize: 10, color: "#475569", marginBottom: 10, letterSpacing: 0.5 }}>
                            {alert.alert_id} · {new Date(alert.ingested_at).toLocaleTimeString()}
                          </div>
                          <div style={{ display: "flex", gap: 24 }}>
                            <div>
                              <div style={{ fontSize: 9, color: "#475569", letterSpacing: 1, marginBottom: 3 }}>SEVERITY</div>
                              <SeverityBar score={alert.severity_score} />
                            </div>
                            <div>
                              <div style={{ fontSize: 9, color: "#475569", letterSpacing: 1, marginBottom: 3 }}>CONFIDENCE</div>
                              <SeverityBar score={alert.confidence_score} />
                            </div>
                            <div>
                              <div style={{ fontSize: 9, color: "#475569", letterSpacing: 1, marginBottom: 3 }}>EXPOSURE</div>
                              <SeverityBar score={alert.exposure_score} />
                            </div>
                          </div>
                        </div>
                        <div style={{ textAlign: "right", marginLeft: 24 }}>
                          <div style={{ fontSize: 24, fontWeight: 700, color: SEVERITY_COLOR(alert.exposure_score) }}>
                            {alert.blast_radius}
                          </div>
                          <div style={{ fontSize: 9, color: "#475569" }}>ASSETS AT RISK</div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* AGENT THOUGHT STREAM */}
          {tab === "stream" && (
            <div>
              <div style={{ marginBottom: 20 }}>
                <h2 style={{ fontSize: 18, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif" }}>Agent Thought Stream</h2>
                {selectedAlert && (
                  <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 4 }}>
                    <span style={{ fontSize: 11, color: "#475569" }}>{selectedAlert.alert_id}</span>
                    <Badge label={selectedAlert.threat_category} color="#7c3aed" bg="rgba(124,58,237,0.12)" />
                    {isStreaming && (
                      <span style={{ fontSize: 11, color: "#39d353", animation: "pulse 1s infinite" }}>● STREAMING</span>
                    )}
                  </div>
                )}
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
                {/* Thought stream */}
                <div style={{
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid rgba(255,255,255,0.07)",
                  borderRadius: 8, padding: 16,
                  height: 420, overflowY: "auto",
                }}>
                  <div style={{ fontSize: 10, color: "#475569", letterSpacing: 1.5, marginBottom: 12 }}>CHAIN-OF-THOUGHT TRACE</div>
                  {thoughtSteps.length === 0 ? (
                    <div style={{ color: "#334155", fontSize: 12, textAlign: "center", marginTop: 40 }}>
                      Select an alert to stream agent reasoning
                    </div>
                  ) : (
                    <ThoughtStream alertId={selectedAlert?.alert_id} steps={thoughtSteps} />
                  )}
                </div>

                {/* Kill chain graph */}
                <div style={{
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid rgba(255,255,255,0.07)",
                  borderRadius: 8, padding: 16,
                }}>
                  <div style={{ fontSize: 10, color: "#475569", letterSpacing: 1.5, marginBottom: 12 }}>KILL CHAIN GRAPH</div>
                  {selectedAlert && <KillChainGraph alert={selectedAlert} />}
                  <div style={{ display: "flex", gap: 16, marginTop: 12 }}>
                    {[
                      { label: "Compromised", color: "#ff3b3b" },
                      { label: "Internal", color: "#7c3aed" },
                      { label: "Crown Jewel", color: "#f59e0b" },
                    ].map(l => (
                      <div key={l.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
                        <div style={{ width: 8, height: 8, borderRadius: "50%", background: l.color }} />
                        <span style={{ fontSize: 9, color: "#64748b" }}>{l.label}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* State snapshot */}
                {selectedAlert && (
                  <div style={{
                    gridColumn: "1 / -1",
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid rgba(255,255,255,0.07)",
                    borderRadius: 8, padding: 16,
                  }}>
                    <div style={{ fontSize: 10, color: "#475569", letterSpacing: 1.5, marginBottom: 12 }}>FINAL SOC STATE</div>
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 12 }}>
                      {[
                        { label: "THREAT CATEGORY", val: selectedAlert.threat_category },
                        { label: "DECISION", val: selectedAlert.decision, color: DECISION_CONFIG[selectedAlert.decision]?.color },
                        { label: "CONFIDENCE", val: `${(selectedAlert.confidence_score * 100).toFixed(1)}%` },
                        { label: "BLAST RADIUS", val: `${selectedAlert.blast_radius} assets` },
                        { label: "EXPOSURE", val: `${(selectedAlert.exposure_score * 100).toFixed(1)}%` },
                      ].map(f => (
                        <div key={f.label} style={{ background: "rgba(255,255,255,0.03)", borderRadius: 6, padding: "10px 12px" }}>
                          <div style={{ fontSize: 9, color: "#475569", letterSpacing: 1, marginBottom: 4 }}>{f.label}</div>
                          <div style={{ fontSize: 14, fontWeight: 700, color: f.color || "#e2e8f0" }}>{f.val}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* LESSON LIBRARY */}
          {tab === "lessons" && (
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
                <div>
                  <h2 style={{ fontSize: 18, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif" }}>Lesson Library</h2>
                  <p style={{ fontSize: 12, color: "#475569", marginTop: 2 }}>Vectorized institutional memory — {MOCK_LESSONS.length} lessons stored</p>
                </div>
              </div>
              <input
                placeholder="Semantic search lessons..."
                value={lessonQuery}
                onChange={e => setLessonQuery(e.target.value)}
                style={{
                  width: "100%", padding: "10px 14px", marginBottom: 16,
                  background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 6, color: "#e2e8f0", fontSize: 12,
                  fontFamily: "inherit", outline: "none",
                }}
              />
              <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                {filteredLessons.map(lesson => (
                  <div key={lesson.id} style={{
                    background: "rgba(255,255,255,0.025)",
                    border: "1px solid rgba(255,255,255,0.07)",
                    borderLeft: `3px solid ${lesson.source === "analyst" ? "#f59e0b" : "#7c3aed"}`,
                    borderRadius: 8, padding: "14px 18px",
                  }}>
                    <div style={{ display: "flex", gap: 8, marginBottom: 8 }}>
                      <Badge label={lesson.category} color="#7c3aed" bg="rgba(124,58,237,0.12)" />
                      <Badge
                        label={lesson.source === "analyst" ? "ANALYST" : "CRITIC AGENT"}
                        color={lesson.source === "analyst" ? "#f59e0b" : "#0891b2"}
                        bg="rgba(8,145,178,0.1)"
                      />
                    </div>
                    <p style={{ fontSize: 13, color: "#cbd5e1", lineHeight: 1.6 }}>{lesson.text}</p>
                    <div style={{ fontSize: 10, color: "#475569", marginTop: 8 }}>
                      {lesson.id} · {new Date(lesson.created_at).toLocaleString()}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* METRICS */}
          {tab === "metrics" && (
            <div>
              <h2 style={{ fontSize: 18, fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif", marginBottom: 4 }}>Platform Metrics</h2>
              <p style={{ fontSize: 12, color: "#475569", marginBottom: 20 }}>Live Prometheus gauges — last 24 hours</p>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
                <MetricCard label="ALERTS TODAY"      value={MOCK_METRICS.alerts_today.toLocaleString()} sub="since 00:00 UTC" />
                <MetricCard label="AUTO-TRIAGED"      value="95.4%" sub={`${MOCK_METRICS.auto_triaged} decisions`} color="#39d353" />
                <MetricCard label="ESCALATED"         value={MOCK_METRICS.escalated} sub="requiring human review" color="#ff3b3b" />
                <MetricCard label="AVG CONFIDENCE"    value="84.7%" sub="SecBERT risk gate" color="#a78bfa" />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 12, marginBottom: 24 }}>
                <MetricCard label="LESSON HIT RATE"   value="43.0%" sub="lessons informing decisions" color="#7c3aed" />
                <MetricCard label="FALSE POSITIVE RATE" value="12.0%" sub="down from 65% baseline" color="#39d353" />
                <MetricCard label="AVG TRIAGE LATENCY" value="1.84s" sub="P99 < 5s SLA" color="#f5c518" />
                <MetricCard label="LESSONS STORED"    value={MOCK_METRICS.lessons_stored} sub="vectorized in ChromaDB" color="#0891b2" />
              </div>

              {/* Goal progress */}
              <div style={{
                background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.07)",
                borderRadius: 8, padding: 20,
              }}>
                <div style={{ fontSize: 10, color: "#475569", letterSpacing: 1.5, marginBottom: 16 }}>GA LAUNCH TARGETS (Q2 2026)</div>
                {[
                  { label: "Alert Auto-Triage Rate",   current: 95.4, target: 95,  unit: "%" },
                  { label: "False Positive Rate",       current: 12,   target: 15,  unit: "%", inverse: true },
                  { label: "Lesson Hit Rate",           current: 43,   target: 40,  unit: "%" },
                  { label: "Triage Latency P99",        current: 1.84, target: 5,   unit: "s", inverse: true },
                ].map(m => {
                  const passing = m.inverse ? m.current <= m.target : m.current >= m.target;
                  const pct = m.inverse
                    ? Math.min(100, (m.target / m.current) * 100)
                    : Math.min(100, (m.current / m.target) * 100);
                  return (
                    <div key={m.label} style={{ marginBottom: 14 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
                        <span style={{ fontSize: 12, color: "#94a3b8" }}>{m.label}</span>
                        <span style={{ fontSize: 12, color: passing ? "#39d353" : "#f5c518" }}>
                          {m.current}{m.unit} / target {m.inverse ? "≤" : "≥"}{m.target}{m.unit} {passing ? "✓" : "↗"}
                        </span>
                      </div>
                      <div style={{ height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2, overflow: "hidden" }}>
                        <div style={{
                          height: "100%", width: `${pct}%`,
                          background: passing ? "#39d353" : "#f5c518",
                          borderRadius: 2, transition: "width 1s ease",
                        }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
