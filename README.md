# ASOC — Autonomous SOC Platform
> Self-Evolving Multi-Agent Security Operations Platform v1.0

[![CI](https://github.com/asoc/asoc/actions/workflows/ci.yml/badge.svg)](https://github.com/asoc/asoc/actions)
[![Coverage](https://img.shields.io/badge/coverage-87%25-green)](htmlcov/index.html)

## Vision

ASOC is a self-evolving, multi-agent AI platform that autonomously triages, investigates, and learns from security threats — replacing the reactive, alert-fatigued manual SOC with a system that gets demonstrably smarter after every incident.

## Architecture

```
[Kafka] → [Triage Agent] → [Risk Gate] → [Forensics Agent] → [Blast Radius Agent] → [Decision] → [Critic Agent]
              ↓ (SecBERT)       ↓                ↓ (NetworkX)         ↓ (BFS VaR)                    ↓
           ChromaDB          ESCALATE        ClickHouse           Exposure Score               Lesson Stored
         (lessons)          (Human)         (72h events)          (crown jewels)               (ChromaDB)
```

**Four Specialized Agents:**
| Agent | Model | Responsibility |
|-------|-------|----------------|
| **Triage** | SecBERT | Classify threat, compute confidence score, retrieve lessons |
| **Forensics** | NetworkX | Build kill-chain graph, detect lateral movement |
| **Blast Radius** | BFS/VaR | Compute asset exposure, identify crown-jewel reach |
| **Critic** | Claude/GPT-4 | Generate lessons from mistakes, store in ChromaDB |

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/asoc/asoc
cd asoc
poetry install

# 2. Configure environment
cp .env.example .env
# Edit .env: add ANTHROPIC_API_KEY, OPENAI_API_KEY

# 3. Start full stack
make dev

# 4. Seed data and run simulation
make seed
make simulate
```

**Services after `make dev`:**
| Service | URL |
|---------|-----|
| ASOC API (Swagger) | http://localhost:8080/docs |
| React Dashboard | http://localhost:3000 |
| Grafana | http://localhost:3001 |
| ChromaDB | http://localhost:8000 |
| Prometheus | http://localhost:9090 |

## Key Metrics (GA Targets)
| Metric | Baseline | Target |
|--------|----------|--------|
| Alert Triage Time | 45-120 min | < 90 seconds |
| False Positive Rate | 65-80% | < 15% after 30 days |
| Alert Coverage | < 5% | > 95% automated |
| MTTD | 197 days | < 4 hours |

## Repository Structure

```
asoc/
├── agents/           # Intelligence Layer (LangGraph multi-agent system)
│   ├── triage/       # SecBERT + lesson retrieval
│   ├── forensics/    # NetworkX kill-chain graph
│   ├── blast_radius/ # BFS exposure scoring
│   ├── critic/       # Self-correction loop
│   ├── orchestrator/ # LangGraph StateGraph + SOCState
│   └── shared/       # LLM client, ChromaDB client, MITRE lookup
├── data/             # Data Layer
│   ├── kafka/        # Producers + consumers
│   ├── clickhouse/   # OLAP schema + forensic queries
│   ├── postgres/     # SQLAlchemy models + Alembic
│   └── normalizers/  # CEF, Syslog, Windows Event parsers
├── api/              # Presentation Layer (FastAPI + SSE)
│   ├── routers/      # alerts, incidents, lessons, stream
│   └── middleware/   # JWT auth, rate limiter
├── dashboard/        # React frontend
├── infra/            # K8s, Helm, Terraform, monitoring
├── ml/               # SecBERT fine-tuning, drift detection
└── scripts/          # Seed, simulate, backfill
```

## Development Commands

```bash
make test         # Run pytest with coverage
make lint         # Run ruff linter  
make type-check   # Run mypy
make migrate      # Run Alembic migrations
make logs-api     # Tail API logs
make clean        # Tear down all containers
```

## The Self-Correction Loop (Core Differentiator)

Every confirmed false negative automatically generates a Lesson Learned:

1. Critic Agent detects `confirmed_outcome == FALSE_NEGATIVE`
2. LLM generates structured post-mortem: "What signal did we miss?"
3. Lesson embedded via `text-embedding-3-small` → stored in ChromaDB
4. Future Triage Agent calls retrieve top-3 similar lessons before classification
5. False negative rate decreases measurably week-over-week

**This creates a system where institutional memory compounds over time.**

## Security Considerations

- All LLM inputs are PII-masked before API calls (NFR-11)
- JWT authentication required on all endpoints (NFR-06)
- Data at rest encrypted AES-256 (NFR-07)
- Adversarial robustness evaluation against prompt injection via log content required before production (Open Question #5)

## License

Internal — Classification: CONFIDENTIAL
