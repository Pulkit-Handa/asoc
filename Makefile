# ─────────────────────────────────────────────────────────────────────────────
# ASOC Makefile — Production Commands
# ─────────────────────────────────────────────────────────────────────────────
.PHONY: help dev prod test unit integration load seed migrate lint fmt typecheck \
        docker-build topology-sync dlq-list clean

PYTHON     = poetry run python
PYTEST     = poetry run pytest
API_URL   ?= http://localhost:8080

help:
	@echo ""
	@echo "  ASOC v1.2 — Autonomous SOC"
	@echo ""
	@echo "  Dev Setup:"
	@echo "    make install        Install all Python dependencies"
	@echo "    make dev            Start full local stack (Docker + API + worker)"
	@echo "    make migrate        Run Alembic migrations"
	@echo "    make seed           Seed topology + baseline lessons"
	@echo ""
	@echo "  Testing:"
	@echo "    make unit           Unit tests (no Docker required)"
	@echo "    make integration    Integration tests (requires running stack)"
	@echo "    make load           k6 load test against local stack"
	@echo "    make test           All tests"
	@echo "    make coverage       HTML coverage report"
	@echo ""
	@echo "  Code Quality:"
	@echo "    make lint           Ruff linter"
	@echo "    make fmt            Black formatter"
	@echo "    make typecheck      mypy type checking"
	@echo ""
	@echo "  Operations:"
	@echo "    make topology-sync  Trigger immediate topology refresh"
	@echo "    make dlq-list       List failed alerts in DLQ"
	@echo "    make logs           Tail API logs"
	@echo ""

install:
	poetry install --with dev

dev: ## Start full local development stack
	docker-compose up -d kafka postgres redis chromadb clickhouse prometheus grafana
	@echo "Waiting for services to be healthy..."
	@sleep 10
	$(MAKE) migrate
	$(MAKE) seed
	@echo ""
	@echo "Starting API (port 8080) and Worker in tmux..."
	@echo "Or run manually in two terminals:"
	@echo "  Terminal 1: ASOC_DEV_MODE=true poetry run uvicorn api.main:app --reload"
	@echo "  Terminal 2: ASOC_DEV_MODE=true poetry run python -m data.kafka.consumer"

migrate: ## Apply all Alembic migrations
	$(PYTHON) -m alembic upgrade head

seed: ## Seed network topology and baseline lessons
	$(PYTHON) scripts/seed_topology.py

simulate: ## Send lateral movement attack through pipeline
	$(PYTHON) scripts/simulate_attack.py --scenario lateral_movement

simulate-all: ## Run all attack scenarios
	$(PYTHON) scripts/simulate_attack.py --scenario all

unit: ## Fast unit tests (no infrastructure)
	$(PYTEST) tests/unit/ -m "not integration" -v

integration: ## Integration tests (requires Docker stack)
	ASOC_DEV_MODE=true $(PYTEST) tests/integration/ -v --timeout=60

load: ## k6 load test (install k6 first: https://k6.io)
	@which k6 > /dev/null || (echo "k6 not found. Install: https://k6.io/docs/get-started/installation/" && exit 1)
	k6 run --env BASE_URL=$(API_URL) tests/load/load_test.js

load-ga: ## k6 load test at GA target (10k RPS — needs cluster)
	k6 run --env BASE_URL=$(API_URL) --env TARGET_RPS=10000 tests/load/load_test.js

test: unit integration ## Run all tests

coverage: ## Generate HTML coverage report
	$(PYTEST) tests/unit/ --cov=. --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

lint: ## Ruff linter
	poetry run ruff check . --fix

fmt: ## Black formatter
	poetry run black .

typecheck: ## mypy type checking
	poetry run mypy agents/ api/ data/ config/ --ignore-missing-imports

topology-sync: ## Trigger immediate topology sync via admin API
	curl -s -X POST $(API_URL)/admin/topology/sync \
	  -H "Authorization: ApiKey dev-simulation-key" | python3 -m json.tool

dlq-list: ## List failed alerts
	curl -s $(API_URL)/admin/dlq \
	  -H "Authorization: ApiKey dev-simulation-key" | python3 -m json.tool

logs: ## Tail API logs
	docker-compose logs -f asoc-api 2>/dev/null || poetry run uvicorn api.main:app --reload

circuit-breakers: ## Show circuit breaker states
	curl -s $(API_URL)/admin/circuit-breakers \
	  -H "Authorization: ApiKey dev-simulation-key" | python3 -m json.tool

clean: ## Stop Docker services and remove volumes
	docker-compose down -v
	find . -type d -name __pycache__ | xargs rm -rf
	find . -type d -name .pytest_cache | xargs rm -rf
	find . -type d -name htmlcov | xargs rm -rf

docker-build: ## Build Docker images
	docker build --target api    -t asoc-api:1.2.0    .
	docker build --target worker -t asoc-worker:1.2.0 .
