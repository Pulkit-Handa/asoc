"""
ASOC Centralized Configuration
================================
Single source of truth for every config value in the platform.

Every value is:
  - Type-validated at startup (bad config fails fast, not mid-processing)
  - Documented with description and examples
  - Loaded from environment / .env file
  - Accessible via the singleton: from config.settings import cfg

Production deployment: inject via Kubernetes Secrets + ConfigMaps.
Never commit .env files. Use ASOC_ENV=production to enable strict checks.
"""
from __future__ import annotations

import logging
from enum import Enum
from functools import lru_cache
from typing import Optional

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING     = "staging"
    PRODUCTION  = "production"


class LLMProvider(str, Enum):
    ANTHROPIC   = "anthropic"
    OPENAI      = "openai"
    OLLAMA      = "ollama"
    GEMINI      = "gemini"
    HUGGINGFACE = "huggingface"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Runtime environment ───────────────────────────────────────────────────
    asoc_env: Environment = Field(Environment.DEVELOPMENT, description="Runtime environment")
    asoc_dev_mode: bool   = Field(False, description="Disables JWT auth — never use in production")
    log_level: str        = Field("INFO", description="Python log level")
    log_format: str       = Field("json", description="'json' for prod, 'text' for dev")

    # ── LLM (Critic Agent reasoning only) ────────────────────────────────────
    llm_provider: LLMProvider = Field(LLMProvider.ANTHROPIC)

    anthropic_api_key: Optional[SecretStr] = Field(None)
    anthropic_model: str = Field("claude-sonnet-4-20250514")

    openai_api_key: Optional[SecretStr] = Field(None)
    openai_model: str = Field("gpt-4o-mini")

    google_api_key: Optional[SecretStr] = Field(None)
    gemini_model: str = Field("gemini-1.5-flash")

    ollama_model: str    = Field("llama3.2")
    ollama_base_url: str = Field("http://localhost:11434")

    hf_api_token: Optional[SecretStr] = Field(None)
    hf_model: str = Field("mistralai/Mistral-7B-Instruct-v0.3")

    # ── Embeddings (fully local, no key required) ─────────────────────────────
    embedding_model: str   = Field("BAAI/bge-small-en-v1.5")
    embedding_device: str  = Field("auto", description="auto | cpu | cuda | mps")
    embedding_batch_size: int = Field(64, description="Batch size for encoding many texts at once")

    # ── PostgreSQL ────────────────────────────────────────────────────────────
    database_url: SecretStr = Field(
        "postgresql+psycopg2://asoc:asoc_dev_password@localhost:5432/asoc"
    )
    db_pool_size: int     = Field(10)
    db_max_overflow: int  = Field(20)
    db_pool_timeout: int  = Field(30)
    db_pool_recycle: int  = Field(1800, description="Recycle connections every 30 min")

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_host: str = Field("localhost")
    redis_port: int = Field(6379)
    redis_password: Optional[SecretStr] = Field(None)
    redis_db_state: int    = Field(0, description="LangGraph checkpointing")
    redis_db_topology: int = Field(1, description="Network topology graph")
    redis_db_pubsub: int   = Field(2, description="SSE pub/sub channels")
    redis_db_ratelimit: int = Field(3, description="Rate limiting counters")

    # ── ClickHouse ────────────────────────────────────────────────────────────
    clickhouse_host: str     = Field("localhost")
    clickhouse_port: int     = Field(9000)
    clickhouse_db: str       = Field("asoc")
    clickhouse_user: str     = Field("default")
    clickhouse_password: Optional[SecretStr] = Field(None)
    clickhouse_pool_size: int = Field(5)

    # ── ChromaDB ─────────────────────────────────────────────────────────────
    chromadb_host: str          = Field("localhost")
    chromadb_port: int          = Field(8000)
    chromadb_persistent: bool   = Field(False)
    chromadb_persist_path: str  = Field("./chroma_data")

    # ── Kafka ─────────────────────────────────────────────────────────────────
    kafka_bootstrap: str     = Field("localhost:9092")
    kafka_consumer_group: str = Field("asoc-triage-worker")
    kafka_batch_size: int    = Field(50)
    kafka_dlq_topic: str     = Field("security.dlq", description="Dead letter queue for failed alerts")
    kafka_max_retries: int   = Field(3, description="Retries before sending to DLQ")

    # ── API Security ──────────────────────────────────────────────────────────
    jwt_secret: SecretStr = Field("CHANGE_ME_IN_PRODUCTION")
    jwt_algorithm: str    = Field("HS256")
    jwt_expire_minutes: int       = Field(480,   description="Access token lifetime")
    jwt_refresh_expire_days: int  = Field(30,    description="Refresh token lifetime")
    api_keys: str = Field("", description="Comma-separated static API keys for SIEM integrations")
    cors_origins: str = Field("http://localhost:3000")

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    rate_limit_requests: int    = Field(1000)
    rate_limit_window_sec: int  = Field(60)

    # ── Agent thresholds (match PRD) ──────────────────────────────────────────
    risk_gate_threshold: float       = Field(0.70, description="Min confidence to continue automation")
    escalate_exposure_threshold: float = Field(0.40, description="Exposure score that forces ESCALATE")
    crown_jewel_weight: int           = Field(10,   description="Crown-jewel asset multiplier in BFS")
    lesson_min_similarity: float      = Field(0.30, description="Min cosine sim to use a retrieved lesson")
    lesson_review_required: bool      = Field(True, description="Require human review before lesson goes live")

    # ── SecBERT ───────────────────────────────────────────────────────────────
    secbert_model_path: str  = Field("", description="Path to fine-tuned checkpoint; empty=base model")
    secbert_batch_size: int  = Field(32,  description="Batch size for SecBERT inference")

    # ── Topology sync ─────────────────────────────────────────────────────────
    topology_sync_interval_sec: int = Field(3600, description="How often to refresh network topology")
    topology_source: str = Field("static", description="static | aws | nmap | qualys")

    # ── Observability ─────────────────────────────────────────────────────────
    otel_endpoint: str    = Field("", description="OpenTelemetry collector endpoint (gRPC)")
    otel_service_name: str = Field("asoc")
    prometheus_pushgateway: str = Field("")
    sentry_dsn: Optional[str]   = Field(None, description="Sentry DSN for error tracking")

    # ── Validators ────────────────────────────────────────────────────────────
    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if v.upper() not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return v.upper()

    @model_validator(mode="after")
    def validate_production_requirements(self) -> "Settings":
        if self.asoc_env == Environment.PRODUCTION:
            errors = []

            if self.asoc_dev_mode:
                errors.append("ASOC_DEV_MODE must be false in production")

            jwt_secret = self.jwt_secret.get_secret_value()
            if jwt_secret in ("CHANGE_ME_IN_PRODUCTION", "asoc-dev-secret-change-in-production"):
                errors.append("JWT_SECRET must be changed in production")

            if self.llm_provider == LLMProvider.ANTHROPIC and not self.anthropic_api_key:
                errors.append("ANTHROPIC_API_KEY is required when LLM_PROVIDER=anthropic")

            if self.llm_provider == LLMProvider.OPENAI and not self.openai_api_key:
                errors.append("OPENAI_API_KEY is required when LLM_PROVIDER=openai")
            
            if self.llm_provider == LLMProvider.GEMINI and not self.google_api_key:
                errors.append("GOOGLE_API_KEY is required when LLM_PROVIDER=gemini")
            
            if errors:
                raise ValueError(
                    f"Production configuration errors:\n" + "\n".join(f"  - {e}" for e in errors)
                )
        return self

    @property
    def redis_url(self) -> str:
        pwd = f":{self.redis_password.get_secret_value()}@" if self.redis_password else "@"
        return f"redis://{pwd}{self.redis_host}:{self.redis_port}"

    @property
    def api_keys_set(self) -> set[str]:
        return set(k.strip() for k in self.api_keys.split(",") if k.strip())

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.asoc_env == Environment.PRODUCTION


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    s = Settings()
    logger.info(
        "ASOC config loaded: env=%s llm=%s embedding=%s dev_mode=%s",
        s.asoc_env, s.llm_provider, s.embedding_model, s.asoc_dev_mode,
    )
    return s


# Convenience singleton — import this everywhere
cfg = get_settings()
