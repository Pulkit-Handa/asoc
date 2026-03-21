"""
PostgreSQL ORM Models
======================
All database tables defined here. Alembic reads this file to generate migrations.

Table overview:
  incidents        — one row per processed alert, final decision + outcome
  lessons          — mirror of ChromaDB lessons (ChromaDB is the search index;
                     PostgreSQL is the authoritative record for audit/backup)
  lesson_reviews   — pending lessons awaiting analyst approval before ChromaDB storage
  analyst_feedback — analyst-submitted confirmed outcomes that trigger Critic Agent
  audit_logs       — append-only SOC2/ISO27001 compliance trail
  refresh_tokens   — JWT refresh token store for secure multi-device auth
"""
from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Enum as SAEnum, Float, Index, Integer,
    String, Text, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class IncidentStatus(str, enum.Enum):
    OPEN       = "OPEN"
    ESCALATED  = "ESCALATED"
    RESOLVED   = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class Decision(str, enum.Enum):
    ESCALATE   = "ESCALATE"
    MONITOR    = "MONITOR"
    AUTO_CLOSE = "AUTO_CLOSE"


class ConfirmedOutcome(str, enum.Enum):
    TRUE_POSITIVE  = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"


class LessonReviewStatus(str, enum.Enum):
    PENDING  = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class UserRole(str, enum.Enum):
    ANALYST     = "ANALYST"
    SOC_MANAGER = "SOC_MANAGER"
    ADMIN       = "ADMIN"
    READONLY    = "READONLY"


# ── Tables ────────────────────────────────────────────────────────────────────

class Incident(Base):
    """One row per processed alert. The authoritative decision record."""
    __tablename__ = "incidents"

    id:               Mapped[int]            = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id:         Mapped[str]            = mapped_column(String(64),  nullable=False, unique=True, index=True)
    threat_category:  Mapped[str]            = mapped_column(String(128), nullable=False, default="UNKNOWN")
    severity_score:   Mapped[float]          = mapped_column(Float,   default=0.0)
    confidence_score: Mapped[float]          = mapped_column(Float,   default=0.0)
    blast_radius:     Mapped[int]            = mapped_column(Integer, default=0)
    exposure_score:   Mapped[float]          = mapped_column(Float,   default=0.0)
    decision:         Mapped[str]            = mapped_column(String(32), nullable=False)
    mitre_techniques: Mapped[str]            = mapped_column(Text, default="")
    status:           Mapped[str]            = mapped_column(
        SAEnum(IncidentStatus), default=IncidentStatus.OPEN, index=True
    )
    confirmed_outcome:  Mapped[str | None]   = mapped_column(SAEnum(ConfirmedOutcome), nullable=True)
    escalation_reason:  Mapped[str | None]   = mapped_column(Text, nullable=True)
    lesson_id:          Mapped[str | None]   = mapped_column(String(128), nullable=True)
    processing_time_ms: Mapped[int | None]   = mapped_column(Integer, nullable=True)
    src_ip:             Mapped[str | None]   = mapped_column(String(45), nullable=True)
    host_id:            Mapped[str | None]   = mapped_column(String(255), nullable=True)
    created_at:         Mapped[datetime]     = mapped_column(DateTime, server_default=func.now(), index=True)
    resolved_at:        Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_incidents_category_date", "threat_category", "created_at"),
        Index("ix_incidents_decision_date", "decision", "created_at"),
    )


class Lesson(Base):
    """Authoritative record of all lessons (mirrors ChromaDB for backup/audit)."""
    __tablename__ = "lessons"

    id:          Mapped[int]  = mapped_column(Integer, primary_key=True, autoincrement=True)
    lesson_id:   Mapped[str]  = mapped_column(String(128), nullable=False, unique=True)
    alert_id:    Mapped[str]  = mapped_column(String(64),  nullable=False, index=True)
    category:    Mapped[str]  = mapped_column(String(128), nullable=False, index=True)
    lesson_text: Mapped[str]  = mapped_column(Text, nullable=False)
    source:      Mapped[str]  = mapped_column(String(32), default="critic")
    created_at:  Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)
    created_by:  Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_active:   Mapped[bool] = mapped_column(Boolean, default=True)


class LessonReview(Base):
    """
    Quality gate: Critic Agent writes here first.
    Only moves to ChromaDB (and Lesson table) after analyst APPROVED.
    When lesson_review_required=False in config, auto-approves immediately.
    """
    __tablename__ = "lesson_reviews"

    id:           Mapped[int]  = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id:     Mapped[str]  = mapped_column(String(64),  nullable=False, index=True)
    category:     Mapped[str]  = mapped_column(String(128), nullable=False)
    lesson_text:  Mapped[str]  = mapped_column(Text, nullable=False)
    source:       Mapped[str]  = mapped_column(String(32), default="critic")
    status:       Mapped[str]  = mapped_column(
        SAEnum(LessonReviewStatus), default=LessonReviewStatus.PENDING, index=True
    )
    reviewer_id:  Mapped[str | None] = mapped_column(String(128), nullable=True)
    review_note:  Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at:   Mapped[datetime]   = mapped_column(DateTime, server_default=func.now())
    reviewed_at:  Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AnalystFeedback(Base):
    """Analyst-submitted confirmed outcomes. Triggers Critic Agent lesson generation."""
    __tablename__ = "analyst_feedback"

    id:                Mapped[int]  = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id:          Mapped[str]  = mapped_column(String(64),  nullable=False, index=True)
    analyst_id:        Mapped[str]  = mapped_column(String(128), nullable=False)
    confirmed_outcome: Mapped[str]  = mapped_column(SAEnum(ConfirmedOutcome), nullable=False)
    override_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    annotation:        Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at:        Mapped[datetime]   = mapped_column(DateTime, server_default=func.now())


class AuditLog(Base):
    """
    Append-only SOC2/ISO27001 compliance trail.
    This table should have UPDATE and DELETE revoked at the DB level.
    """
    __tablename__ = "audit_logs"

    id:             Mapped[int]  = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id:        Mapped[str]  = mapped_column(String(128), nullable=False, index=True)
    action:         Mapped[str]  = mapped_column(String(256), nullable=False)
    resource:       Mapped[str]  = mapped_column(String(256), nullable=False)
    client_ip:      Mapped[str]  = mapped_column(String(45),  nullable=False)
    status_code:    Mapped[int]  = mapped_column(Integer, nullable=False)
    response_ms:    Mapped[int]  = mapped_column(Integer, default=0)
    correlation_id: Mapped[str]  = mapped_column(String(64), nullable=False, index=True)
    created_at:     Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), index=True)

    __table_args__ = (
        Index("ix_audit_user_date",   "user_id",   "created_at"),
        Index("ix_audit_action_date", "action",    "created_at"),
    )


class RefreshToken(Base):
    """
    JWT refresh token store. Enables token revocation and multi-device support.
    Expired and revoked tokens are purged by a nightly cron job.
    """
    __tablename__ = "refresh_tokens"

    id:         Mapped[int]  = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str]  = mapped_column(String(128), nullable=False, unique=True, index=True)
    user_id:    Mapped[str]  = mapped_column(String(128), nullable=False, index=True)
    user_role:  Mapped[str]  = mapped_column(SAEnum(UserRole), default=UserRole.ANALYST)
    device_id:  Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime]          = mapped_column(DateTime, server_default=func.now())
    expires_at: Mapped[datetime]          = mapped_column(DateTime, nullable=False, index=True)
    revoked_at: Mapped[datetime | None]   = mapped_column(DateTime, nullable=True)
