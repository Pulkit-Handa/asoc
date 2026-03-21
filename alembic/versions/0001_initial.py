"""Initial schema: incidents, lessons, analyst_feedback

Revision ID: 0001_initial
Revises: 
Create Date: 2026-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id",               sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("alert_id",         sa.String(64),  nullable=False, unique=True),
        sa.Column("threat_category",  sa.String(128), nullable=False, default="UNKNOWN"),
        sa.Column("severity_score",   sa.Float,       default=0.0),
        sa.Column("confidence_score", sa.Float,       default=0.0),
        sa.Column("blast_radius",     sa.Integer,     default=0),
        sa.Column("exposure_score",   sa.Float,       default=0.0),
        sa.Column("decision",         sa.String(32),  nullable=False),
        sa.Column("mitre_techniques", sa.Text,        default=""),
        sa.Column("status",           sa.String(32),  default="OPEN"),
        sa.Column("confirmed_outcome",sa.String(32),  nullable=True),
        sa.Column("escalation_reason",sa.Text,        nullable=True),
        sa.Column("lesson_id",        sa.String(128), nullable=True),
        sa.Column("created_at",       sa.DateTime,    default=sa.func.now()),
        sa.Column("resolved_at",      sa.DateTime,    nullable=True),
    )
    op.create_index("ix_incidents_alert_id",  "incidents", ["alert_id"])
    op.create_index("ix_incidents_status",    "incidents", ["status"])
    op.create_index("ix_incidents_created",   "incidents", ["created_at"])
    op.create_index("ix_incidents_category",  "incidents", ["threat_category"])

    op.create_table(
        "lessons",
        sa.Column("id",          sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("lesson_id",   sa.String(128), nullable=False, unique=True),
        sa.Column("alert_id",    sa.String(64),  nullable=False),
        sa.Column("category",    sa.String(128), nullable=False),
        sa.Column("lesson_text", sa.Text,        nullable=False),
        sa.Column("source",      sa.String(32),  default="critic"),
        sa.Column("created_at",  sa.DateTime,    default=sa.func.now()),
        sa.Column("created_by",  sa.String(128), nullable=True),
    )
    op.create_index("ix_lessons_category", "lessons", ["category"])
    op.create_index("ix_lessons_created",  "lessons", ["created_at"])

    op.create_table(
        "analyst_feedback",
        sa.Column("id",               sa.Integer,    primary_key=True, autoincrement=True),
        sa.Column("alert_id",         sa.String(64), nullable=False),
        sa.Column("analyst_id",       sa.String(128),nullable=False),
        sa.Column("confirmed_outcome",sa.String(32), nullable=False),
        sa.Column("override_decision",sa.String(32), nullable=True),
        sa.Column("annotation",       sa.Text,       nullable=True),
        sa.Column("created_at",       sa.DateTime,   default=sa.func.now()),
    )
    op.create_index("ix_feedback_alert_id", "analyst_feedback", ["alert_id"])


def downgrade() -> None:
    op.drop_table("analyst_feedback")
    op.drop_table("lessons")
    op.drop_table("incidents")
