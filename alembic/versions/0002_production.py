"""Production schema: audit_logs, lesson_reviews, refresh_tokens, incidents v2

Revision ID: 0002_production
Revises: 0001_initial
Create Date: 2026-03-15 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision      = "0002_production"
down_revision = "0001_initial"
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # ── lesson_reviews ────────────────────────────────────────────────────────
    op.create_table(
        "lesson_reviews",
        sa.Column("id",          sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("alert_id",    sa.String(64),  nullable=False),
        sa.Column("category",    sa.String(128), nullable=False),
        sa.Column("lesson_text", sa.Text,        nullable=False),
        sa.Column("source",      sa.String(32),  default="critic"),
        sa.Column("status",      sa.String(32),  default="PENDING"),
        sa.Column("reviewer_id", sa.String(128), nullable=True),
        sa.Column("review_note", sa.Text,        nullable=True),
        sa.Column("created_at",  sa.DateTime,    server_default=sa.func.now()),
        sa.Column("reviewed_at", sa.DateTime,    nullable=True),
    )
    op.create_index("ix_lesson_reviews_status",   "lesson_reviews", ["status"])
    op.create_index("ix_lesson_reviews_alert_id", "lesson_reviews", ["alert_id"])

    # ── audit_logs ────────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id",             sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("user_id",        sa.String(128), nullable=False),
        sa.Column("action",         sa.String(256), nullable=False),
        sa.Column("resource",       sa.String(256), nullable=False),
        sa.Column("client_ip",      sa.String(45),  nullable=False),
        sa.Column("status_code",    sa.Integer,     nullable=False),
        sa.Column("response_ms",    sa.Integer,     default=0),
        sa.Column("correlation_id", sa.String(64),  nullable=False),
        sa.Column("created_at",     sa.DateTime,    server_default=sa.func.now()),
    )
    op.create_index("ix_audit_user_date",   "audit_logs", ["user_id",  "created_at"])
    op.create_index("ix_audit_action_date", "audit_logs", ["action",   "created_at"])
    op.create_index("ix_audit_corr",        "audit_logs", ["correlation_id"])

    # Make audit_logs append-only at the DB level
    # (requires superuser — comment out if your DB user is restricted)
    # op.execute("REVOKE UPDATE, DELETE ON audit_logs FROM asoc_app_user;")

    # ── refresh_tokens ────────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id",         sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column("token_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("user_id",    sa.String(128), nullable=False),
        sa.Column("user_role",  sa.String(32),  default="ANALYST"),
        sa.Column("device_id",  sa.String(128), nullable=True),
        sa.Column("is_revoked", sa.Boolean,     default=False),
        sa.Column("created_at", sa.DateTime,    server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime,    nullable=False),
        sa.Column("revoked_at", sa.DateTime,    nullable=True),
    )
    op.create_index("ix_refresh_token_hash",    "refresh_tokens", ["token_hash"])
    op.create_index("ix_refresh_token_user",    "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_token_expires", "refresh_tokens", ["expires_at"])

    # ── incidents v2 additions ────────────────────────────────────────────────
    op.add_column("incidents", sa.Column("src_ip",  sa.String(45),  nullable=True))
    op.add_column("incidents", sa.Column("host_id", sa.String(255), nullable=True))
    op.add_column("incidents", sa.Column(
        "processing_time_ms", sa.Integer, nullable=True
    ))

    # Composite indexes for dashboard queries
    op.create_index("ix_incidents_category_date", "incidents", ["threat_category", "created_at"])
    op.create_index("ix_incidents_decision_date", "incidents", ["decision",        "created_at"])


def downgrade() -> None:
    op.drop_index("ix_incidents_decision_date",   table_name="incidents")
    op.drop_index("ix_incidents_category_date",   table_name="incidents")
    op.drop_column("incidents", "processing_time_ms")
    op.drop_column("incidents", "host_id")
    op.drop_column("incidents", "src_ip")
    op.drop_table("refresh_tokens")
    op.drop_table("audit_logs")
    op.drop_table("lesson_reviews")
