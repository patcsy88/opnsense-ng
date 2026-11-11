"""staged change requests, their history, and the per-firewall allow_writes flag

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firewalls",
        sa.Column("allow_writes", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "change_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "firewall_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("firewalls.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("action", sa.String(20), nullable=False),
        sa.Column("target_uuid", sa.String(64), nullable=True),
        sa.Column("proposed", postgresql.JSONB, nullable=True),
        sa.Column("base_snapshot", postgresql.JSONB, nullable=True),
        sa.Column("base_fingerprint", sa.String(64), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("high_risk", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("self_approved", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column(
            "requester_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("requester_username", sa.String(64), nullable=False),
        sa.Column("reviewer_username", sa.String(64), nullable=True),
        sa.Column("applier_username", sa.String(64), nullable=True),
        sa.Column("result_snapshot", postgresql.JSONB, nullable=True),
        sa.Column("failure_message", sa.Text, nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_change_requests_firewall_status", "change_requests", ["firewall_id", "status"]
    )
    op.create_index("ix_change_requests_created_at", "change_requests", ["created_at"])
    op.create_table(
        "change_request_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "change_request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("change_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("actor_username", sa.String(64), nullable=False),
        sa.Column("from_status", sa.String(20), nullable=True),
        sa.Column("to_status", sa.String(20), nullable=False),
        sa.Column("note", sa.String(500), nullable=True),
    )
    op.create_index(
        "ix_change_events_request_ts", "change_request_events", ["change_request_id", "timestamp"]
    )


def downgrade() -> None:
    op.drop_table("change_request_events")
    op.drop_table("change_requests")
    op.drop_column("firewalls", "allow_writes")
