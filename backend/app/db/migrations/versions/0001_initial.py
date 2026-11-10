"""initial schema: users, sessions, firewalls, audit_log

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

user_role = postgresql.ENUM(
    "admin", "network_admin", "security_admin", "read_only", name="user_role", create_type=False
)


def upgrade() -> None:
    user_role.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_table(
        "sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("csrf_token_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    op.create_table(
        "firewalls",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("base_url", sa.String(500), nullable=False),
        sa.Column("api_key_encrypted", sa.Text, nullable=False),
        sa.Column("api_secret_encrypted", sa.Text, nullable=False),
        sa.Column("verify_tls", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("username", sa.String(64), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("firewall_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("detail", postgresql.JSONB, nullable=True),
    )
    op.create_index("ix_audit_log_timestamp", "audit_log", ["timestamp"])
    op.create_index("ix_audit_log_firewall_id", "audit_log", ["firewall_id"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("firewalls")
    op.drop_table("sessions")
    op.drop_table("users")
    user_role.drop(op.get_bind(), checkfirst=True)
