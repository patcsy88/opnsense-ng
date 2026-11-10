"""security hardening: audit source/user agent, login throttle, idle timeout, firewall CA bundle

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("source_ip", sa.String(64), nullable=True))
    op.add_column("audit_log", sa.Column("user_agent", sa.String(256), nullable=True))
    op.create_index("ix_audit_log_ip_action_ts", "audit_log", ["source_ip", "action", "timestamp"])
    op.add_column(
        "sessions",
        sa.Column(
            "last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.add_column("firewalls", sa.Column("ca_bundle_pem", sa.Text, nullable=True))
    op.create_table(
        "login_throttle",
        sa.Column("username", sa.String(64), primary_key=True),
        sa.Column("failures", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "last_failure_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
    )
    # Usernames are now case-normalised. Fails (unique violation) if two accounts differ only
    # by case; resolve those by hand before upgrading.
    op.execute("UPDATE users SET username = lower(username)")


def downgrade() -> None:
    op.drop_table("login_throttle")
    op.drop_column("firewalls", "ca_bundle_pem")
    op.drop_column("sessions", "last_seen_at")
    op.drop_index("ix_audit_log_ip_action_ts", table_name="audit_log")
    op.drop_column("audit_log", "user_agent")
    op.drop_column("audit_log", "source_ip")
