"""rate_limit_counters for the login limits (ADR-0014)

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_counters",
        sa.Column("key", sa.String(128), primary_key=True),
        sa.Column("window_start", sa.DateTime(timezone=True), primary_key=True),
        sa.Column("count", sa.Integer, nullable=False),
    )
    op.create_index("ix_rate_limit_counters_window_start", "rate_limit_counters", ["window_start"])


def downgrade() -> None:
    op.drop_index("ix_rate_limit_counters_window_start", table_name="rate_limit_counters")
    op.drop_table("rate_limit_counters")
