"""Audit log writer. Independent of OPNsense logs; never receives secrets."""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AuditLog

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_DENIED = "denied"


def record(
    db: Session,
    *,
    action: str,
    outcome: str,
    user_id: uuid.UUID | None = None,
    username: str | None = None,
    firewall_id: uuid.UUID | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    """Persist an audit record and commit immediately so failures are still recorded."""
    db.add(
        AuditLog(
            user_id=user_id,
            username=username,
            action=action,
            firewall_id=firewall_id,
            outcome=outcome,
            detail=detail,
        )
    )
    db.commit()
