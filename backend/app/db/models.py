"""SQLAlchemy 2 models (PostgreSQL types)."""

import enum
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

BASE_URL_MAX_LENGTH = 500
USER_AGENT_MAX_LENGTH = 256


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(enum.StrEnum):
    admin = "admin"
    network_admin = "network_admin"
    security_admin = "security_admin"
    read_only = "read_only"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(SAEnum(Role, name="user_role"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    # TOTP (ADR-0012). The secret is Fernet-encrypted and bound to this user's id; it exists
    # before mfa_enabled while enrolment is pending.
    # Set for a temporary password (ADR-0013): the session may only change the password.
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Last accepted time step; a code for the same or an earlier step is refused.
    mfa_last_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class MfaChallenge(Base):
    """Proof that the password step passed. Single use, short lived, hashed at rest."""

    __tablename__ = "mfa_challenges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (Index("ix_mfa_challenges_user_id", "user_id"),)


class MfaRecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (Index("ix_mfa_recovery_codes_user_id", "user_id"),)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # SHA-256 hex of the session token; the raw token only ever lives in the cookie.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    csrf_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Updated (at most once a minute) on use; drives the idle timeout.
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    user: Mapped[User] = relationship()

    __table_args__ = (Index("ix_sessions_expires_at", "expires_at"),)


class LoginThrottle(Base):
    """Consecutive failed logins per (normalised) username, including unknown usernames, so
    the response never reveals whether an account exists. Survives restarts."""

    __tablename__ = "login_throttle"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_failure_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Firewall(Base):
    __tablename__ = "firewalls"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(BASE_URL_MAX_LENGTH), nullable=False)
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    api_secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Optional PEM bundle (public certificates only) trusted instead of the system store.
    ca_bundle_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Writes (applying staged changes) are refused unless this is switched on explicitly.
    allow_writes: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class ChangeRequest(Base):
    """A proposed firewall change. Lives only in our database until an admin applies it."""

    __tablename__ = "change_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    firewall_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("firewalls.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    target_uuid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    proposed: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    base_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    base_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="draft")
    high_risk: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    self_approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    requester_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requester_username: Mapped[str] = mapped_column(String(64), nullable=False)
    reviewer_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    applier_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    result_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    failure_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    __table_args__ = (
        Index("ix_change_requests_firewall_status", "firewall_id", "status"),
        Index("ix_change_requests_created_at", "created_at"),
    )


class ChangeRequestEvent(Base):
    """Append-only history of a change request."""

    __tablename__ = "change_request_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    change_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("change_requests.id", ondelete="CASCADE"), nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    actor_username: Mapped[str] = mapped_column(String(64), nullable=False)
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)
    note: Mapped[str | None] = mapped_column(String(500), nullable=True)

    __table_args__ = (Index("ix_change_events_request_ts", "change_request_id", "timestamp"),)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Not a foreign key on purpose: audit records must outlive users and firewalls.
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    firewall_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(USER_AGENT_MAX_LENGTH), nullable=True)

    __table_args__ = (
        Index("ix_audit_log_timestamp", "timestamp"),
        Index("ix_audit_log_firewall_id", "firewall_id"),
        Index("ix_audit_log_ip_action_ts", "source_ip", "action", "timestamp"),
    )


class RateLimitCounter(Base):
    """Fixed-window request counters for the login limits (ADR-0014). Holds source IPs for at
    most about an hour; rows are removed by an opportunistic cleanup and the CLI."""

    __tablename__ = "rate_limit_counters"
    __table_args__ = (Index("ix_rate_limit_counters_window_start", "window_start"),)

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
