"""Service start, stop and restart (ADR-0016). Admin only, direct (not staged), allow_writes
required. OPNsense answers ``ok`` as soon as the command is queued, so the result is read back
from the service list and never assumed."""

import asyncio
import re
import uuid
from typing import Any, Literal

import anyio.from_thread
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import audit
from app.api.firewalls import _log_error, open_client
from app.auth.deps import CurrentUser, get_db, require_roles
from app.auth.loginlimit import hit
from app.core.config import Settings, get_settings
from app.core.crypto import CredentialDecryptionError
from app.core.logging import get_logger
from app.db.models import Firewall, Role
from app.opnsense.client import OPNsenseClient
from app.opnsense.errors import FirewallError
from app.opnsense.normalise.services import ServiceInfo, normalise_services
from app.opnsense.registry.entries import (
    SERVICES_LIST,
    SERVICES_RESTART,
    SERVICES_START,
    SERVICES_STOP,
)

router = APIRouter(prefix="/api/v1/firewalls", tags=["firewalls"])
log = get_logger("api.service_control")

# Carry the management path itself (the web interface, API and configd behind it).
PROTECTED = frozenset({"configd", "webgui"})
# Stopping or restarting these needs the name typed.
HIGH_IMPACT = frozenset(
    {
        "unbound",
        "dnsmasq",
        "dhcpd",
        "dhcpd6",
        "dhcrelay",
        "kea-dhcp4",
        "kea-dhcp6",
        "radvd",
        "wireguard",
        "openvpn",
        "ipsec",
        "strongswan",
        "ntpd",
        "chronyd",
        "syslog-ng",
    }
)
OPERATIONS = {"start": SERVICES_START, "stop": SERVICES_STOP, "restart": SERVICES_RESTART}
RATE_LIMIT = "10/minute"
READBACK_SECONDS = 10
READBACK_INTERVAL = 1.0
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ServiceActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service: str = Field(max_length=64)
    instance: str | None = Field(default=None, max_length=64)
    confirm_name: str | None = Field(default=None, max_length=64)

    @field_validator("service")
    @classmethod
    def _service(cls, v: str) -> str:
        if not _NAME.match(v):
            raise ValueError("Invalid service name")
        return v

    @field_validator("instance")
    @classmethod
    def _instance(cls, v: str | None) -> str | None:
        if v and not _NAME.match(v):
            raise ValueError("Invalid instance")
        return v or None


class ServiceActionOut(BaseModel):
    firewall_id: uuid.UUID
    service: str
    instance: str | None
    action: str
    was_running: bool
    running: bool
    confirmed: bool
    message: str


class _Refused(Exception):
    def __init__(self, code: int, reason: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.reason = reason
        self.message = message


def _find(services: list[ServiceInfo], name: str, instance: str | None) -> ServiceInfo | None:
    for s in services:
        if s.name == name and (s.instance or None) == instance:
            return s
    return None


async def _list(client: OPNsenseClient) -> list[ServiceInfo]:
    return normalise_services(await client.execute(SERVICES_LIST)).services


async def _perform(
    client: OPNsenseClient, action: str, body: ServiceActionIn
) -> tuple[ServiceInfo, bool, bool]:
    """Returns (service as listed before, running after, confirmed)."""
    before = _find(await _list(client), body.service, body.instance)
    if before is None:
        raise _Refused(404, "unknown_service", "The firewall does not list that service")
    if before.locked:
        raise _Refused(403, "locked", "This service is locked and cannot be controlled here")
    if action != "start" and body.service in PROTECTED:
        raise _Refused(403, "protected", "This service carries the management path")
    if action != "start" and body.service in HIGH_IMPACT and body.confirm_name != body.service:
        raise _Refused(422, "confirmation_required", "Type the service name to confirm")
    await client.execute(
        OPERATIONS[action],
        path_params={"service": body.service, "instance": body.instance or ""},
    )
    want_running = action != "stop"
    running = before.running
    for attempt in range(max(1, int(READBACK_SECONDS / READBACK_INTERVAL) + 1)):
        if attempt:
            await asyncio.sleep(READBACK_INTERVAL)
        now = _find(await _list(client), body.service, body.instance)
        if now is not None:
            running = now.running
            if running is want_running:
                return before, running, True
    return before, running, False


def _audit(
    db: Session,
    request: Request,
    user: CurrentUser,
    fw_id: uuid.UUID,
    action: str,
    outcome: str,
    detail: dict[str, Any],
) -> None:
    audit.record(
        db,
        action=f"firewall.service.{action}",
        outcome=outcome,
        user_id=user.id,
        username=user.username,
        firewall_id=fw_id,
        detail=detail,
        request=request,
    )


@router.post("/{firewall_id}/services/{action}", response_model=ServiceActionOut)
def control_service(
    request: Request,
    firewall_id: uuid.UUID,
    action: Literal["start", "stop", "restart"],
    body: ServiceActionIn,
    user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ServiceActionOut:
    who = {"service": body.service, "instance": body.instance or ""}

    def refuse(code: int, reason: str, message: str, headers: dict[str, str] | None = None) -> Any:
        _audit(
            db, request, user, firewall_id, action, audit.OUTCOME_FAILURE, {**who, "reason": reason}
        )
        return HTTPException(code, message, headers=headers)

    wait = hit(db, f"service:{user.id}", RATE_LIMIT)
    if wait:
        raise refuse(429, "rate_limited", "Too many service actions", {"Retry-After": str(wait)})
    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise refuse(404, "firewall_not_found", "Firewall not found")
    if not fw.allow_writes:
        raise refuse(403, "writes_disabled", "Changes are not enabled for this firewall")

    # One action at a time per firewall. Held on its own connection for the whole action,
    # because the request's session releases its connection at every commit.
    engine = request.app.state.engine
    with engine.connect() as lock_conn:
        key = f"service-control:{fw.id}"
        got = lock_conn.execute(
            text("SELECT pg_try_advisory_lock(hashtext(:k))"), {"k": key}
        ).scalar_one()
        if not got:
            raise refuse(409, "busy", "Another service action is running on this firewall")
        try:
            return _run(request, db, settings, user, fw, action, body)
        finally:
            lock_conn.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": key})
            lock_conn.commit()


def _run(
    request: Request,
    db: Session,
    settings: Settings,
    user: CurrentUser,
    fw: Firewall,
    action: str,
    body: ServiceActionIn,
) -> ServiceActionOut:
    who = {"service": body.service, "instance": body.instance or ""}
    fw_id = fw.id
    try:
        client = open_client(fw, settings)
    except CredentialDecryptionError:
        log.error("credential_decrypt_failed", firewall_id=str(fw_id))
        _audit(
            db,
            request,
            user,
            fw_id,
            action,
            audit.OUTCOME_FAILURE,
            {**who, "reason": "credentials"},
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    try:
        before, running, confirmed = anyio.from_thread.run(lambda: _perform(client, action, body))
    except _Refused as exc:
        _audit(
            db, request, user, fw_id, action, audit.OUTCOME_FAILURE, {**who, "reason": exc.reason}
        )
        raise HTTPException(exc.code, exc.message) from None
    except FirewallError as exc:
        _audit(
            db,
            request,
            user,
            fw_id,
            action,
            audit.OUTCOME_FAILURE,
            {**who, "reason": "firewall_error", "status": exc.status.value},
        )
        raise _log_error(exc, user) from None
    except Exception:
        log.exception("service_control_crashed", firewall_id=str(fw_id))
        db.rollback()
        _audit(db, request, user, fw_id, action, audit.OUTCOME_FAILURE, {**who, "reason": "error"})
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    finally:
        anyio.from_thread.run(client.aclose)
    _audit(
        db,
        request,
        user,
        fw_id,
        action,
        audit.OUTCOME_SUCCESS,
        {**who, "was_running": before.running, "running": running, "confirmed": confirmed},
    )
    if confirmed:
        message = "Running, confirmed" if running else "Stopped, confirmed"
    else:
        state = "running" if running else "stopped"
        message = f"Not confirmed: still {state} after {READBACK_SECONDS} s. Check again shortly."
    return ServiceActionOut(
        firewall_id=fw_id,
        service=body.service,
        instance=body.instance,
        action=action,
        was_running=before.running,
        running=running,
        confirmed=confirmed,
        message=message,
    )
