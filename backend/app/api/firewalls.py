import uuid
from typing import Any

import anyio.from_thread
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.api.schemas import ConnectivityOut, FirewallCreate, FirewallOut, SystemStatusOut
from app.auth.deps import ALL_ROLES, CurrentUser, get_db, require_roles
from app.core.config import Settings, get_settings
from app.core.crypto import CredentialCipher, CredentialDecryptionError
from app.core.logging import get_logger, register_secret
from app.db.models import Firewall, Role
from app.opnsense.client import OPNsenseClient
from app.opnsense.errors import ConnectionStatus, FirewallError
from app.opnsense.normalise import normalise_system_status
from app.opnsense.registry.entries import CONNECTIVITY_CHECK, SYSTEM_STATUS

router = APIRouter(prefix="/api/v1/firewalls", tags=["firewalls"])
log = get_logger("api.firewalls")

_HTTP_FOR_STATUS = {
    ConnectionStatus.timeout: status.HTTP_504_GATEWAY_TIMEOUT,
    ConnectionStatus.auth_failed: status.HTTP_502_BAD_GATEWAY,
}


def _out(fw: Firewall) -> FirewallOut:
    return FirewallOut(
        id=fw.id,
        name=fw.name,
        base_url=fw.base_url,
        verify_tls=fw.verify_tls,
        created_at=fw.created_at,
    )


@router.post("", response_model=FirewallOut, status_code=status.HTTP_201_CREATED)
def create_firewall(
    body: FirewallCreate,
    user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> FirewallOut:
    cipher = CredentialCipher(settings.credential_encryption_key.get_secret_value())
    key, secret = body.api_key.get_secret_value(), body.api_secret.get_secret_value()
    register_secret(key)
    register_secret(secret)
    fw = Firewall(
        name=body.name,
        base_url=str(body.base_url).rstrip("/"),
        api_key_encrypted=cipher.encrypt(key),
        api_secret_encrypted=cipher.encrypt(secret),
        verify_tls=body.verify_tls,
    )
    db.add(fw)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        audit.record(
            db,
            action="firewall.create",
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            detail={"reason": "duplicate_name"},
        )
        raise HTTPException(status.HTTP_409_CONFLICT, "A firewall with this name exists") from None
    audit.record(
        db,
        action="firewall.create",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        firewall_id=fw.id,
        detail={"name": fw.name},
    )
    return _out(fw)


@router.get("", response_model=list[FirewallOut])
def list_firewalls(
    _user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
) -> list[FirewallOut]:
    rows = db.execute(select(Firewall).order_by(Firewall.name)).scalars().all()
    return [_out(fw) for fw in rows]


def _run_operation(
    *,
    firewall_id: uuid.UUID,
    operation_id: str,
    user: CurrentUser,
    db: Session,
    settings: Settings,
) -> Any:
    """Load the firewall, execute a registry operation, audit the outcome.
    Raises FirewallError (already audited) on connection/API failure."""
    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall not found")
    action = f"firewall.{operation_id}"
    try:
        cipher = CredentialCipher(settings.credential_encryption_key.get_secret_value())
        api_key = cipher.decrypt(fw.api_key_encrypted)
        api_secret = cipher.decrypt(fw.api_secret_encrypted)
    except CredentialDecryptionError:
        log.error("credential_decrypt_failed", firewall_id=str(fw.id))
        audit.record(
            db,
            action=action,
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            firewall_id=fw.id,
            detail={"reason": "credential_decrypt_failed"},
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    register_secret(api_key)
    register_secret(api_secret)

    client = OPNsenseClient(
        base_url=fw.base_url,
        api_key=api_key,
        api_secret=api_secret,
        verify_tls=fw.verify_tls,
        connect_timeout_s=settings.opnsense_connect_timeout_s,
        read_timeout_s=settings.opnsense_read_timeout_s,
        max_retries=settings.opnsense_max_retries,
        backoff_base_s=settings.opnsense_backoff_base_s,
    )
    try:
        result = anyio.from_thread.run(client.execute, operation_id)
    except FirewallError as exc:
        audit.record(
            db,
            action=action,
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            firewall_id=fw.id,
            detail={"status": exc.status.value},
        )
        raise
    finally:
        anyio.from_thread.run(client.aclose)
    audit.record(
        db,
        action=action,
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        firewall_id=fw.id,
    )
    return result


@router.get("/{firewall_id}/connectivity", response_model=ConnectivityOut)
def connectivity(
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ConnectivityOut:
    try:
        _run_operation(
            firewall_id=firewall_id,
            operation_id=CONNECTIVITY_CHECK,
            user=user,
            db=db,
            settings=settings,
        )
    except FirewallError as exc:
        return ConnectivityOut(
            firewall_id=firewall_id, ok=False, status=exc.status, message=exc.message
        )
    return ConnectivityOut(
        firewall_id=firewall_id, ok=True, status=ConnectionStatus.ok, message="Connected"
    )


@router.get("/{firewall_id}/system/status", response_model=SystemStatusOut)
def system_status(
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> SystemStatusOut:
    try:
        raw = _run_operation(
            firewall_id=firewall_id,
            operation_id=SYSTEM_STATUS,
            user=user,
            db=db,
            settings=settings,
        )
    except FirewallError as exc:
        raise HTTPException(
            _HTTP_FOR_STATUS.get(exc.status, status.HTTP_502_BAD_GATEWAY),
            {"status": exc.status.value, "message": exc.message},
        ) from None
    return SystemStatusOut(firewall_id=firewall_id, status=normalise_system_status(raw))
