import ipaddress
import uuid
from typing import Any

import anyio.from_thread
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.api.schemas import (
    AliasesOut,
    ConnectivityOut,
    FirewallCreate,
    FirewallOption,
    FirewallOut,
    FirewallUpdate,
    InterfacesOut,
    RulesOut,
    SystemStatusOut,
)
from app.auth.deps import ALL_ROLES, CurrentUser, get_db, require_roles
from app.core.config import Settings, get_settings
from app.core.crypto import CredentialCipher, CredentialDecryptionError
from app.core.logging import get_logger, register_secret
from app.db.models import Firewall, Role
from app.opnsense import cpu_sampler
from app.opnsense.client import OPNsenseClient
from app.opnsense.cpu_sampler import sample_cpu
from app.opnsense.errors import ConnectionStatus, FirewallError, public_status
from app.opnsense.netpolicy import TargetPolicy, split_host
from app.opnsense.normalise import (
    normalise_aliases,
    normalise_cpu_events,
    normalise_interfaces,
    normalise_rules,
    normalise_system_status,
)
from app.opnsense.registry import ResponseKind, get_operation
from app.opnsense.registry.entries import (
    CONNECTIVITY_CHECK,
    CPU_USAGE,
    FIREWALL_ALIASES_LIST,
    FIREWALL_RULES_LIST,
    INTERFACES_OVERVIEW,
    SYSTEM_DISK,
    SYSTEM_RESOURCES,
    SYSTEM_STATUS,
    SYSTEM_TIME,
)

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
        has_ca_bundle=bool(fw.ca_bundle_pem),
        allow_writes=fw.allow_writes,
        created_at=fw.created_at,
    )


def build_policy(settings: Settings) -> TargetPolicy:
    return TargetPolicy(
        allowed_networks=[ipaddress.ip_network(n) for n in settings.allowed_firewall_networks],
        denied_networks=[ipaddress.ip_network(n) for n in settings.denied_firewall_networks],
        own_hostnames=TargetPolicy.own_names(settings.allowed_hosts),
    )


def _check_target(
    *,
    base_url: str,
    verify_tls: bool,
    settings: Settings,
    db: Session,
    user: CurrentUser,
    request: Request,
    action: str,
    firewall_id: uuid.UUID | None = None,
) -> None:
    """Reject disallowed hosts and insecure TLS with a 422 (audited)."""
    reason: str | None = None
    if not verify_tls and not settings.allow_insecure_tls:
        reason = "Disabling TLS verification is not enabled on this server"
        code = "insecure_tls_disabled"
    elif not build_policy(settings).host_allowed(split_host(base_url)[0]):
        reason = "This firewall address is not permitted by the server policy"
        code = "target_not_allowed"
    if reason is None:
        return
    audit.record(
        db,
        action=action,
        outcome=audit.OUTCOME_DENIED,
        user_id=user.id,
        username=user.username,
        firewall_id=firewall_id,
        detail={"reason": code, "base_url": base_url, "verify_tls": verify_tls},
        request=request,
    )
    raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, reason)


@router.post("", response_model=FirewallOut, status_code=status.HTTP_201_CREATED)
def create_firewall(
    request: Request,
    body: FirewallCreate,
    user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> FirewallOut:
    _check_target(
        base_url=body.base_url,
        verify_tls=body.verify_tls,
        settings=settings,
        db=db,
        user=user,
        request=request,
        action="firewall.create",
    )
    cipher = CredentialCipher(settings.credential_encryption_key.get_secret_value())
    key, secret = body.api_key.get_secret_value(), body.api_secret.get_secret_value()
    register_secret(key)
    register_secret(secret)
    fw_id = uuid.uuid4()
    fw = Firewall(
        id=fw_id,
        name=body.name,
        base_url=body.base_url,
        api_key_encrypted=cipher.encrypt(key, f"{fw_id}:api_key"),
        api_secret_encrypted=cipher.encrypt(secret, f"{fw_id}:api_secret"),
        verify_tls=body.verify_tls,
        ca_bundle_pem=body.ca_bundle_pem,
    )
    db.add(fw)
    # The audit row commits atomically with the firewall row.
    audit.add(
        db,
        action="firewall.create",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        firewall_id=fw_id,
        detail={
            "name": fw.name,
            "base_url": fw.base_url,
            "verify_tls": fw.verify_tls,
            "has_ca_bundle": bool(fw.ca_bundle_pem),
        },
        request=request,
    )
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
            request=request,
        )
        raise HTTPException(status.HTTP_409_CONFLICT, "A firewall with this name exists") from None
    return _out(fw)


@router.patch("/{firewall_id}", response_model=FirewallOut)
def update_firewall(
    request: Request,
    firewall_id: uuid.UUID,
    body: FirewallUpdate,
    user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> FirewallOut:
    fw = _get_firewall(db, firewall_id, "firewall.update", user, request)
    changes = body.model_dump(exclude_unset=True)
    new_url = body.base_url or fw.base_url
    new_verify = fw.verify_tls if body.verify_tls is None else body.verify_tls
    _check_target(
        base_url=new_url,
        verify_tls=new_verify,
        settings=settings,
        db=db,
        user=user,
        request=request,
        action="firewall.update",
        firewall_id=fw.id,
    )
    cipher = CredentialCipher(settings.credential_encryption_key.get_secret_value())
    detail: dict[str, Any] = {"fields": sorted(changes)}
    if body.name is not None:
        fw.name = body.name
    if body.base_url is not None:
        detail["base_url"] = {"old": fw.base_url, "new": body.base_url}
        fw.base_url = body.base_url
    if body.verify_tls is not None:
        detail["verify_tls"] = {"old": fw.verify_tls, "new": body.verify_tls}
        fw.verify_tls = body.verify_tls
    if body.allow_writes is not None:
        detail["allow_writes"] = {"old": fw.allow_writes, "new": body.allow_writes}
        fw.allow_writes = body.allow_writes
    if "ca_bundle_pem" in changes:
        fw.ca_bundle_pem = body.ca_bundle_pem or None
        detail["has_ca_bundle"] = bool(fw.ca_bundle_pem)
    # Credentials are always re-sealed bound to this firewall id (never logged).
    for attr, new, label in (
        ("api_key_encrypted", body.api_key, "api_key"),
        ("api_secret_encrypted", body.api_secret, "api_secret"),
    ):
        if new is not None:
            register_secret(new.get_secret_value())
            setattr(fw, attr, cipher.encrypt(new.get_secret_value(), f"{fw.id}:{label}"))
    audit.add(
        db,
        action="firewall.update",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        firewall_id=fw.id,
        detail=detail,
        request=request,
    )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        audit.record(
            db,
            action="firewall.update",
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            firewall_id=firewall_id,
            detail={"reason": "duplicate_name"},
            request=request,
        )
        raise HTTPException(status.HTTP_409_CONFLICT, "A firewall with this name exists") from None
    return _out(fw)


@router.delete("/{firewall_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_firewall(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
) -> None:
    fw = _get_firewall(db, firewall_id, "firewall.delete", user, request)
    # Name and URL are kept in the audit record, which outlives the firewall; no credentials.
    audit.add(
        db,
        action="firewall.delete",
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        firewall_id=fw.id,
        detail={"name": fw.name, "base_url": fw.base_url},
        request=request,
    )
    db.delete(fw)
    db.commit()
    cpu_sampler.forget(firewall_id)


@router.get("/options", response_model=list[FirewallOption])
def firewall_options(
    _user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
) -> list[FirewallOption]:
    rows = db.execute(select(Firewall).order_by(Firewall.name)).scalars().all()
    return [FirewallOption(id=fw.id, name=fw.name) for fw in rows]


@router.get("", response_model=list[FirewallOut])
def list_firewalls(
    _user: CurrentUser = Depends(require_roles(Role.admin)),
    db: Session = Depends(get_db),
) -> list[FirewallOut]:
    rows = db.execute(select(Firewall).order_by(Firewall.name)).scalars().all()
    return [_out(fw) for fw in rows]


def _get_firewall(
    db: Session, firewall_id: uuid.UUID, action: str, user: CurrentUser, request: Request
) -> Firewall:
    fw = db.get(Firewall, firewall_id)
    if fw is None:
        audit.record(
            db,
            action=action,
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            firewall_id=firewall_id,
            detail={"reason": "firewall_not_found"},
            request=request,
        )
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall not found")
    return fw


def decrypt_credentials(fw: Firewall, settings: Settings) -> tuple[str, str]:
    """Raises CredentialDecryptionError. Registers both values so logs redact them."""
    cipher = CredentialCipher(settings.credential_encryption_key.get_secret_value())
    api_key = cipher.decrypt(fw.api_key_encrypted, f"{fw.id}:api_key")
    api_secret = cipher.decrypt(fw.api_secret_encrypted, f"{fw.id}:api_secret")
    register_secret(api_key)
    register_secret(api_secret)
    return api_key, api_secret


def make_client(fw: Firewall, api_key: str, api_secret: str, settings: Settings) -> OPNsenseClient:
    return OPNsenseClient(
        base_url=fw.base_url,
        api_key=api_key,
        api_secret=api_secret,
        # fail closed if insecure TLS was switched off server-wide after the row was saved
        verify_tls=fw.verify_tls or not settings.allow_insecure_tls,
        ca_bundle_pem=fw.ca_bundle_pem,
        policy=build_policy(settings),
        connect_timeout_s=settings.opnsense_connect_timeout_s,
        read_timeout_s=settings.opnsense_read_timeout_s,
        max_retries=settings.opnsense_max_retries,
        backoff_base_s=settings.opnsense_backoff_base_s,
    )


def open_client(fw: Firewall, settings: Settings) -> OPNsenseClient:
    """Raises CredentialDecryptionError. The caller must close the client."""
    api_key, api_secret = decrypt_credentials(fw, settings)
    return make_client(fw, api_key, api_secret, settings)


def _run_operation(
    *,
    firewall_id: uuid.UUID,
    operation_id: str,
    user: CurrentUser,
    db: Session,
    settings: Settings,
    request: Request,
) -> Any:
    """Load the firewall, execute a registry operation, audit the outcome.
    Raises FirewallError (already audited) on connection/API failure. Any other unexpected
    exception is audited as a failure and surfaces as a generic 500."""
    action = f"firewall.{operation_id}"
    fw = _get_firewall(db, firewall_id, action, user, request)
    try:
        api_key, api_secret = decrypt_credentials(fw, settings)
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
            request=request,
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    verified = get_operation(operation_id).verified
    client: OPNsenseClient | None = None
    try:
        client = make_client(fw, api_key, api_secret, settings)
        if get_operation(operation_id).response_kind is ResponseKind.sse:
            result = anyio.from_thread.run(lambda: client.sample_stream(operation_id, max_events=2))
        else:
            result = anyio.from_thread.run(client.execute, operation_id)
    except FirewallError as exc:
        detail: dict[str, Any] = {"status": exc.status.value}
        if exc.status is ConnectionStatus.endpoint_not_found:
            detail["problem"] = "registry_or_version"
            detail["registry_verified"] = verified
            log.error("registry_endpoint_problem", operation=operation_id, firewall_id=str(fw.id))
        audit.record(
            db,
            action=action,
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            firewall_id=fw.id,
            detail=detail,
            request=request,
        )
        raise
    except Exception:
        log.exception("firewall_operation_crashed", operation=operation_id, firewall_id=str(fw.id))
        db.rollback()
        audit.record(
            db,
            action=action,
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            firewall_id=fw.id,
            detail={"reason": "unexpected_error"},
            request=request,
        )
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    finally:
        if client is not None:
            anyio.from_thread.run(client.aclose)
    audit.record(
        db,
        action=action,
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        firewall_id=fw.id,
        request=request,
    )
    return result


@router.get("/{firewall_id}/connectivity", response_model=ConnectivityOut)
def connectivity(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ConnectivityOut:
    verified = get_operation(CONNECTIVITY_CHECK).verified
    admin = user.role is Role.admin
    try:
        _run_operation(
            firewall_id=firewall_id,
            operation_id=CONNECTIVITY_CHECK,
            user=user,
            db=db,
            settings=settings,
            request=request,
        )
    except FirewallError as exc:
        return ConnectivityOut(
            firewall_id=firewall_id,
            ok=False,
            status=exc.status if admin else public_status(exc.status),
            message=exc.message if admin else "Firewall is unreachable",
            registry_verified=verified,
        )
    return ConnectivityOut(
        firewall_id=firewall_id,
        ok=True,
        status=ConnectionStatus.ok if admin else public_status(ConnectionStatus.ok),
        message="Connected",
        registry_verified=verified,
    )


@router.get("/{firewall_id}/system/status", response_model=SystemStatusOut)
def system_status(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> SystemStatusOut:
    admin = user.role is Role.admin
    try:
        raw = _run_operation(
            firewall_id=firewall_id,
            operation_id=SYSTEM_STATUS,
            user=user,
            db=db,
            settings=settings,
            request=request,
        )
    except FirewallError as exc:
        if not admin:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                {"status": public_status(exc.status), "message": "Firewall is unreachable"},
            ) from None
        raise HTTPException(
            _HTTP_FOR_STATUS.get(exc.status, status.HTTP_502_BAD_GATEWAY),
            {"status": exc.status.value, "message": exc.message},
        ) from None
    # Time data is best-effort: a failure here is audited by _run_operation and
    # leaves uptime/time empty rather than failing the whole status call.
    time_raw = None
    try:
        time_raw = _run_operation(
            firewall_id=firewall_id,
            operation_id=SYSTEM_TIME,
            user=user,
            db=db,
            settings=settings,
            request=request,
        )
    except FirewallError:
        pass
    resources_raw = None
    try:
        resources_raw = _run_operation(
            firewall_id=firewall_id,
            operation_id=SYSTEM_RESOURCES,
            user=user,
            db=db,
            settings=settings,
            request=request,
        )
    except FirewallError:
        pass

    def fetch_cpu() -> float | None:
        try:
            events = _run_operation(
                firewall_id=firewall_id,
                operation_id=CPU_USAGE,
                user=user,
                db=db,
                settings=settings,
                request=request,
            )
        except FirewallError:
            return None
        return normalise_cpu_events(events)

    disk_raw = None
    try:
        disk_raw = _run_operation(
            firewall_id=firewall_id,
            operation_id=SYSTEM_DISK,
            user=user,
            db=db,
            settings=settings,
            request=request,
        )
    except FirewallError:
        pass
    cpu = sample_cpu(firewall_id, fetch_cpu)
    return SystemStatusOut(
        firewall_id=firewall_id,
        status=normalise_system_status(raw, time_raw, resources_raw, cpu, disk_raw),
        registry_verified=all(
            get_operation(op).verified
            for op in (SYSTEM_STATUS, SYSTEM_TIME, SYSTEM_RESOURCES, CPU_USAGE, SYSTEM_DISK)
        ),
    )


@router.get("/{firewall_id}/interfaces", response_model=InterfacesOut)
def interfaces(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> InterfacesOut:
    try:
        raw = _run_operation(
            firewall_id=firewall_id,
            operation_id=INTERFACES_OVERVIEW,
            user=user,
            db=db,
            settings=settings,
            request=request,
        )
    except FirewallError as exc:
        if user.role is not Role.admin:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                {"status": public_status(exc.status), "message": "Firewall is unreachable"},
            ) from None
        raise HTTPException(
            _HTTP_FOR_STATUS.get(exc.status, status.HTTP_502_BAD_GATEWAY),
            {"status": exc.status.value, "message": exc.message},
        ) from None
    return InterfacesOut(
        firewall_id=firewall_id,
        interfaces=normalise_interfaces(raw),
        registry_verified=get_operation(INTERFACES_OVERVIEW).verified,
    )


@router.get("/{firewall_id}/firewall/rules", response_model=RulesOut)
def firewall_rules(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> RulesOut:
    try:
        raw = _run_operation(
            firewall_id=firewall_id,
            operation_id=FIREWALL_RULES_LIST,
            user=user,
            db=db,
            settings=settings,
            request=request,
        )
    except FirewallError as exc:
        if user.role is not Role.admin:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                {"status": public_status(exc.status), "message": "Firewall is unreachable"},
            ) from None
        raise HTTPException(
            _HTTP_FOR_STATUS.get(exc.status, status.HTTP_502_BAD_GATEWAY),
            {"status": exc.status.value, "message": exc.message},
        ) from None
    result = normalise_rules(raw)
    return RulesOut(
        firewall_id=firewall_id,
        rules=result.rules,
        truncated=result.truncated,
        registry_verified=get_operation(FIREWALL_RULES_LIST).verified,
    )


@router.get("/{firewall_id}/firewall/aliases", response_model=AliasesOut)
def firewall_aliases(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(*ALL_ROLES)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AliasesOut:
    try:
        raw = _run_operation(
            firewall_id=firewall_id,
            operation_id=FIREWALL_ALIASES_LIST,
            user=user,
            db=db,
            settings=settings,
            request=request,
        )
    except FirewallError as exc:
        if user.role is not Role.admin:
            raise HTTPException(
                status.HTTP_502_BAD_GATEWAY,
                {"status": public_status(exc.status), "message": "Firewall is unreachable"},
            ) from None
        raise HTTPException(
            _HTTP_FOR_STATUS.get(exc.status, status.HTTP_502_BAD_GATEWAY),
            {"status": exc.status.value, "message": exc.message},
        ) from None
    result = normalise_aliases(raw)
    return AliasesOut(
        firewall_id=firewall_id,
        aliases=result.aliases,
        truncated=result.truncated,
        registry_verified=get_operation(FIREWALL_ALIASES_LIST).verified,
    )
