"""Read-only view of Dnsmasq static hosts (ADR-0017). MAC addresses are included, so this is
limited to admin and network_admin. Changes go through the staged flow in api/changes.py."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.firewalls import _log_error
from app.auth.deps import CurrentUser, get_db, require_roles
from app.changes import apply as apply_changes
from app.core.config import Settings, get_settings
from app.core.crypto import CredentialDecryptionError
from app.db.models import Firewall, Role
from app.opnsense.errors import FirewallError
from app.opnsense.normalise.dnsmasq import DomainInfo, HostInfo

router = APIRouter(prefix="/api/v1/firewalls", tags=["dnsmasq"])


class HostsOut(BaseModel):
    firewall_id: uuid.UUID
    hosts: list[HostInfo]
    registry_verified: bool


@router.get("/{firewall_id}/dnsmasq/hosts", response_model=HostsOut)
def list_hosts(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(Role.admin, Role.network_admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> HostsOut:
    from app.opnsense.registry.entries import DNSMASQ_HOSTS_LIST, get_operation

    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall not found")
    try:
        hosts = apply_changes.read_hosts(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except CredentialDecryptionError:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    except FirewallError as exc:
        raise _log_error(exc, user) from None
    return HostsOut(
        firewall_id=firewall_id,
        hosts=hosts,
        registry_verified=get_operation(DNSMASQ_HOSTS_LIST).verified,
    )


class DomainsOut(BaseModel):
    firewall_id: uuid.UUID
    domains: list[DomainInfo]
    registry_verified: bool


@router.get("/{firewall_id}/dnsmasq/domains", response_model=DomainsOut)
def list_domains(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(Role.admin, Role.network_admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> DomainsOut:
    from app.opnsense.registry.entries import DNSMASQ_DOMAINS_LIST, get_operation

    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall not found")
    try:
        domains = apply_changes.read_domains(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except CredentialDecryptionError:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    except FirewallError as exc:
        raise _log_error(exc, user) from None
    return DomainsOut(
        firewall_id=firewall_id,
        domains=domains,
        registry_verified=get_operation(DNSMASQ_DOMAINS_LIST).verified,
    )
