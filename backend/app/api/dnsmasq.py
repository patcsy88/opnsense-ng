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
from app.opnsense.normalise.unbound import UnboundForwardInfo, UnboundHostInfo
from app.opnsense.normalise.wireguard_config import WireguardPeerInfo, WireguardTunnelInfo

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


class UnboundHostsOut(BaseModel):
    firewall_id: uuid.UUID
    hosts: list[UnboundHostInfo]
    registry_verified: bool


@router.get("/{firewall_id}/unbound/hosts", response_model=UnboundHostsOut)
def list_unbound_hosts(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(Role.admin, Role.network_admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UnboundHostsOut:
    """Unbound host overrides (ADR-0018). Admin and network_admin only."""
    from app.opnsense.registry.entries import UNBOUND_HOSTS_LIST, get_operation

    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall not found")
    try:
        hosts = apply_changes.read_unbound_hosts(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except CredentialDecryptionError:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    except FirewallError as exc:
        raise _log_error(exc, user) from None
    return UnboundHostsOut(
        firewall_id=firewall_id,
        hosts=hosts,
        registry_verified=get_operation(UNBOUND_HOSTS_LIST).verified,
    )


class UnboundForwardsOut(BaseModel):
    firewall_id: uuid.UUID
    forwards: list[UnboundForwardInfo]
    registry_verified: bool


@router.get("/{firewall_id}/unbound/forwards", response_model=UnboundForwardsOut)
def list_unbound_forwards(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(Role.admin, Role.network_admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UnboundForwardsOut:
    """Unbound domain forwards (ADR-0018). Admin and network_admin only."""
    from app.opnsense.registry.entries import UNBOUND_FORWARDS_LIST, get_operation

    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall not found")
    try:
        forwards = apply_changes.read_unbound_forwards(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except CredentialDecryptionError:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    except FirewallError as exc:
        raise _log_error(exc, user) from None
    return UnboundForwardsOut(
        firewall_id=firewall_id,
        forwards=forwards,
        registry_verified=get_operation(UNBOUND_FORWARDS_LIST).verified,
    )


class WireguardPeersOut(BaseModel):
    firewall_id: uuid.UUID
    peers: list[WireguardPeerInfo]
    registry_verified: bool


@router.get("/{firewall_id}/wireguard/peers", response_model=WireguardPeersOut)
def list_wireguard_peers(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(Role.admin, Role.network_admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> WireguardPeersOut:
    """WireGuard peers (ADR-0019). Public keys only; admin and network_admin."""
    from app.opnsense.registry.entries import WIREGUARD_PEERS_LIST, get_operation

    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall not found")
    try:
        peers = apply_changes.read_wireguard_peers(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except CredentialDecryptionError:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    except FirewallError as exc:
        raise _log_error(exc, user) from None
    return WireguardPeersOut(
        firewall_id=firewall_id,
        peers=peers,
        registry_verified=get_operation(WIREGUARD_PEERS_LIST).verified,
    )


class WireguardTunnelsOut(BaseModel):
    firewall_id: uuid.UUID
    tunnels: list[WireguardTunnelInfo]
    registry_verified: bool


@router.get("/{firewall_id}/wireguard/tunnels", response_model=WireguardTunnelsOut)
def list_wireguard_tunnels(
    request: Request,
    firewall_id: uuid.UUID,
    user: CurrentUser = Depends(require_roles(Role.admin, Role.network_admin)),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> WireguardTunnelsOut:
    """WireGuard tunnels (ADR-0019). Public keys only; admin and network_admin."""
    from app.opnsense.registry.entries import WIREGUARD_TUNNELS_LIST, get_operation

    fw = db.get(Firewall, firewall_id)
    if fw is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Firewall not found")
    try:
        tunnels = apply_changes.read_wireguard_tunnels(
            db, firewall=fw, user=user, settings=settings, request=request
        )
    except CredentialDecryptionError:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Internal error") from None
    except FirewallError as exc:
        raise _log_error(exc, user) from None
    return WireguardTunnelsOut(
        firewall_id=firewall_id,
        tunnels=tunnels,
        registry_verified=get_operation(WIREGUARD_TUNNELS_LIST).verified,
    )
