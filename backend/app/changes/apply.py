"""Apply an approved alias-create request to a firewall (ADR-0005, step 3).

Order of events, all audited:
  1. serialise per firewall, then approved -> applying (admin and allow_writes are checked)
  2. stale check: re-read the aliases; the name must still be free
  3. add the alias (saved on the firewall, not yet active)
  4. reconfigure (activate)
  5. read back and store the result, then applying -> applied

There is no automatic rollback. If step 3 succeeded and step 4 failed, the request is marked
failed and says plainly that the change is saved on the firewall but not active.
"""

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import anyio.from_thread
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.requests import Request

from app import audit
from app.auth.deps import CurrentUser
from app.changes import service
from app.changes.dnsmasq_schemas import domain_key, host_key
from app.changes.fingerprint import fingerprint
from app.changes.forward_schemas import ForwardProposal
from app.changes.rule_schemas import RuleProposal
from app.changes.states import Status
from app.changes.unbound_schemas import unbound_host_key
from app.core.config import Settings
from app.core.crypto import CredentialDecryptionError
from app.core.logging import get_logger
from app.db.models import ChangeRequest, Firewall
from app.opnsense.client import OPNsenseClient
from app.opnsense.errors import ConnectionStatus, FirewallError
from app.opnsense.normalise import NatRule, normalise_aliases, normalise_nat, normalise_rules
from app.opnsense.normalise.aliases import AliasInfo
from app.opnsense.normalise.dnsmasq import (
    DomainInfo,
    HostInfo,
    normalise_domains,
    normalise_hosts,
)
from app.opnsense.normalise.rules import RuleInfo
from app.opnsense.normalise.unbound import (
    UnboundForwardInfo,
    UnboundHostInfo,
    normalise_unbound_forwards,
    normalise_unbound_hosts,
)
from app.opnsense.registry.entries import (
    DNSMASQ_DOMAINS_ADD,
    DNSMASQ_DOMAINS_DELETE,
    DNSMASQ_DOMAINS_LIST,
    DNSMASQ_DOMAINS_UPDATE,
    DNSMASQ_HOSTS_ADD,
    DNSMASQ_HOSTS_DELETE,
    DNSMASQ_HOSTS_LIST,
    DNSMASQ_HOSTS_UPDATE,
    DNSMASQ_RECONFIGURE,
    FIREWALL_ALIASES_ADD,
    FIREWALL_ALIASES_DELETE,
    FIREWALL_ALIASES_LIST,
    FIREWALL_ALIASES_RECONFIGURE,
    FIREWALL_ALIASES_UPDATE,
    FIREWALL_NAT_PORT_FORWARDS,
    FIREWALL_RULES_ADD,
    FIREWALL_RULES_APPLY,
    FIREWALL_RULES_DELETE,
    FIREWALL_RULES_LIST,
    FIREWALL_RULES_TOGGLE,
    FIREWALL_RULES_UPDATE,
    FORWARDS_ADD,
    FORWARDS_APPLY,
    FORWARDS_DELETE,
    FORWARDS_DISABLE,
    FORWARDS_ENABLE,
    FORWARDS_UPDATE,
    UNBOUND_FORWARDS_ADD,
    UNBOUND_FORWARDS_DELETE,
    UNBOUND_FORWARDS_DISABLE,
    UNBOUND_FORWARDS_ENABLE,
    UNBOUND_FORWARDS_LIST,
    UNBOUND_FORWARDS_UPDATE,
    UNBOUND_HOSTS_ADD,
    UNBOUND_HOSTS_DELETE,
    UNBOUND_HOSTS_DISABLE,
    UNBOUND_HOSTS_ENABLE,
    UNBOUND_HOSTS_LIST,
    UNBOUND_HOSTS_UPDATE,
    UNBOUND_RECONFIGURE,
)

log = get_logger("changes.apply")
MESSAGE_MAX = 500


class ApplyRefused(Exception):
    """The request was not started. The message is safe to show."""


def _payload(proposed: dict[str, Any]) -> dict[str, Any]:
    return {
        "alias": {
            "enabled": "1" if proposed.get("enabled", True) else "0",
            "name": proposed["name"],
            "type": proposed["type"],
            "content": "\n".join(proposed["content"]),
            "description": proposed.get("description", ""),
        }
    }


def _validation_message(reply: Any) -> str:
    validations = reply.get("validations") if isinstance(reply, dict) else None
    if isinstance(validations, dict) and validations:
        parts = [
            f"{str(field)[:60]}: {str(msg)[:120]}" for field, msg in list(validations.items())[:5]
        ]
        return "The firewall rejected the alias: " + "; ".join(parts)
    message = reply.get("message") if isinstance(reply, dict) else None
    if isinstance(message, str) and message.strip():
        return "The firewall refused the change: " + " ".join(message.split())[:300]
    if isinstance(reply, dict):
        result = reply.get("result")
        shown = str(result)[:40] if isinstance(result, str) else "none"
        keys = ", ".join(sorted(str(k)[:30] for k in reply)[:8])
        return f"The firewall did not complete the change (result: {shown}; reply fields: {keys})"
    return "The firewall did not complete the change"


def read_aliases(
    db: Session,
    *,
    firewall: Firewall,
    user: CurrentUser,
    settings: Settings,
    request: Request,
) -> list[AliasInfo]:
    """Read-only: the aliases currently on the firewall. Raises FirewallError."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    client = open_client(firewall, settings)
    try:
        raw = _call(db, client, FIREWALL_ALIASES_LIST, None, user, firewall.id, request)
    finally:
        anyio.from_thread.run(client.aclose)
    return list(normalise_aliases(raw).aliases)


def begin_apply(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    request: Request,
    kind: str,
    actions: tuple[str, ...],
    confirm_name: str | None,
    confirm_key: str = "name",
) -> tuple[ChangeRequest, Firewall]:
    """Checks shared by every apply: request shape, typed confirmation, per-firewall lock, and
    approved -> applying. Raises ApplyRefused when nothing was started."""
    cr = db.get(ChangeRequest, change_id)
    if cr is None:
        raise ApplyRefused("Change request not found")
    if cr.kind != kind or cr.action not in actions or not cr.proposed:
        raise ApplyRefused(f"Only {kind} changes of this type can be applied here")
    if cr.action != "create" and not cr.target_uuid:
        raise ApplyRefused(f"This request has no target {kind}")
    if cr.high_risk and confirm_name != cr.proposed.get(confirm_key):
        what = {
            "alias": "alias name",
            "dnsmasq_host": "description",
            "dnsmasq_domain": "description",
            "unbound_host": "description",
            "unbound_forward": "description",
        }.get(kind, "rule label")
        raise ApplyRefused(f"Type the {what} to confirm this high-risk change")
    fw = db.get(Firewall, cr.firewall_id)
    if fw is None:
        raise ApplyRefused("Firewall not found")

    # Serialise starts per firewall; the "applying" status then blocks everyone else.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": str(fw.id)})
    busy = db.scalar(
        select(func.count())
        .select_from(ChangeRequest)
        .where(
            ChangeRequest.firewall_id == fw.id,
            ChangeRequest.status == Status.applying.value,
            ChangeRequest.id != cr.id,
        )
    )
    if busy:
        db.rollback()
        raise ApplyRefused("Another change is being applied to this firewall")
    service.transition(db, cr, Status.applying, user=user, request=request)
    db.commit()
    return cr, fw


def apply_alias_change(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    cr, fw = begin_apply(
        db,
        change_id=change_id,
        user=user,
        request=request,
        kind="alias",
        actions=("create", "update", "delete"),
        confirm_name=confirm_name,
    )
    firewall_id = fw.id

    proposed = dict(cr.proposed or {})
    action = cr.action
    target = cr.target_uuid
    params = {"uuid": target} if action != "create" and target else None
    client: OPNsenseClient | None = None
    saved = False
    try:
        try:
            client = open_client(fw, settings)
        except CredentialDecryptionError:
            return _finish(
                db, cr, Status.failed, user, request, "Stored credentials could not be decrypted"
            )

        # 2. stale check
        try:
            listing = _call(db, client, FIREWALL_ALIASES_LIST, None, user, fw.id, request)
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Check failed: {exc.message}")
        rows = normalise_aliases(listing).aliases
        if action == "create":
            if proposed["name"] in {a.name for a in rows}:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    "An alias with this name now exists on the firewall; nothing was changed",
                )
        else:
            current = next((a for a in rows if a.uuid == target), None)
            if current is None:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    "The alias no longer exists on the firewall; nothing was changed",
                )
            if fingerprint(current.model_dump()) != cr.base_fingerprint:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    "The alias was changed on the firewall after this request was made; "
                    "nothing was changed. Create a new request.",
                )

        # 3. save
        if action == "create":
            op_id, body, done = FIREWALL_ALIASES_ADD, _payload(proposed), "saved"
        elif action == "update":
            op_id, body, done = FIREWALL_ALIASES_UPDATE, _payload(proposed), "saved"
        else:
            op_id, body, done = FIREWALL_ALIASES_DELETE, {}, "deleted"
        try:
            reply = _call(db, client, op_id, body, user, fw.id, request, params)
        except FirewallError as exc:
            if action == "delete" and exc.status is ConnectionStatus.server_error:
                note = "The firewall refused to delete the alias; it may still be in use"
            else:
                note = f"Not saved: {exc.message}"
            return _finish(db, cr, Status.failed, user, request, note)
        if not isinstance(reply, dict) or reply.get("result") != done:
            return _finish(db, cr, Status.failed, user, request, _validation_message(reply))
        saved = True

        # 4. activate
        try:
            result = _call(db, client, FIREWALL_ALIASES_RECONFIGURE, {}, user, fw.id, request)
        except FirewallError as exc:
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                f"The change is saved on the firewall but NOT active: {exc.message}",
            )
        if not isinstance(result, dict) or result.get("status") != "ok":
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                "The change is saved on the firewall but NOT active: activation was not confirmed",
            )

        # 5. read back (best effort) and finish
        snapshot: dict[str, Any] | None
        try:
            after = _call(db, client, FIREWALL_ALIASES_LIST, None, user, fw.id, request)
            match = next(
                (
                    a
                    for a in normalise_aliases(after).aliases
                    if (a.uuid == target if action != "create" else a.name == proposed["name"])
                ),
                None,
            )
            snapshot = match.model_dump() if match else None
        except FirewallError:
            snapshot = None
        return _finish(db, cr, Status.applied, user, request, None, snapshot)
    except Exception:
        log.exception("apply_crashed", change_request=str(cr.id), firewall_id=str(firewall_id))
        db.rollback()
        db.refresh(cr)
        state = (
            "saved on the firewall, activation unknown"
            if saved
            else "the firewall state is unknown"
        )
        return _finish(
            db, cr, Status.failed, user, request, f"Unexpected error; {state}. Check the firewall."
        )
    finally:
        if client is not None:
            anyio.from_thread.run(client.aclose)


def read_rules(
    db: Session,
    *,
    firewall: Firewall,
    user: CurrentUser,
    settings: Settings,
    request: Request,
) -> list[RuleInfo]:
    """Read-only: the rules currently on the firewall. Raises FirewallError."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    client = open_client(firewall, settings)
    try:
        raw = _call(db, client, FIREWALL_RULES_LIST, None, user, firewall.id, request)
    finally:
        anyio.from_thread.run(client.aclose)
    return list(normalise_rules(raw).rules)


def read_forwards(
    db: Session,
    *,
    firewall: Firewall,
    user: CurrentUser,
    settings: Settings,
    request: Request,
) -> list[NatRule]:
    """Read-only: the port forwards currently on the firewall. Raises FirewallError."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    client = open_client(firewall, settings)
    try:
        raw = _call(db, client, FIREWALL_NAT_PORT_FORWARDS, None, user, firewall.id, request)
    finally:
        anyio.from_thread.run(client.aclose)
    return list(normalise_nat(raw, "port_forward").rules)


def rule_payload(proposed: dict[str, Any], sequence: int) -> dict[str, Any]:
    return {
        "rule": {
            "enabled": "1" if proposed.get("enabled", True) else "0",
            "sequence": str(sequence),
            "action": proposed["action"],
            "quick": "1",
            "interface": proposed["interface"],
            "direction": proposed["direction"],
            "ipprotocol": proposed["ip_protocol"],
            "protocol": proposed["protocol"],
            "source_net": proposed["source"],
            "source_port": proposed.get("source_port", ""),
            "destination_net": proposed["destination"],
            "destination_port": proposed.get("destination_port", ""),
            "log": "1" if proposed.get("log") else "0",
            "description": proposed["description"],
        }
    }


def next_sequence(rules: list[RuleInfo]) -> int:
    """After the last user rule, never first: OPNsense would default a new rule to 1."""
    used = [r.sequence for r in rules if r.sequence is not None]
    return min((max(used) + 1) if used else 1, 999999)


def alias_problem(
    references: set[str], aliases: list[AliasInfo], proposed: dict[str, Any]
) -> str | None:
    """Every alias a rule names must exist, as the right kind (ports vs addresses)."""
    by_name = {a.name: a for a in aliases if a.name}
    port_names = {
        proposed.get("source_port", ""),
        proposed.get("destination_port", ""),
        proposed.get("target_port", ""),
    }
    for name in sorted(references):
        alias = by_name.get(name)
        if alias is None:
            return f"The alias {name} does not exist on the firewall"
        if (alias.type == "port") != (name in port_names):
            return f"The alias {name} is the wrong type for this field"
    return None


def apply_rule_change(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    """Rule counterpart of apply_alias_change: stale check, save, `filter/apply`, read back."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    cr, fw = begin_apply(
        db,
        change_id=change_id,
        user=user,
        request=request,
        kind="rule",
        actions=("toggle", "create", "update", "delete"),
        confirm_name=confirm_name,
        confirm_key="label",
    )
    firewall_id = fw.id
    action = cr.action
    target = cr.target_uuid
    proposed = dict(cr.proposed or {})
    params = {"uuid": target} if action != "create" and target else None
    client: OPNsenseClient | None = None
    saved = False
    try:
        try:
            client = open_client(fw, settings)
        except CredentialDecryptionError:
            return _finish(
                db, cr, Status.failed, user, request, "Stored credentials could not be decrypted"
            )

        try:
            listing = _call(db, client, FIREWALL_RULES_LIST, None, user, fw.id, request)
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Check failed: {exc.message}")
        rules = normalise_rules(listing).rules
        sequence = 0
        if action != "create":
            current = next((r for r in rules if r.uuid == target), None)
            if current is None:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    "The rule no longer exists on the firewall; nothing was changed",
                )
            if fingerprint(current.model_dump()) != cr.base_fingerprint:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    "The rule was changed on the firewall after this request was made; "
                    "nothing was changed. Create a new request.",
                )
            sequence = current.sequence or 0
        if action == "create" and any(r.description == proposed["description"] for r in rules):
            return _finish(
                db,
                cr,
                Status.stale,
                user,
                request,
                "A rule with this description now exists on the firewall; nothing was changed",
            )
        if action in ("create", "update"):
            references = RuleProposal.model_validate(
                {k: v for k, v in proposed.items() if k not in ("label", "risk")}
            ).alias_references()
            if references:
                try:
                    aliases = normalise_aliases(
                        _call(db, client, FIREWALL_ALIASES_LIST, None, user, fw.id, request)
                    ).aliases
                except FirewallError as exc:
                    return _finish(
                        db, cr, Status.failed, user, request, f"Check failed: {exc.message}"
                    )
                problem = alias_problem(references, list(aliases), proposed)
                if problem:
                    return _finish(
                        db, cr, Status.stale, user, request, f"{problem}; nothing was changed"
                    )
            if action == "create":
                sequence = next_sequence(rules)

        try:
            if action == "toggle":
                reply = _call(db, client, FIREWALL_RULES_TOGGLE, {}, user, fw.id, request, params)
                want = "Enabled" if proposed.get("enabled") else "Disabled"
            elif action == "delete":
                reply = _call(db, client, FIREWALL_RULES_DELETE, {}, user, fw.id, request, params)
                want = "deleted"
            elif action == "update":
                reply = _call(
                    db,
                    client,
                    FIREWALL_RULES_UPDATE,
                    rule_payload(proposed, sequence),
                    user,
                    fw.id,
                    request,
                    params,
                )
                want = "saved"
            else:
                reply = _call(
                    db,
                    client,
                    FIREWALL_RULES_ADD,
                    rule_payload(proposed, sequence),
                    user,
                    fw.id,
                    request,
                )
                want = "saved"
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Not saved: {exc.message}")
        if not isinstance(reply, dict) or reply.get("result") != want:
            return _finish(db, cr, Status.failed, user, request, _validation_message(reply))
        saved = True
        if action == "create":
            new_id = reply.get("uuid")
            target = new_id if isinstance(new_id, str) else None

        try:
            result = _call(db, client, FIREWALL_RULES_APPLY, {}, user, fw.id, request)
        except FirewallError as exc:
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                f"The change is saved on the firewall but NOT active: {exc.message}",
            )
        status_text = result.get("status") if isinstance(result, dict) else None
        if not isinstance(status_text, str) or status_text.strip().lower() != "ok":
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                "The change is saved on the firewall but NOT active: activation was not confirmed",
            )

        snapshot: dict[str, Any] | None
        if action == "delete":
            return _finish(db, cr, Status.applied, user, request, None, None)
        try:
            after = _call(db, client, FIREWALL_RULES_LIST, None, user, fw.id, request)
            match = next(
                (
                    r
                    for r in normalise_rules(after).rules
                    if (
                        r.uuid == target if target else r.description == proposed.get("description")
                    )
                ),
                None,
            )
            snapshot = match.model_dump() if match else None
        except FirewallError:
            snapshot = None
        return _finish(db, cr, Status.applied, user, request, None, snapshot)
    except Exception:
        log.exception("apply_crashed", change_request=str(cr.id), firewall_id=str(firewall_id))
        db.rollback()
        db.refresh(cr)
        state = (
            "saved on the firewall, activation unknown"
            if saved
            else "the firewall state is unknown"
        )
        return _finish(
            db, cr, Status.failed, user, request, f"Unexpected error; {state}. Check the firewall."
        )
    finally:
        if client is not None:
            anyio.from_thread.run(client.aclose)


def forward_payload(
    proposed: dict[str, Any], sequence: int | None, *, fixed_defaults: bool
) -> dict[str, Any]:
    """Body for addRule/setRule. `pass` is left blank (Manual) so no filter rule is registered.
    On update the fixed fields are omitted so whatever the firewall holds stays untouched."""
    rule: dict[str, Any] = {
        "disabled": "0" if proposed.get("enabled", True) else "1",
        "interface": proposed["interface"],
        "ipprotocol": proposed["ip_protocol"],
        "protocol": proposed["protocol"],
        "source": {
            "network": proposed["source"],
            "port": proposed.get("source_port", ""),
            "not": "0",
        },
        "destination": {
            "network": proposed["destination"],
            "port": proposed.get("destination_port", ""),
            "not": "0",
        },
        "target": proposed["target"],
        "local-port": proposed.get("target_port", ""),
        "log": "1" if proposed.get("log") else "0",
        "descr": proposed["description"],
    }
    if sequence is not None:
        rule["sequence"] = str(sequence)
    if fixed_defaults:
        rule.update({"nordr": "0", "poolopts": "", "natreflection": "", "pass": ""})
    return {"rule": rule}


def apply_forward_change(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    """Port forward counterpart of apply_rule_change (ADR-0006): stale check, save, `d_nat/apply`,
    read back. No automatic rollback."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    cr, fw = begin_apply(
        db,
        change_id=change_id,
        user=user,
        request=request,
        kind="nat_forward",
        actions=("toggle", "create", "update", "delete"),
        confirm_name=confirm_name,
        confirm_key="label",
    )
    firewall_id = fw.id
    action = cr.action
    target = cr.target_uuid
    proposed = dict(cr.proposed or {})
    params = {"uuid": target} if action != "create" and target else None
    client: OPNsenseClient | None = None
    saved = False
    try:
        try:
            client = open_client(fw, settings)
        except CredentialDecryptionError:
            return _finish(
                db, cr, Status.failed, user, request, "Stored credentials could not be decrypted"
            )

        try:
            listing = _call(db, client, FIREWALL_NAT_PORT_FORWARDS, None, user, fw.id, request)
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Check failed: {exc.message}")
        forwards = normalise_nat(listing, "port_forward").rules
        sequence: int | None = None
        if action != "create":
            current = next((r for r in forwards if r.uuid == target), None)
            if current is None:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    "The port forward no longer exists on the firewall; nothing was changed",
                )
            if fingerprint(current.model_dump()) != cr.base_fingerprint:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    "The port forward was changed on the firewall after this request was made; "
                    "nothing was changed. Create a new request.",
                )
            sequence = current.sequence
        if action == "create" and any(r.description == proposed["description"] for r in forwards):
            return _finish(
                db,
                cr,
                Status.stale,
                user,
                request,
                "A port forward with this description now exists on the firewall; "
                "nothing was changed",
            )
        if action in ("create", "update"):
            references = ForwardProposal.model_validate(
                {k: v for k, v in proposed.items() if k not in ("label", "risk")}
            ).alias_references()
            if references:
                try:
                    aliases = normalise_aliases(
                        _call(db, client, FIREWALL_ALIASES_LIST, None, user, fw.id, request)
                    ).aliases
                except FirewallError as exc:
                    return _finish(
                        db, cr, Status.failed, user, request, f"Check failed: {exc.message}"
                    )
                problem = alias_problem(references, list(aliases), proposed)
                if problem:
                    return _finish(
                        db, cr, Status.stale, user, request, f"{problem}; nothing was changed"
                    )
            if action == "create":
                used = [r.sequence for r in forwards if r.sequence is not None]
                sequence = min((max(used) + 1) if used else 1, 999999)

        try:
            if action == "toggle":
                enabling = bool(proposed.get("enabled"))
                reply = _call(
                    db,
                    client,
                    FORWARDS_ENABLE if enabling else FORWARDS_DISABLE,
                    {},
                    user,
                    fw.id,
                    request,
                    params,
                )
                want = "Enabled" if enabling else "Disabled"
            elif action == "delete":
                reply = _call(db, client, FORWARDS_DELETE, {}, user, fw.id, request, params)
                want = "deleted"
            else:
                reply = _call(
                    db,
                    client,
                    FORWARDS_UPDATE if action == "update" else FORWARDS_ADD,
                    forward_payload(proposed, sequence, fixed_defaults=action == "create"),
                    user,
                    fw.id,
                    request,
                    params,
                )
                want = "saved"
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Not saved: {exc.message}")
        if not isinstance(reply, dict) or reply.get("result") != want:
            return _finish(db, cr, Status.failed, user, request, _validation_message(reply))
        saved = True
        if action == "create":
            new_id = reply.get("uuid")
            target = new_id if isinstance(new_id, str) else None

        try:
            result = _call(db, client, FORWARDS_APPLY, {}, user, fw.id, request)
        except FirewallError as exc:
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                f"The change is saved on the firewall but NOT active: {exc.message}",
            )
        status_text = result.get("status") if isinstance(result, dict) else None
        if not isinstance(status_text, str) or status_text.strip().lower() != "ok":
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                "The change is saved on the firewall but NOT active: activation was not confirmed",
            )

        if action == "delete":
            return _finish(db, cr, Status.applied, user, request, None, None)
        snapshot: dict[str, Any] | None
        try:
            after = _call(db, client, FIREWALL_NAT_PORT_FORWARDS, None, user, fw.id, request)
            match = next(
                (
                    r
                    for r in normalise_nat(after, "port_forward").rules
                    if (
                        r.uuid == target if target else r.description == proposed.get("description")
                    )
                ),
                None,
            )
            snapshot = match.model_dump() if match else None
        except FirewallError:
            snapshot = None
        return _finish(db, cr, Status.applied, user, request, None, snapshot)
    except Exception:
        log.exception("apply_crashed", change_request=str(cr.id), firewall_id=str(firewall_id))
        db.rollback()
        db.refresh(cr)
        state = (
            "saved on the firewall, activation unknown"
            if saved
            else "the firewall state is unknown"
        )
        return _finish(
            db, cr, Status.failed, user, request, f"Unexpected error; {state}. Check the firewall."
        )
    finally:
        if client is not None:
            anyio.from_thread.run(client.aclose)


def _call(
    db: Session,
    client: OPNsenseClient,
    operation_id: str,
    payload: dict[str, Any] | None,
    user: CurrentUser,
    firewall_id: uuid.UUID,
    request: Request,
    path_params: dict[str, str] | None = None,
) -> Any:
    """Run one registry operation and audit it, whatever the outcome."""
    action = f"firewall.{operation_id}"
    try:
        result = anyio.from_thread.run(client.execute, operation_id, payload, path_params)
    except FirewallError as exc:
        audit.record(
            db,
            action=action,
            outcome=audit.OUTCOME_FAILURE,
            user_id=user.id,
            username=user.username,
            firewall_id=firewall_id,
            detail={"status": exc.status.value},
            request=request,
        )
        raise
    audit.record(
        db,
        action=action,
        outcome=audit.OUTCOME_SUCCESS,
        user_id=user.id,
        username=user.username,
        firewall_id=firewall_id,
        request=request,
    )
    return result


def _finish(
    db: Session,
    cr: ChangeRequest,
    to: Status,
    user: CurrentUser,
    request: Request,
    message: str | None,
    snapshot: dict[str, Any] | None = None,
) -> ChangeRequest:
    service.transition(db, cr, to, user=user, note=message, request=request)
    # Set after the transition: it re-reads the row under a lock and would drop pending edits.
    if message:
        cr.failure_message = message[:MESSAGE_MAX]
    if to is Status.applied:
        cr.result_snapshot = snapshot
    db.commit()
    return cr


def read_hosts(
    db: Session,
    *,
    firewall: Firewall,
    user: CurrentUser,
    settings: Settings,
    request: Request,
) -> list[HostInfo]:
    """Read-only: the Dnsmasq static hosts currently on the firewall. Raises FirewallError."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    client = open_client(firewall, settings)
    try:
        raw = _call(db, client, DNSMASQ_HOSTS_LIST, None, user, firewall.id, request)
    finally:
        anyio.from_thread.run(client.aclose)
    return list(normalise_hosts(raw).hosts)


def host_conflict(proposed: dict[str, Any], hosts: list[HostInfo], own: str | None) -> str | None:
    """Duplicate name or MAC against the hosts on the firewall, ignoring the entry being edited."""
    key = host_key(proposed.get("host"), proposed.get("domain"))
    macs = set(proposed.get("hwaddrs") or [])
    for h in hosts:
        if h.uuid == own:
            continue
        if host_key(h.host, h.domain) == key:
            return "A host entry with this name and domain already exists on the firewall"
        if macs & set(h.hwaddrs):
            return "Another host entry on the firewall already uses one of these MAC addresses"
    return None


def host_payload(proposed: dict[str, Any]) -> dict[str, Any]:
    """Body for addHost/setHost. Client id, lease time, tags, local and comments stay at defaults
    on create and untouched on update."""
    return {
        "host": {
            "host": proposed["host"],
            "domain": proposed.get("domain", ""),
            "ip": ",".join(proposed["ips"]),
            "hwaddr": ",".join(proposed.get("hwaddrs", [])),
            "cnames": ",".join(proposed.get("cnames", [])),
            "ignore": "1" if proposed.get("ignore") else "0",
            "descr": proposed["description"],
        }
    }


def read_domains(
    db: Session,
    *,
    firewall: Firewall,
    user: CurrentUser,
    settings: Settings,
    request: Request,
) -> list[DomainInfo]:
    """Read-only: the Dnsmasq domain overrides currently on the firewall. Raises FirewallError."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    client = open_client(firewall, settings)
    try:
        raw = _call(db, client, DNSMASQ_DOMAINS_LIST, None, user, firewall.id, request)
    finally:
        anyio.from_thread.run(client.aclose)
    return list(normalise_domains(raw).domains)


def domain_conflict(
    proposed: dict[str, Any], domains: list[DomainInfo], own: str | None
) -> str | None:
    """Only one override per domain, ignoring the entry being edited."""
    key = domain_key(proposed.get("domain"))
    for d in domains:
        if d.uuid != own and domain_key(d.domain) == key:
            return "An override for this domain already exists on the firewall"
    return None


def domain_payload(proposed: dict[str, Any]) -> dict[str, Any]:
    """Body for addDomain/setDomain. Source IP, ipset and sequence stay at defaults."""
    port = proposed.get("port")
    return {
        "domainoverride": {
            "domain": proposed["domain"],
            "ip": proposed["server"],
            "port": str(port) if port else "",
            "descr": proposed["description"],
        }
    }


@dataclass(frozen=True)
class ResolverSpec:
    """What differs between the Dnsmasq and Unbound kinds in the shared apply procedure
    (ADR-0017, ADR-0018)."""

    kind: str
    noun: str
    list_op: str
    add_op: str
    update_op: str
    delete_op: str
    normalise: Callable[[Any], list[Any]]
    conflict: Callable[[dict[str, Any], list[Any], str | None], str | None]
    payload: Callable[[dict[str, Any]], dict[str, Any]]
    same: Callable[[Any, dict[str, Any]], bool]
    reconfigure_op: str = DNSMASQ_RECONFIGURE
    toggle_on: str | None = None
    toggle_off: str | None = None


HOST_SPEC = ResolverSpec(
    kind="dnsmasq_host",
    noun="host entry",
    list_op=DNSMASQ_HOSTS_LIST,
    add_op=DNSMASQ_HOSTS_ADD,
    update_op=DNSMASQ_HOSTS_UPDATE,
    delete_op=DNSMASQ_HOSTS_DELETE,
    normalise=lambda raw: list(normalise_hosts(raw).hosts),
    conflict=host_conflict,
    payload=host_payload,
    same=lambda h, p: host_key(h.host, h.domain) == host_key(p.get("host"), p.get("domain")),
)

DOMAIN_SPEC = ResolverSpec(
    kind="dnsmasq_domain",
    noun="domain override",
    list_op=DNSMASQ_DOMAINS_LIST,
    add_op=DNSMASQ_DOMAINS_ADD,
    update_op=DNSMASQ_DOMAINS_UPDATE,
    delete_op=DNSMASQ_DOMAINS_DELETE,
    normalise=lambda raw: list(normalise_domains(raw).domains),
    conflict=domain_conflict,
    payload=domain_payload,
    same=lambda d, p: domain_key(d.domain) == domain_key(p.get("domain")),
)


def read_unbound_hosts(
    db: Session,
    *,
    firewall: Firewall,
    user: CurrentUser,
    settings: Settings,
    request: Request,
) -> list[UnboundHostInfo]:
    """Read-only: the Unbound host overrides currently on the firewall. Raises FirewallError."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    client = open_client(firewall, settings)
    try:
        raw = _call(db, client, UNBOUND_HOSTS_LIST, None, user, firewall.id, request)
    finally:
        anyio.from_thread.run(client.aclose)
    return list(normalise_unbound_hosts(raw).hosts)


def unbound_host_conflict(
    proposed: dict[str, Any], hosts: list[UnboundHostInfo], own: str | None
) -> str | None:
    """Same name, domain and record type already present, ignoring the entry being edited."""
    key = unbound_host_key(proposed.get("hostname"), proposed.get("domain"), proposed.get("rr"))
    for h in hosts:
        if h.uuid != own and unbound_host_key(h.hostname, h.domain, h.rr) == key:
            return "A host override with this name, domain and record type already exists"
    return None


def unbound_host_payload(proposed: dict[str, Any]) -> dict[str, Any]:
    """Body for addHostOverride/setHostOverride. Reverse record, MX and TXT fields stay at their
    defaults on create and untouched on update."""
    ttl = proposed.get("ttl")
    return {
        "host": {
            "enabled": "1" if proposed.get("enabled", True) else "0",
            "hostname": proposed["hostname"],
            "domain": proposed["domain"],
            "rr": proposed["rr"],
            "server": proposed["server"],
            "ttl": str(ttl) if ttl is not None else "",
            "description": proposed["description"],
        }
    }


UNBOUND_HOST_SPEC = ResolverSpec(
    kind="unbound_host",
    noun="host override",
    list_op=UNBOUND_HOSTS_LIST,
    add_op=UNBOUND_HOSTS_ADD,
    update_op=UNBOUND_HOSTS_UPDATE,
    delete_op=UNBOUND_HOSTS_DELETE,
    normalise=lambda raw: list(normalise_unbound_hosts(raw).hosts),
    conflict=unbound_host_conflict,
    payload=unbound_host_payload,
    same=lambda h, p: (
        unbound_host_key(h.hostname, h.domain, h.rr)
        == unbound_host_key(p.get("hostname"), p.get("domain"), p.get("rr"))
    ),
    reconfigure_op=UNBOUND_RECONFIGURE,
    toggle_on=UNBOUND_HOSTS_ENABLE,
    toggle_off=UNBOUND_HOSTS_DISABLE,
)


def apply_unbound_host_change(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    return _apply_resolver(UNBOUND_HOST_SPEC, db, change_id, user, settings, request, confirm_name)


def read_unbound_forwards(
    db: Session,
    *,
    firewall: Firewall,
    user: CurrentUser,
    settings: Settings,
    request: Request,
) -> list[UnboundForwardInfo]:
    """Read-only: the Unbound domain forwards currently on the firewall. Raises FirewallError."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    client = open_client(firewall, settings)
    try:
        raw = _call(db, client, UNBOUND_FORWARDS_LIST, None, user, firewall.id, request)
    finally:
        anyio.from_thread.run(client.aclose)
    return list(normalise_unbound_forwards(raw).forwards)


def unbound_forward_conflict(
    proposed: dict[str, Any], forwards: list[UnboundForwardInfo], own: str | None
) -> str | None:
    key = domain_key(proposed.get("domain"))
    for f in forwards:
        if f.uuid != own and domain_key(f.domain) == key:
            return "A forward for this domain already exists on the firewall"
    return None


def unbound_forward_payload(proposed: dict[str, Any]) -> dict[str, Any]:
    """Body for addForward/setForward. The type is always `forward`; TCP-upstream and
    forward-first stay at their defaults."""
    port = proposed.get("port")
    return {
        "dot": {
            "enabled": "1" if proposed.get("enabled", True) else "0",
            "type": "forward",
            "domain": proposed["domain"],
            "server": proposed["server"],
            "port": str(port) if port is not None else "",
            "description": proposed["description"],
        }
    }


UNBOUND_FORWARD_SPEC = ResolverSpec(
    kind="unbound_forward",
    noun="forward",
    list_op=UNBOUND_FORWARDS_LIST,
    add_op=UNBOUND_FORWARDS_ADD,
    update_op=UNBOUND_FORWARDS_UPDATE,
    delete_op=UNBOUND_FORWARDS_DELETE,
    normalise=lambda raw: list(normalise_unbound_forwards(raw).forwards),
    conflict=unbound_forward_conflict,
    payload=unbound_forward_payload,
    same=lambda f, p: domain_key(f.domain) == domain_key(p.get("domain")),
    reconfigure_op=UNBOUND_RECONFIGURE,
    toggle_on=UNBOUND_FORWARDS_ENABLE,
    toggle_off=UNBOUND_FORWARDS_DISABLE,
)


def apply_unbound_forward_change(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    return _apply_resolver(
        UNBOUND_FORWARD_SPEC, db, change_id, user, settings, request, confirm_name
    )


def apply_host_change(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    return _apply_resolver(HOST_SPEC, db, change_id, user, settings, request, confirm_name)


def apply_domain_change(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    return _apply_resolver(DOMAIN_SPEC, db, change_id, user, settings, request, confirm_name)


def _apply_resolver(
    spec: ResolverSpec,
    db: Session,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    """Resolver apply (ADR-0017, ADR-0018): stale check, save, `reconfigure`, read back. No
    automatic rollback. Reconfigure restarts the resolver, so DNS pauses briefly."""
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    cr, fw = begin_apply(
        db,
        change_id=change_id,
        user=user,
        request=request,
        kind=spec.kind,
        actions=("create", "update", "delete") + (("toggle",) if spec.toggle_on else ()),
        confirm_name=confirm_name,
        confirm_key="label",
    )
    firewall_id = fw.id
    action = cr.action
    target = cr.target_uuid
    proposed = dict(cr.proposed or {})
    params = {"uuid": target} if action != "create" and target else None
    client: OPNsenseClient | None = None
    saved = False
    try:
        try:
            client = open_client(fw, settings)
        except CredentialDecryptionError:
            return _finish(
                db, cr, Status.failed, user, request, "Stored credentials could not be decrypted"
            )
        try:
            listing = _call(db, client, spec.list_op, None, user, fw.id, request)
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Check failed: {exc.message}")
        items = spec.normalise(listing)
        if action != "create":
            current = next((h for h in items if h.uuid == target), None)
            if current is None:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    f"The {spec.noun} no longer exists on the firewall; nothing was changed",
                )
            if fingerprint(current.model_dump()) != cr.base_fingerprint:
                return _finish(
                    db,
                    cr,
                    Status.stale,
                    user,
                    request,
                    f"The {spec.noun} was changed on the firewall after this request was made; "
                    "nothing was changed. Create a new request.",
                )
        if action in ("create", "update"):
            clash = spec.conflict(proposed, items, target if action == "update" else None)
            if clash:
                return _finish(db, cr, Status.stale, user, request, f"{clash}; nothing was changed")

        try:
            if action == "toggle":
                enabling = bool(proposed.get("enabled"))
                reply = _call(
                    db,
                    client,
                    (spec.toggle_on if enabling else spec.toggle_off) or "",
                    {},
                    user,
                    fw.id,
                    request,
                    params,
                )
                want = "Enabled" if enabling else "Disabled"
            elif action == "delete":
                reply = _call(db, client, spec.delete_op, {}, user, fw.id, request, params)
                want = "deleted"
            else:
                reply = _call(
                    db,
                    client,
                    spec.update_op if action == "update" else spec.add_op,
                    spec.payload(proposed),
                    user,
                    fw.id,
                    request,
                    params,
                )
                want = "saved"
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Not saved: {exc.message}")
        got = reply.get("result") if isinstance(reply, dict) else None
        if not isinstance(got, str) or got.lower() != want.lower():
            return _finish(db, cr, Status.failed, user, request, _validation_message(reply))
        saved = True
        if action == "create":
            new_id = reply.get("uuid") if isinstance(reply, dict) else None
            target = new_id if isinstance(new_id, str) else None

        try:
            result = _call(db, client, spec.reconfigure_op, {}, user, fw.id, request)
        except FirewallError as exc:
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                f"The change is saved on the firewall but NOT active: {exc.message}",
            )
        status_text = result.get("status") if isinstance(result, dict) else None
        if not isinstance(status_text, str) or status_text.strip().lower() != "ok":
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                "The change is saved on the firewall but NOT active: activation was not confirmed",
            )

        if action == "delete":
            return _finish(db, cr, Status.applied, user, request, None, None)
        snapshot: dict[str, Any] | None
        try:
            after = spec.normalise(_call(db, client, spec.list_op, None, user, fw.id, request))
            match = next(
                (h for h in after if (h.uuid == target if target else spec.same(h, proposed))),
                None,
            )
            snapshot = match.model_dump() if match else None
        except FirewallError:
            snapshot = None
        return _finish(db, cr, Status.applied, user, request, None, snapshot)
    except Exception:
        log.exception("apply_crashed", change_request=str(cr.id), firewall_id=str(firewall_id))
        db.rollback()
        db.refresh(cr)
        state = (
            "saved on the firewall, activation unknown"
            if saved
            else "the firewall state is unknown"
        )
        return _finish(
            db, cr, Status.failed, user, request, f"Unexpected error; {state}. Check the firewall."
        )
    finally:
        if client is not None:
            anyio.from_thread.run(client.aclose)
