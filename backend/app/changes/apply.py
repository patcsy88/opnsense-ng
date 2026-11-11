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
from typing import Any

import anyio.from_thread
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from starlette.requests import Request

from app import audit
from app.auth.deps import CurrentUser
from app.changes import service
from app.changes.fingerprint import fingerprint
from app.changes.states import Status
from app.core.config import Settings
from app.core.crypto import CredentialDecryptionError
from app.core.logging import get_logger
from app.db.models import ChangeRequest, Firewall
from app.opnsense.client import OPNsenseClient
from app.opnsense.errors import ConnectionStatus, FirewallError
from app.opnsense.normalise import normalise_aliases, normalise_rules
from app.opnsense.normalise.aliases import AliasInfo
from app.opnsense.normalise.rules import RuleInfo
from app.opnsense.registry.entries import (
    FIREWALL_ALIASES_ADD,
    FIREWALL_ALIASES_DELETE,
    FIREWALL_ALIASES_LIST,
    FIREWALL_ALIASES_RECONFIGURE,
    FIREWALL_ALIASES_UPDATE,
    FIREWALL_RULES_APPLY,
    FIREWALL_RULES_LIST,
    FIREWALL_RULES_TOGGLE,
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
        what = "alias name" if kind == "alias" else "rule label"
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
        actions=("toggle",),
        confirm_name=confirm_name,
        confirm_key="label",
    )
    firewall_id = fw.id
    target = cr.target_uuid
    params = {"uuid": target} if target else None
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
        current = next((r for r in normalise_rules(listing).rules if r.uuid == target), None)
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

        try:
            reply = _call(db, client, FIREWALL_RULES_TOGGLE, {}, user, fw.id, request, params)
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Not saved: {exc.message}")
        want = "Enabled" if (cr.proposed or {}).get("enabled") else "Disabled"
        if not isinstance(reply, dict) or reply.get("result") != want:
            return _finish(db, cr, Status.failed, user, request, _validation_message(reply))
        saved = True

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
        try:
            after = _call(db, client, FIREWALL_RULES_LIST, None, user, fw.id, request)
            match = next((r for r in normalise_rules(after).rules if r.uuid == target), None)
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
