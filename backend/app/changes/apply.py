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
from app.changes.states import Status
from app.core.config import Settings
from app.core.crypto import CredentialDecryptionError
from app.core.logging import get_logger
from app.db.models import ChangeRequest, Firewall
from app.opnsense.client import OPNsenseClient
from app.opnsense.errors import FirewallError
from app.opnsense.normalise import normalise_aliases
from app.opnsense.registry.entries import (
    FIREWALL_ALIASES_ADD,
    FIREWALL_ALIASES_LIST,
    FIREWALL_ALIASES_RECONFIGURE,
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
    return "The firewall did not save the alias"


def apply_alias_create(
    db: Session,
    *,
    change_id: uuid.UUID,
    user: CurrentUser,
    settings: Settings,
    request: Request,
    confirm_name: str | None,
) -> ChangeRequest:
    from app.api.firewalls import open_client  # local: avoids an import cycle with the router

    cr = db.get(ChangeRequest, change_id)
    if cr is None:
        raise ApplyRefused("Change request not found")
    if cr.kind != "alias" or cr.action != "create" or not cr.proposed:
        raise ApplyRefused("Only alias creation can be applied in this release")
    if cr.high_risk and confirm_name != cr.proposed.get("name"):
        raise ApplyRefused("Type the alias name to confirm this high-risk change")
    fw = db.get(Firewall, cr.firewall_id)
    if fw is None:
        raise ApplyRefused("Firewall not found")
    firewall_id = fw.id

    # Serialise starts per firewall; the "applying" status then blocks everyone else.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": str(firewall_id)})
    busy = db.scalar(
        select(func.count())
        .select_from(ChangeRequest)
        .where(
            ChangeRequest.firewall_id == firewall_id,
            ChangeRequest.status == Status.applying.value,
            ChangeRequest.id != cr.id,
        )
    )
    if busy:
        db.rollback()
        raise ApplyRefused("Another change is being applied to this firewall")
    service.transition(db, cr, Status.applying, user=user, request=request)
    db.commit()

    proposed = dict(cr.proposed or {})
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
        existing = {a.name for a in normalise_aliases(listing).aliases}
        if proposed["name"] in existing:
            return _finish(
                db,
                cr,
                Status.stale,
                user,
                request,
                "An alias with this name now exists on the firewall; nothing was changed",
            )

        # 3. save
        try:
            reply = _call(
                db, client, FIREWALL_ALIASES_ADD, _payload(proposed), user, fw.id, request
            )
        except FirewallError as exc:
            return _finish(db, cr, Status.failed, user, request, f"Not saved: {exc.message}")
        if not isinstance(reply, dict) or reply.get("result") != "saved":
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
                f"The alias is saved on the firewall but NOT active: {exc.message}",
            )
        if not isinstance(result, dict) or result.get("status") != "ok":
            return _finish(
                db,
                cr,
                Status.failed,
                user,
                request,
                "The alias is saved on the firewall but NOT active: activation was not confirmed",
            )

        # 5. read back (best effort) and finish
        snapshot: dict[str, Any] | None
        try:
            after = _call(db, client, FIREWALL_ALIASES_LIST, None, user, fw.id, request)
            match = next(
                (a for a in normalise_aliases(after).aliases if a.name == proposed["name"]), None
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
) -> Any:
    """Run one registry operation and audit it, whatever the outcome."""
    action = f"firewall.{operation_id}"
    try:
        result = anyio.from_thread.run(client.execute, operation_id, payload)
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
