"""Status machine for change requests (ADR-0005). Pure data, no I/O."""

import enum


class Status(enum.StrEnum):
    draft = "draft"
    validated = "validated"
    in_review = "in_review"
    approved = "approved"
    applying = "applying"
    applied = "applied"
    rejected = "rejected"
    cancelled = "cancelled"
    failed = "failed"
    stale = "stale"


TRANSITIONS: dict[Status, frozenset[Status]] = {
    Status.draft: frozenset({Status.validated, Status.cancelled}),
    Status.validated: frozenset({Status.draft, Status.in_review, Status.cancelled}),
    Status.in_review: frozenset({Status.approved, Status.rejected, Status.cancelled}),
    Status.approved: frozenset({Status.applying, Status.cancelled}),
    Status.applying: frozenset({Status.applied, Status.failed, Status.stale}),
    Status.applied: frozenset(),
    Status.rejected: frozenset(),
    Status.cancelled: frozenset(),
    Status.failed: frozenset(),
    Status.stale: frozenset(),
}

TERMINAL = frozenset(s for s, targets in TRANSITIONS.items() if not targets)


def can_transition(current: Status, target: Status) -> bool:
    return target in TRANSITIONS[current]
