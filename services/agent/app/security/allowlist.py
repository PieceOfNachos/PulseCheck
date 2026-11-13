"""Code-side allowlist for model-proposed actions.

The planner's output is never trusted: whatever it proposes is filtered here, and
whatever a human approves is checked again before the executor runs it.
"""

from __future__ import annotations

from app.contracts import ALLOWED_ACTIONS, ActionName, ProposedAction


def _normalise(name: object) -> str:
    return name.strip().lower() if isinstance(name, str) else ""


def filter_actions(
    proposed: list[ProposedAction],
) -> tuple[list[ProposedAction], list[ProposedAction]]:
    """Split proposals into ``(allowed, rejected)``.

    Allowed names are normalised and deduplicated (first reason wins). ``no_action``
    is dropped when any real action survives. Rejected keeps the original proposal
    so the audit trail shows exactly what the model asked for.
    """
    allowed: list[ProposedAction] = []
    rejected: list[ProposedAction] = []
    seen: set[str] = set()

    for item in proposed:
        name = _normalise(item.action)
        if name not in ALLOWED_ACTIONS:
            rejected.append(item)
            continue
        if name in seen:
            continue
        seen.add(name)
        allowed.append(ProposedAction(action=name, reason=item.reason))

    no_action = ActionName.NO_ACTION.value
    if any(a.action != no_action for a in allowed):
        allowed = [a for a in allowed if a.action != no_action]
    return allowed, rejected


def validate_approved(approved: list[str], proposed: list[str]) -> list[str]:
    """Return the approved names that were both proposed and allowlisted, deduplicated."""
    proposed_set = {_normalise(p) for p in proposed} & ALLOWED_ACTIONS
    result: list[str] = []
    for name in approved:
        norm = _normalise(name)
        if norm in proposed_set and norm not in result:
            result.append(norm)
    return result
