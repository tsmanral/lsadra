"""
Action broker (G-30): the only path from an LLM recommendation to an action.

It can do exactly one thing with a recommendation: store it as a PROPOSED
action on the incident. It has no execute function. A human (ADMIN) approves
or rejects a proposal; approving records the decision and nothing else.
Carrying out an approved action belongs to the response layer, which stays
dry-run by default and needs human approval for live actions (CLAUDE.md).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from lsadra.llm.guardrails import ALLOWED_ACTIONS, TriageResult

DECISIONS = ("APPROVED", "REJECTED")


def propose_actions(incident_id: int, triage: TriageResult, source: str = "llm") -> List[int]:
    """Store each validated recommendation as a PROPOSED action. Returns their ids."""
    from lsadra.explainability.sanitize import clean_field
    from lsadra.storage.database import insert_proposed_action

    ids = []
    for act in triage.recommended_actions:
        if (
            act["action"] not in ALLOWED_ACTIONS
        ):  # validated already; never trust twice-removed input
            continue
        ids.append(
            insert_proposed_action(
                incident_id=int(incident_id),
                action=act["action"],
                target=clean_field(act["target"], 128),
                rationale=clean_field(act["rationale"], 300),
                source=source,
                evidence_event_ids=list(triage.cited_event_ids),
            )
        )
    return ids


def list_proposals(
    incident_id: Optional[int] = None, status: Optional[str] = None
) -> List[Dict[str, Any]]:
    from lsadra.storage.database import get_proposed_actions

    return get_proposed_actions(incident_id=incident_id, status=status)


def decide(proposal_id: int, decision: str, decided_by: str) -> bool:
    """Record a human decision on a PROPOSED action. Returns False if it was not pending."""
    from lsadra.storage.database import decide_proposed_action

    decision = decision.upper()
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}")
    if not decided_by:
        raise ValueError("a decision needs the deciding user")
    return decide_proposed_action(proposal_id, decision, decided_by)
