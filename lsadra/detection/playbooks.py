"""
LSADRA — response playbooks.

A playbook is guidance for the analyst: an ordered list of steps, each with a
suggested command the analyst may run *themselves*. LSADRA never runs these
commands; nothing here touches a monitored host.

Commands use fixed placeholders (``<SOURCE_IP>``, ``<HOST>``, ``<USERNAME>``)
and are never filled in with values taken from logs. Those values are attacker
influenced: interpolating a user name such as ``x"; rm -rf ~`` into a command
an analyst copies would turn a log line into a shell injection. The incident's
real values are returned next to the steps as plain data instead.

``incident_manager`` assigns a playbook name to new incidents by attack type;
incidents without one get :data:`DEFAULT_PLAYBOOK`.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

DEFAULT_PLAYBOOK = "GENERIC_TRIAGE"

_PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "AD_ELEVATION_RESPONSE": {
        "title": "Privilege escalation response",
        "description": "Contain an account that gained administrator rights it should not have.",
        "steps": [
            {
                "label": "Confirm the account and its new group memberships",
                "description": "Check which privileged groups the account joined and when.",
                "command": "Get-ADUser -Identity <USERNAME> -Properties MemberOf | Select-Object -ExpandProperty MemberOf",
            },
            {
                "label": "Isolate the source host",
                "description": "Cut the host off the network with your EDR or switch port before changing the account.",
                "command": None,
            },
            {
                "label": "Remove the privileged group memberships",
                "description": "Take the account out of every group it was added to without approval.",
                "command": "Remove-ADGroupMember -Identity \"Domain Admins\" -Members <USERNAME>",
            },
            {
                "label": "Reset the password and end sessions",
                "description": "Force a password reset and revoke existing sessions and tokens for the account.",
                "command": "Set-ADAccountPassword -Identity <USERNAME> -Reset",
            },
            {
                "label": "Record what happened",
                "description": "Write down the timeline and actions in the incident notes, then resolve it.",
                "command": None,
            },
        ],
    },
    "BRUTE_FORCE_RESPONSE": {
        "title": "Brute-force response",
        "description": "Stop repeated login attempts and check whether any of them succeeded.",
        "steps": [
            {
                "label": "Check for a successful login from the source",
                "description": "A success after many failures means the account may be compromised.",
                "command": "grep \"Accepted\" /var/log/auth.log | grep <SOURCE_IP>",
            },
            {
                "label": "Block the source address",
                "description": "Add a firewall rule for the attacking address.",
                "command": "sudo ufw deny from <SOURCE_IP>",
            },
            {
                "label": "Review the targeted accounts",
                "description": "Lock or reset any account the attacker may have guessed.",
                "command": None,
            },
            {
                "label": "Harden the login path",
                "description": "Require keys or MFA and rate-limit the service.",
                "command": None,
            },
        ],
    },
    "RANSOMWARE_RESPONSE": {
        "title": "Ransomware containment",
        "description": "Contain a host that shows file-encryption or ransomware behaviour.",
        "steps": [
            {
                "label": "Isolate the host",
                "description": "Disconnect it from the network now; do not power it off, memory holds evidence.",
                "command": None,
            },
            {
                "label": "Preserve evidence",
                "description": "Capture memory and a disk image before cleaning anything.",
                "command": None,
            },
            {
                "label": "Block outbound traffic to the source",
                "description": "Block the address the host was talking to at the perimeter firewall.",
                "command": "sudo ufw deny out to <SOURCE_IP>",
            },
            {
                "label": "Restore from a clean backup",
                "description": "Restore affected files from the last backup taken before the first alert.",
                "command": None,
            },
            {
                "label": "Re-image the host",
                "description": "Rebuild it from a known-good image before it rejoins the network.",
                "command": None,
            },
        ],
    },
    DEFAULT_PLAYBOOK: {
        "title": "General triage",
        "description": "Work out whether the activity is malicious and contain it if it is.",
        "steps": [
            {
                "label": "Read the timeline",
                "description": "Go through every alert in this incident and the raw log lines behind them.",
                "command": None,
            },
            {
                "label": "Check the source address",
                "description": "Look the source up in Threat Intel and check which other hosts it reached.",
                "command": None,
            },
            {
                "label": "Decide: real threat or false positive",
                "description": "Label the alerts in Feedback so the detector learns from your decision.",
                "command": None,
            },
            {
                "label": "Contain if needed and record the outcome",
                "description": "Isolate the host or block the source if it is real, then resolve the incident with a note.",
                "command": None,
            },
        ],
    },
}


def get_playbook(name: Optional[str]) -> Dict[str, Any]:
    """Return a copy of the named playbook, or the default one if unknown/empty."""
    key = name if name in _PLAYBOOKS else DEFAULT_PLAYBOOK
    book = copy.deepcopy(_PLAYBOOKS[key])
    book["name"] = key
    for i, step in enumerate(book["steps"], start=1):
        step["id"] = i
    return book


def list_playbook_names() -> List[str]:
    return list(_PLAYBOOKS)
