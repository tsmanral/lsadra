"""
The closed list of event types LSADRA detects on, mapped to OCSF and ECS.

Event schema v1 (ADR 0006) keeps ``event_type`` a free string at the ingestion
boundary, so out-of-tree collectors keep working. Detection does not: every
stored event is resolved to one of the canonical types below before features
and rules see it. In-repo parsers, agents and the demo corpus emit canonical
names directly; older names (``ssh_failed_password``, ``process_create``, ...)
resolve through ``ALIASES``; anything else becomes ``other``, which no rule may
key on. ``tests/test_event_types.py`` enforces all of that.

Each type records the OCSF 1.9 class and activity it corresponds to and the ECS
``event.category`` / ``event.type`` values, so a future OCSF or ECS export is a
lookup, not a guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

#: OCSF schema version the class UIDs below were checked against.
OCSF_VERSION = "1.9.0"
#: ECS version the category/type values below were checked against.
ECS_VERSION = "9.5"

OTHER = "other"


@dataclass(frozen=True)
class EventType:
    """One canonical event type."""

    name: str
    description: str
    #: Coarse source family, used by rules and cross-source correlation:
    #: auth | endpoint | network | system.
    source: str
    ocsf_class_uid: int
    ocsf_class_name: str
    ocsf_activity: str
    ecs_category: Tuple[str, ...]
    ecs_type: Tuple[str, ...]
    #: "success" / "failure" when the type itself fixes the outcome, else None.
    outcome: Optional[str] = None


def _t(name, description, source, ocsf, activity, ecs_category, ecs_type, outcome=None):
    uid, cls = ocsf
    return EventType(
        name, description, source, uid, cls, activity, tuple(ecs_category), tuple(ecs_type), outcome
    )


_AUTHN = (3002, "Authentication")
_ACCOUNT = (3001, "Account Change")
_GROUP = (3006, "Group Management")
_PROCESS = (1007, "Process Activity")
_SCRIPT = (1009, "Script Activity")
_FILE = (1001, "File System Activity")
_MODULE = (1005, "Module Activity")
_JOB = (1006, "Scheduled Job Activity")
_EVENT_LOG = (1008, "Event Log Activity")
_REGISTRY = (201002, "Registry Value Activity")  # OCSF Windows extension
_WIN_SERVICE = (201004, "Windows Service Activity")  # OCSF Windows extension
_NETWORK = (4001, "Network Activity")
_DNS = (4003, "DNS Activity")
_CONFIG_STATE = (5019, "Device Config State Change")
_BASE = (0, "Base Event")

_TYPES = [
    # Authentication and identity
    _t(
        "auth_success",
        "A logon or authentication succeeded",
        "auth",
        _AUTHN,
        "Logon",
        ["authentication"],
        ["start"],
        "success",
    ),
    _t(
        "auth_failure",
        "A logon or authentication failed",
        "auth",
        _AUTHN,
        "Logon",
        ["authentication"],
        ["start"],
        "failure",
    ),
    _t(
        "session_open",
        "An interactive session opened",
        "auth",
        _AUTHN,
        "Logon",
        ["session"],
        ["start"],
        "success",
    ),
    _t(
        "session_close",
        "An interactive session closed",
        "auth",
        _AUTHN,
        "Logoff",
        ["session"],
        ["end"],
    ),
    _t(
        "privileged_logon",
        "Special privileges were assigned to a new logon",
        "auth",
        _AUTHN,
        "Logon",
        ["authentication", "iam"],
        ["admin"],
        "success",
    ),
    _t(
        "account_create",
        "A local user account was created",
        "auth",
        _ACCOUNT,
        "Create",
        ["iam"],
        ["user", "creation"],
    ),
    _t(
        "group_member_add",
        "A user was added to a group",
        "auth",
        _GROUP,
        "Add User",
        ["iam"],
        ["group", "change"],
    ),
    # Process and script execution
    _t("process_exec", "A process started", "endpoint", _PROCESS, "Launch", ["process"], ["start"]),
    _t(
        "sudo_exec",
        "A command ran through sudo or su",
        "endpoint",
        _PROCESS,
        "Launch",
        ["process"],
        ["start"],
    ),
    _t(
        "script_exec",
        "A script block or script ran (e.g. PowerShell 4104)",
        "endpoint",
        _SCRIPT,
        "Execute",
        ["process"],
        ["info"],
    ),
    _t("cron_job", "A scheduled job ran", "system", _PROCESS, "Launch", ["process"], ["start"]),
    # Files, registry, modules
    _t("file_access", "A file was read", "endpoint", _FILE, "Read", ["file"], ["access"]),
    _t(
        "file_write",
        "A file was created or changed",
        "endpoint",
        _FILE,
        "Update",
        ["file"],
        ["change"],
    ),
    _t("file_delete", "A file was deleted", "endpoint", _FILE, "Delete", ["file"], ["deletion"]),
    _t(
        "archive_create",
        "An archive was written",
        "endpoint",
        _FILE,
        "Create",
        ["file"],
        ["creation"],
    ),
    _t(
        "registry_set",
        "A registry value was set",
        "endpoint",
        _REGISTRY,
        "Set",
        ["registry"],
        ["change"],
    ),
    _t(
        "module_load",
        "A library, DLL or kernel module was loaded",
        "endpoint",
        _MODULE,
        "Load",
        ["library"],
        ["start"],
    ),
    # Services, scheduled jobs, logs (persistence and defence impairment)
    _t(
        "service_install",
        "A service or systemd unit was installed",
        "system",
        _WIN_SERVICE,
        "Create",
        ["configuration"],
        ["creation"],
    ),
    _t(
        "service_start",
        "A service started",
        "system",
        _WIN_SERVICE,
        "Start",
        ["process"],
        ["start"],
    ),
    _t("service_stop", "A service stopped", "system", _WIN_SERVICE, "Stop", ["process"], ["end"]),
    _t(
        "service_change",
        "A service was reconfigured",
        "system",
        _WIN_SERVICE,
        "Reconfigure",
        ["configuration"],
        ["change"],
    ),
    _t(
        "scheduled_task_create",
        "A scheduled task was created",
        "system",
        _JOB,
        "Create",
        ["configuration"],
        ["creation"],
    ),
    _t(
        "cron_modified",
        "A crontab was created or edited",
        "system",
        _JOB,
        "Update",
        ["configuration"],
        ["change"],
    ),
    _t(
        "log_cleared",
        "An event log was cleared",
        "system",
        _EVENT_LOG,
        "Clear",
        ["configuration"],
        ["deletion"],
    ),
    _t(
        "log_forward",
        "A forwarded log record wrapping another event",
        "system",
        _BASE,
        "Other",
        ["configuration"],
        ["info"],
    ),
    _t(
        "package_update",
        "A software package was installed or upgraded",
        "system",
        _BASE,
        "Other",
        ["package"],
        ["installation"],
    ),
    _t(
        "interface_change",
        "A network interface changed state",
        "system",
        _CONFIG_STATE,
        "Other",
        ["host"],
        ["change"],
    ),
    # Network
    _t(
        "network_flow",
        "A network connection or flow",
        "network",
        _NETWORK,
        "Traffic",
        ["network"],
        ["connection"],
    ),
    _t(
        "firewall_deny",
        "A firewall refused a connection",
        "network",
        _NETWORK,
        "Refuse",
        ["network"],
        ["connection", "denied"],
        "failure",
    ),
    _t("dns_query", "A DNS lookup", "network", _DNS, "Query", ["network"], ["protocol"]),
    # Catch-all: stored and shown, never matched by a rule
    _t(OTHER, "Anything outside this list", "system", _BASE, "Other", [], ["info"]),
]

EVENT_TYPES: Dict[str, EventType] = {t.name: t for t in _TYPES}

#: Older or source-specific names that resolve to a canonical type.
ALIASES: Dict[str, str] = {
    # V3 SSH parser / Python Linux agent
    "sudo_command": "sudo_exec",
    "session_opened": "session_open",
    "session_closed": "session_close",
    # Syslog parser (before canonical names)
    "privilege_escalation": "sudo_exec",
    "kernel_module_load": "module_load",
    "network_interface_change": "interface_change",
    "syslog_event": OTHER,
    # Windows parsers (before canonical names)
    "windows_logon_success": "auth_success",
    "windows_logon_failure": "auth_failure",
    "windows_explicit_credential": "auth_success",
    "windows_special_logon": "privileged_logon",
    "windows_unknown": OTHER,
    "user_account_created": "account_create",
    "service_installed": "service_install",
    "scheduled_task_created": "scheduled_task_create",
    # Endpoint and network parsers (before canonical names)
    "process_create": "process_exec",
    "registry_write": "registry_set",
    "dll_load": "module_load",
    "network_connect": "network_flow",
    "connection": "network_flow",
    "unknown": OTHER,
}

#: Old names whose meaning depends on the outcome the parser reported.
_OUTCOME_ALIASES: Dict[str, Tuple[str, str]] = {
    "login_attempt": ("auth_success", "auth_failure"),
}

#: Prefix families: ``ssh_failed_password``, ``ssh_accepted_publickey``, ...
_PREFIX_ALIASES: Tuple[Tuple[str, str], ...] = (
    ("ssh_failed_", "auth_failure"),
    ("ssh_invalid_", "auth_failure"),
    ("ssh_accepted_", "auth_success"),
)


def canonical_event_type(raw: object, success: Optional[bool] = None) -> str:
    """
    Resolve a stored or parsed ``event_type`` to its canonical name.

    Matching is exact (after trimming surrounding whitespace and lower-casing):
    look-alike strings with invisible or homoglyph characters, which the demo
    injection corpus contains, resolve to ``other`` rather than to a real type.
    """
    if not isinstance(raw, str):
        return OTHER
    name = raw.strip().lower()
    if name in EVENT_TYPES:
        return name
    if name in ALIASES:
        return ALIASES[name]
    if name in _OUTCOME_ALIASES:
        ok, failed = _OUTCOME_ALIASES[name]
        if success is None:
            return OTHER
        return ok if success else failed
    for prefix, target in _PREFIX_ALIASES:
        if name.startswith(prefix):
            return target
    return OTHER


def event_type_info(raw: object, success: Optional[bool] = None) -> EventType:
    """The ``EventType`` record for any stored or parsed name."""
    return EVENT_TYPES[canonical_event_type(raw, success)]


def is_failure(name: str) -> bool:
    """True for canonical types whose outcome is a failure."""
    return EVENT_TYPES.get(name, EVENT_TYPES[OTHER]).outcome == "failure"


def is_success(name: str) -> bool:
    """True for canonical types whose outcome is a success."""
    return EVENT_TYPES.get(name, EVENT_TYPES[OTHER]).outcome == "success"
