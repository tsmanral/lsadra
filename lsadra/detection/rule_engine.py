"""
LSADRA detection rules: one registry, with metadata, run on the live path.

Every rule is registered once with Sigma-shaped metadata (stable ID, version,
status, level, ATT&CK techniques from the pinned map, the canonical event types
it reads, known false positives) and a matcher over one feature row from
``lsadra.features.rule_features.build_rule_features``. The orchestrator calls
``evaluate`` for every scored event, so the rules that are deployed are exactly
the rules that are tested (``tests/test_rules.py``) and scored
(``docs/detection/scorecard.md``).

Levels follow Sigma. A ``medium`` or higher match raises an alert on its own; a
``low`` or ``informational`` match only names the technique when the anomaly
layers flag the event.

[V4 ENHANCEMENT — gap: multi-rule detection]
[GLASSWING ALIGNMENT — lateral movement detection]
[MYTHOS ALIGNMENT — cross-source behavioral sequences]
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from lsadra.detection.attack_map import Technique, technique
from lsadra.detection.event_types import canonical_event_type

logger = logging.getLogger(__name__)

# What evaluate_rules returns when no rule matches. Callers compare against it.
NO_RULE_MATCH: Tuple[str, str] = ("None", "N/A")
# Label for an anomaly flagged by layers 1-3 that no rule explains. It carries
# no ATT&CK technique: guessing one (this used to say T1190) mislabels the
# alert and, because "no match" was not distinguishable from a match, it also
# turned every scored event into an alert.
UNMAPPED_ANOMALY: Tuple[str, str] = ("Unknown Anomalous Activity", "N/A")

LEVELS = ("informational", "low", "medium", "high", "critical")
#: Lowest level that raises an alert without help from the anomaly layers.
ALERT_LEVEL = "medium"
_LEVEL_TO_SEVERITY = {
    "informational": "LOW", "low": "LOW", "medium": "MEDIUM",
    "high": "HIGH", "critical": "CRITICAL",
}
STATUSES = ("stable", "test", "experimental")


def level_rank(level: str) -> int:
    """Position of a Sigma level, 0 (informational) to 4 (critical)."""
    return LEVELS.index(level)


@dataclass(frozen=True)
class Rule:
    """Metadata for one detection rule (Sigma-shaped)."""

    id: str
    title: str
    code: str               # legacy alert type, e.g. BRUTE_FORCE
    version: int
    status: str
    level: str              # base level; a matcher may raise or lower it
    technique_ids: Tuple[str, ...]
    event_types: Tuple[str, ...]   # canonical types read; () = any
    description: str
    falsepositives: Tuple[str, ...]
    confidence: float        # author-set confidence that a match is the technique
    scenario: Optional[str] = None  # demo corpus scenario exercising it
    evaluated_by: str = "event"     # "event" (orchestrator) or "scheduler"
    matcher: Optional[Callable[[Dict[str, Any]], Optional["Hit"]]] = field(
        default=None, compare=False, repr=False)

    @property
    def techniques(self) -> Tuple[Technique, ...]:
        return tuple(technique(t) for t in self.technique_ids)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "version": self.version,
            "status": self.status, "level": self.level,
            "techniques": [t.as_dict() for t in self.techniques],
            "event_types": list(self.event_types), "description": self.description,
            "falsepositives": list(self.falsepositives), "confidence": self.confidence,
            "scenario": self.scenario, "evaluated_by": self.evaluated_by,
        }


@dataclass(frozen=True)
class Hit:
    """What a matcher returns: why it fired, and any change to the base level."""

    reason: str
    level: Optional[str] = None
    technique_id: Optional[str] = None


@dataclass
class RuleMatch:
    """A rule that fired on one row."""

    rule: Rule
    level: str
    reason: str
    technique: Technique
    source_ip: str = ""
    source_type: str = ""

    @property
    def severity(self) -> str:
        return _LEVEL_TO_SEVERITY[self.level]

    @property
    def raises_alert(self) -> bool:
        return level_rank(self.level) >= level_rank(ALERT_LEVEL)

    @property
    def tactics(self) -> List[str]:
        return [t.name for t in self.technique.tactics]

    def as_alert(self) -> Dict[str, Any]:
        """The V4 alert dict shape (``type``, ``severity``, ``mitre_id``, ...)."""
        return {
            "ip": self.source_ip or "unknown",
            "type": self.rule.code,
            "reason": self.reason,
            "severity": self.severity,
            "rule_weight": self.rule.confidence,
            "source_type": self.source_type,
            "mitre_id": self.technique.id,
            "mitre_name": self.technique.name,
            "mitre_tactics": self.tactics,
            "rule_id": self.rule.id,
            "rule_version": self.rule.version,
            "rule_title": self.rule.title,
            "level": self.level,
        }


RULES: Dict[str, Rule] = {}


def rule(**meta: Any) -> Callable:
    """Register a matcher with its metadata. Validates techniques at import."""
    def wrap(fn: Callable[[Dict[str, Any]], Optional[Hit]]) -> Callable:
        r = Rule(matcher=fn, **meta)
        if r.id in RULES:
            raise ValueError(f"duplicate rule id {r.id}")
        if r.level not in LEVELS or r.status not in STATUSES:
            raise ValueError(f"{r.id}: bad level or status")
        for tid in r.technique_ids:
            technique(tid)  # raises on unknown, revoked or deprecated IDs
        RULES[r.id] = r
        return fn
    return wrap


# ============================================================================
# Feature access (rows from build_rule_features, or hand-built dicts)
# ============================================================================

def _f(row: Dict[str, Any], *keys: str) -> float:
    """Largest numeric value among *keys* (missing / bad values count as 0)."""
    best = 0.0
    for key in keys:
        try:
            best = max(best, float(row.get(key) or 0))
        except (TypeError, ValueError):
            continue
    return best


def _et(row: Dict[str, Any]) -> str:
    return row.get("canonical_event_type") or canonical_event_type(row.get("event_type"))


def _is_event(row: Dict[str, Any], *types: str) -> bool:
    """
    True when the row's event is one of *types*.

    A hand-built row with no event type at all (V3/V4 API callers that pass
    only counters) is accepted, so window rules stay callable on bare counters.
    """
    if row.get("event_type") is None and row.get("canonical_event_type") is None:
        return True
    return _et(row) in types


def _failures_15m(row: Dict[str, Any]) -> float:
    return _f(row, "failures_15m", "failed_logins_last_15min")


def _users_15m(row: Dict[str, Any]) -> float:
    return _f(row, "unique_users_15m", "unique_usernames_per_ip")


# ============================================================================
# Credential access
# ============================================================================

@rule(
    id="lsadra-auth-credential-stuffing", title="Credential Stuffing", code="CREDENTIAL_STUFFING",
    version=2, status="stable", level="high", technique_ids=("T1110.004",),
    event_types=("auth_failure", "auth_success"), confidence=0.75, scenario="ssh_bruteforce",
    description="One source address fails logins against five or more accounts in 15 minutes.",
    falsepositives=("A shared jump host or NAT address where several users mistype passwords",),
)
def _credential_stuffing(row: Dict[str, Any]) -> Optional[Hit]:
    if not _is_event(row, "auth_failure"):
        return None
    users, fails = _users_15m(row), _failures_15m(row)
    if users >= 5 and fails > 5:
        return Hit(f"{fails:.0f} failed logins against {users:.0f} accounts in 15 min")
    return None


@rule(
    id="lsadra-auth-brute-force", title="Brute Force Attack", code="BRUTE_FORCE",
    version=2, status="stable", level="medium", technique_ids=("T1110.001",),
    event_types=("auth_failure",), confidence=0.85, scenario="ssh_bruteforce",
    description=("Repeated failed logins from one source address: 15 or more in 5 minutes is "
                 "critical, 5 or more in 5 minutes high, 8 or more in 15 minutes medium."),
    falsepositives=("A service retrying with an expired password",),
)
def _brute_force(row: Dict[str, Any]) -> Optional[Hit]:
    if not _is_event(row, "auth_failure"):
        return None
    f5, f15 = _f(row, "failed_logins_last_5min"), _failures_15m(row)
    if f5 >= 15:
        return Hit(f"{f5:.0f} failed logins in 5 min", level="critical")
    if f5 >= 5:
        return Hit(f"{f5:.0f} failed logins in 5 min", level="high")
    if f15 >= 8:
        return Hit(f"{f15:.0f} failed logins in 15 min")
    return None


@rule(
    id="lsadra-auth-low-and-slow", title="Low and Slow Attack", code="LOW_AND_SLOW",
    version=2, status="stable", level="medium", technique_ids=("T1110.001",),
    event_types=("auth_failure",), confidence=0.70,
    description=("6 to 20 failed logins from one address in 15 minutes, over 90 % failure rate, "
                 "paced under 5 attempts per 5 minutes to stay below burst thresholds."),
    falsepositives=("A misconfigured client retrying slowly",),
)
def _low_and_slow(row: Dict[str, Any]) -> Optional[Hit]:
    if not _is_event(row, "auth_failure"):
        return None
    f15 = _failures_15m(row)
    ratio = _f(row, "failure_ratio_15m", "failure_ratio")
    if 5 < f15 <= 20 and ratio > 0.9 and _f(row, "login_attempts_last_5min") < 5:
        return Hit(f"{f15:.0f} failed logins in 15 min at a slow pace")
    return None


@rule(
    id="lsadra-auth-success-after-failures", title="Successful Login After Repeated Failures",
    code="SUCCESS_AFTER_FAILURES", version=1, status="stable", level="high",
    technique_ids=("T1110.001",), event_types=("auth_success",), confidence=0.80,
    scenario="ssh_bruteforce",
    description="A login succeeds from an address with five or more failures in the last 15 minutes.",
    falsepositives=("A user who forgot a password and then got it right",),
)
def _success_after_failures(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) != "auth_success":
        return None
    fails = _failures_15m(row)
    if fails >= 5:
        return Hit(f"login succeeded after {fails:.0f} failures in 15 min from the same address")
    return None


@rule(
    id="lsadra-auth-off-hours-access", title="Anomalous Off-Hour Access", code="OFF_HOURS_ACCESS",
    version=2, status="stable", level="low", technique_ids=("T1078",),
    event_types=("auth_success", "session_open"), confidence=0.40,
    description=("A clean login between 22:00 and 06:00. Low level: it only names the "
                 "technique when the anomaly layers also flag the event."),
    falsepositives=("Shift workers, scheduled jobs, travel",),
)
def _off_hours_access(row: Dict[str, Any]) -> Optional[Hit]:
    if not _is_event(row, "auth_success", "session_open"):
        return None
    if _f(row, "successes_15m") > 0 and _f(row, "is_off_hours") == 1 and _failures_15m(row) == 0:
        return Hit("successful login outside 06:00-22:00 with no failures")
    return None


# ============================================================================
# Discovery, collection, exfiltration
# ============================================================================

@rule(
    id="lsadra-net-port-scan", title="Port Scan", code="PORT_SCAN",
    version=2, status="stable", level="high", technique_ids=("T1046",),
    event_types=("network_flow", "firewall_deny"), confidence=0.75,
    description="One source address reaches 15 or more destination ports in 10 minutes (50+ is critical).",
    falsepositives=("Vulnerability scanners and monitoring probes you run yourself",),
)
def _port_scan(row: Dict[str, Any]) -> Optional[Hit]:
    if not (_is_event(row, "network_flow", "firewall_deny") or row.get("source_type") == "network_flow"):
        return None
    ports = _f(row, "unique_dst_ports_10min", "unique_dst_ports_per_ip")
    if ports >= 50:
        return Hit(f"{ports:.0f} destination ports probed in 10 min", level="critical")
    if ports >= 15:
        return Hit(f"{ports:.0f} destination ports probed in 10 min")
    return None


@rule(
    id="lsadra-net-large-outbound-transfer", title="Large Outbound Transfer",
    code="LARGE_DATA_TRANSFER", version=2, status="stable", level="low",
    technique_ids=("T1048",), event_types=("network_flow",), confidence=0.50,
    scenario="data_movement_offhours",
    description=("More than 10 MB sent from one device to one destination in 30 minutes. Low "
                 "level for internal or documentation addresses (backups look the same); "
                 "medium when the destination is publicly routable."),
    falsepositives=("Backups, cloud sync, large uploads",),
)
def _large_transfer(row: Dict[str, Any]) -> Optional[Hit]:
    if not (_is_event(row, "network_flow") or row.get("source_type") == "network_flow"):
        return None
    sent = _f(row, "bytes_out_to_dest_30min", "total_bytes_out")
    if sent > 10_000_000:
        dest = row.get("dest_ip") or "one destination"
        level = "medium" if int(_f(row, "dest_is_global")) else None
        return Hit(f"{sent / 1e6:.1f} MB sent to {dest} in 30 min", level=level)
    return None


@rule(
    id="lsadra-file-hidden-staging-dir", title="Data Staged in a Hidden Directory",
    code="DATA_STAGING", version=1, status="test", level="medium",
    technique_ids=("T1074.001",),
    event_types=("process_exec", "archive_create", "file_write"), confidence=0.60,
    scenario="data_movement_offhours",
    description="A process or archive writes under a hidden directory in /tmp, /var/tmp or /dev/shm.",
    falsepositives=("Build tools and caches that use dot-directories in /tmp",),
)
def _hidden_staging(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) not in ("process_exec", "archive_create", "file_write"):
        return None
    path = str(row.get("artifact_path") or "")
    if int(_f(row, "artifact_in_hidden_dir")) and path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        return Hit(f"activity staged under hidden directory {path[:120]}")
    return None


# ============================================================================
# Execution
# ============================================================================

@rule(
    id="lsadra-proc-encoded-powershell", title="Encoded PowerShell Command", code="ENCODED_COMMAND",
    version=1, status="stable", level="high", technique_ids=("T1059.001",),
    event_types=("process_exec", "script_exec"), confidence=0.80,
    scenario="persistence_new_service",
    description="PowerShell started with an encoded (-EncodedCommand) script.",
    falsepositives=("Some management agents pass encoded commands",),
)
def _encoded_powershell(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) in ("process_exec", "script_exec") and int(_f(row, "encoded_command")):
        return Hit("PowerShell ran an encoded command")
    return None


@rule(
    id="lsadra-proc-lolbin-proxy-execution", title="Suspicious LOLBin Execution",
    code="SUSPICIOUS_PROCESS", version=2, status="stable", level="high",
    technique_ids=("T1218",), event_types=("process_exec",), confidence=0.75,
    description=("A signed system binary often abused to proxy execution (rundll32, mshta, "
                 "certutil, ...) runs with a suspicious command line or from an Office or "
                 "browser parent. Alone it is low level."),
    falsepositives=("Installers and IT scripts that call these binaries legitimately",),
)
def _lolbin(row: Dict[str, Any]) -> Optional[Hit]:
    if not (_is_event(row, "process_exec") or row.get("source_type") == "endpoint"):
        return None
    if _f(row, "known_lolbin", "lolbin_usage_count") < 1:
        return None
    if int(_f(row, "suspicious_cmdline")) or int(_f(row, "unusual_parent")):
        return Hit("LOLBin ran with a suspicious command line or parent")
    return Hit("LOLBin execution", level="low")


@rule(
    id="lsadra-proc-suspicious-cmdline", title="Suspicious Command Line", code="SUSPICIOUS_CMDLINE",
    version=1, status="stable", level="medium", technique_ids=("T1059",),
    event_types=("process_exec",), confidence=0.60,
    description=("A command line with a download cradle, inline base64 decoding, or "
                 "execution from a temp directory."),
    falsepositives=("Install scripts that download and run tooling",),
)
def _suspicious_cmdline(row: Dict[str, Any]) -> Optional[Hit]:
    if not (_is_event(row, "process_exec") or row.get("source_type") == "endpoint"):
        return None
    if _f(row, "suspicious_cmdline", "suspicious_process_count") >= 1:
        return Hit("command line matches a download, decode or temp-execution pattern")
    return None


# ============================================================================
# Persistence and defence impairment
# ============================================================================

@rule(
    id="lsadra-persist-service-install", title="New Service Installed", code="PERSISTENCE",
    version=2, status="stable", level="medium", technique_ids=("T1543.003", "T1543.002"),
    event_types=("service_install",), confidence=0.85, scenario="persistence_new_service",
    description=("A Windows service or systemd unit was installed; high level when its binary "
                 "sits in a user-writable directory."),
    falsepositives=("Software installs and updates",),
)
def _service_install(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) != "service_install":
        return None
    tid = "T1543.003" if int(_f(row, "windows_artifact")) else "T1543.002"
    path = str(row.get("artifact_path") or "")
    if int(_f(row, "artifact_in_user_writable_dir")):
        return Hit(f"service installed from user-writable path {path[:120]}", "high", tid)
    return Hit("new service installed", technique_id=tid)


@rule(
    id="lsadra-persist-service-registry", title="Service Registry Key Modified",
    code="PERSISTENCE", version=1, status="stable", level="medium", technique_ids=("T1543.003",),
    event_types=("registry_set",), confidence=0.70, scenario="persistence_new_service",
    description="A value under HKLM\\SYSTEM\\CurrentControlSet\\Services was set.",
    falsepositives=("Driver and service updates",),
)
def _service_registry(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) == "registry_set" and int(_f(row, "registry_service_key")):
        return Hit("service configuration changed in the registry")
    return None


@rule(
    id="lsadra-persist-registry-run-key", title="Autostart Registry Key Modified",
    code="PERSISTENCE", version=1, status="stable", level="high", technique_ids=("T1547.001",),
    event_types=("registry_set",), confidence=0.80,
    description="A Run, RunOnce or Winlogon autostart value was set.",
    falsepositives=("Applications that legitimately start at logon",),
)
def _run_key(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) == "registry_set" and int(_f(row, "registry_autostart_key")):
        return Hit("autostart registry value set")
    return None


@rule(
    id="lsadra-persist-scheduled-task", title="Scheduled Task Created", code="PERSISTENCE",
    version=2, status="stable", level="medium", technique_ids=("T1053.005",),
    event_types=("scheduled_task_create",), confidence=0.80, scenario="persistence_new_service",
    description="A Windows scheduled task was created; high level when it runs from a user-writable path.",
    falsepositives=("Software updaters register scheduled tasks",),
)
def _scheduled_task(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) != "scheduled_task_create":
        return None
    if int(_f(row, "artifact_in_user_writable_dir")):
        return Hit("scheduled task runs a binary from a user-writable path", level="high")
    return Hit("scheduled task created")


@rule(
    id="lsadra-persist-cron-modified", title="Crontab Modified", code="PERSISTENCE",
    version=2, status="stable", level="medium", technique_ids=("T1053.003",),
    event_types=("cron_modified",), confidence=0.70,
    description="A crontab was created or edited.",
    falsepositives=("Administrators editing their own crontabs",),
)
def _cron_modified(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) == "cron_modified":
        return Hit("crontab created or edited")
    return None


@rule(
    id="lsadra-persist-local-account-created", title="Local Account Created", code="PERSISTENCE",
    version=1, status="stable", level="medium", technique_ids=("T1136.001",),
    event_types=("account_create",), confidence=0.70,
    description="A local user account was created.",
    falsepositives=("Planned onboarding",),
)
def _account_created(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) == "account_create":
        return Hit("local user account created")
    return None


@rule(
    id="lsadra-impair-event-log-cleared", title="Event Log Cleared", code="DEFENSE_IMPAIRMENT",
    version=1, status="stable", level="high", technique_ids=("T1685.005",),
    event_types=("log_cleared",), confidence=0.90,
    description="A Windows event log was cleared (Security 1102 or System 104).",
    falsepositives=("Rare; some imaging or reset procedures",),
)
def _log_cleared(row: Dict[str, Any]) -> Optional[Hit]:
    if _et(row) == "log_cleared":
        return Hit("event log cleared")
    return None


# Lateral movement is a database query run by the scheduler, not a row
# matcher; it is registered here so its metadata and technique are checked
# with everything else.
RULES["lsadra-lateral-remote-services"] = Rule(
    id="lsadra-lateral-remote-services", title="Lateral Movement", code="LATERAL_MOVEMENT",
    version=2, status="stable", level="high", technique_ids=("T1021",),
    event_types=(), confidence=0.85, evaluated_by="scheduler",
    description="One source address reaches 3 or more users or devices in 30 minutes.",
    falsepositives=("Administrators and automation that log in to many machines",),
)
technique("T1021")


# ============================================================================
# Evaluation
# ============================================================================

def _apply_cross_source(match: RuleMatch, row: Dict[str, Any]) -> RuleMatch:
    """Raise the level one step when the address is active in 2+ source families."""
    if not int(_f(row, "cross_source_activity")):
        return match
    new_level = LEVELS[min(level_rank(match.level) + 1, len(LEVELS) - 1)]
    return replace(match, level=new_level,
                   reason=match.reason + "; the same address is active in another log source")


def evaluate(row: Dict[str, Any]) -> List[RuleMatch]:
    """
    Every event rule that matches *row*, best first.

    Best = highest level, then highest confidence, then registry order. Cross-
    source elevation is applied to the best match only.
    """
    matches: List[Tuple[int, float, int, RuleMatch]] = []
    for order, r in enumerate(RULES.values()):
        if r.evaluated_by != "event" or r.matcher is None:
            continue
        try:
            hit = r.matcher(row)
        except Exception:
            logger.exception("Rule %s raised on a row; skipping it", r.id)
            continue
        if hit is None:
            continue
        m = RuleMatch(
            rule=r, level=hit.level or r.level, reason=hit.reason,
            technique=technique(hit.technique_id or r.technique_ids[0]),
            source_ip=str(row.get("source_ip") or ""),
            source_type=str(row.get("event_source") or row.get("source_type") or ""),
        )
        matches.append((level_rank(m.level), r.confidence, -order, m))
    matches.sort(key=lambda t: t[:3], reverse=True)
    result = [t[3] for t in matches]
    if result:
        result[0] = _apply_cross_source(result[0], row)
    return result


def best_match(row: Dict[str, Any]) -> Optional[RuleMatch]:
    """The highest-ranked match for *row*, or ``None``."""
    found = evaluate(row)
    return found[0] if found else None


def evaluate_rules(feature_row: Dict[str, Any]) -> Tuple[str, str]:
    """
    (Rule title, ATT&CK technique) of the best match, or ``NO_RULE_MATCH``.

    Kept for callers of the V3 API; new code uses ``evaluate``.
    """
    m = best_match(feature_row)
    return (m.rule.title, m.technique.id) if m else NO_RULE_MATCH


def evaluate_all_v4_rules(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The best match as a V4 alert dict, or ``None``. Kept for V4 callers."""
    m = best_match(features)
    return m.as_alert() if m else None


def _single(rule_id: str) -> Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]:
    r = RULES[rule_id]

    def check(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        hit = r.matcher(features) if r.matcher else None
        if hit is None:
            return None
        return RuleMatch(
            rule=r, level=hit.level or r.level, reason=hit.reason,
            technique=technique(hit.technique_id or r.technique_ids[0]),
            source_ip=str(features.get("source_ip") or ""),
            source_type=str(features.get("event_source") or features.get("source_type") or ""),
        ).as_alert()

    check.__name__ = f"check_{rule_id}"
    return check


# V4 per-rule entry points, kept for existing callers.
check_brute_force_v4 = _single("lsadra-auth-brute-force")
check_credential_stuffing = _single("lsadra-auth-credential-stuffing")
check_low_and_slow = _single("lsadra-auth-low-and-slow")
check_port_scan = _single("lsadra-net-port-scan")
check_large_transfer = _single("lsadra-net-large-outbound-transfer")
check_suspicious_process = _single("lsadra-proc-lolbin-proxy-execution")


def check_persistence(features: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Best persistence-rule match as a V4 alert dict, or ``None``."""
    for m in evaluate(features):
        if m.rule.code == "PERSISTENCE":
            return m.as_alert()
    return None


def apply_cross_source_elevation(
    alert: Dict[str, Any], features: Dict[str, Any]
) -> Dict[str, Any]:
    """Raise a V4 alert dict's severity one step on cross-source activity."""
    if not features.get("cross_source_activity"):
        return alert
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    try:
        idx = order.index(alert.get("severity", "LOW"))
        alert["severity"] = order[min(idx + 1, len(order) - 1)]
    except ValueError:
        pass
    alert["reason"] = alert.get("reason", "") + " | Multi-source activity corroborates threat."
    alert["rule_weight"] = min(alert.get("rule_weight", 0.5) + 0.10, 1.0)
    return alert


# ============================================================================
# Lateral movement detection (SQLite)
# ============================================================================

def detect_lateral_movement(
    db_conn: sqlite3.Connection, ip: str
) -> Optional[Dict[str, Any]]:
    """
    Query the database for lateral movement signals from a source IP.

    Flags if the same IP accessed 3+ distinct users OR 3+ distinct devices
    within the last 30 minutes.

    The window is an ISO cutoff computed here, not SQLite's
    ``datetime('now', ...)``: ingestion stores ``isoformat()`` of a UTC time
    (``YYYY-MM-DDTHH:MM:SS+00:00``), and compared as text against
    ``YYYY-MM-DD HH:MM:SS`` (``'T' > ' '``) every event from the current day
    would fall inside the window.

    [V4 ENHANCEMENT — gap: relationship modeling]
    [GLASSWING ALIGNMENT — lateral movement detection]

    Args:
        db_conn: Active SQLite3 connection.
        ip:      Source IP to investigate.

    Returns:
        Alert dict if lateral movement detected, else None.
    """
    sql = """
        SELECT source_ip,
               COUNT(DISTINCT effective_username) AS unique_users,
               COUNT(DISTINCT device_id)          AS unique_devices,
               GROUP_CONCAT(DISTINCT effective_username) AS affected_users,
               GROUP_CONCAT(DISTINCT device_id)          AS affected_devices
        FROM normalized_events
        WHERE source_ip = ?
          AND timestamp >= ?
        GROUP BY source_ip
        HAVING unique_users >= 3 OR unique_devices >= 3
    """
    try:
        cutoff = (datetime.utcnow() - timedelta(minutes=30)).isoformat()
        row = db_conn.execute(sql, (ip, cutoff)).fetchone()
        if row is None:
            return None
        d = dict(row)
        return {
            "ip":              ip,
            "type":            "LATERAL_MOVEMENT",
            "reason":          (
                f"IP {ip} accessed {d['unique_users']} users and "
                f"{d['unique_devices']} devices in 30 min"
            ),
            "severity":        "HIGH",
            "rule_weight":     0.85,
            "source_type":     "multi_source",
            "mitre_id":        "T1021",
            "mitre_name":      "Remote Services",
            "affected_users":  d.get("affected_users", ""),
            "affected_devices": d.get("affected_devices", ""),
        }
    except Exception:
        logger.exception("detect_lateral_movement failed for IP %s", ip)
        return None
