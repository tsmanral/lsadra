"""
Sigma 2.0 rules, evaluated in-process (audit G-28).

Rules are standard Sigma YAML under ``lsadra/detection/sigma_rules/``:
``sigmahq/`` holds rules taken unchanged from the SigmaHQ repository (Detection
Rule License 1.1, see that folder's README), ``lsadra/`` holds LSADRA's own, and
``filters/suppressions.yml`` holds reviewed suppressions in Sigma's filter
format. pySigma parses them and its matcher compiles each rule once; this
module maps LSADRA events onto Sigma's field taxonomy and runs the rules,
including Sigma 2.0 correlation rules, over each detection frame.

The layer is gated by ``LSADRA_SIGMA_MODE``:

- ``shadow`` (default): rules run on every scored event and their matches are
  stored (``sigma_matches`` table) and returned with each result, but they never
  raise or relabel an alert. This is how ADR 0007 says a new detection layer
  ships until the bench shows it helps.
- ``alert``: a match at ``medium`` or above also raises an alert when no
  built-in rule did, with the Sigma rule's technique.
- ``off``: not loaded at all.

Security note: pySigma compiles each rule into Python. Rules and filters are
therefore code, loaded only from this repository and from the operator-chosen
``LSADRA_SIGMA_SUPPRESSIONS`` file, never from event data.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd

from lsadra.detection.attack_map import get_technique
from lsadra.detection.attack_map import tactics as attack_tactics
from lsadra.detection.event_types import canonical_event_type

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).resolve().parent / "sigma_rules"
MODES = ("off", "shadow", "alert")
LEVELS = ("informational", "low", "medium", "high", "critical")

# Canonical event type -> Sigma logsource category (Sigma taxonomy where one exists).
_CATEGORY = {
    "process_exec": "process_creation",
    "sudo_exec": "process_creation",
    "cron_job": "process_creation",
    "file_write": "file_event",
    "archive_create": "file_event",
    "file_delete": "file_delete",
    "file_access": "file_access",
    "registry_set": "registry_set",
    "network_flow": "network_connection",
    "firewall_deny": "firewall",
    "dns_query": "dns_query",
    "module_load": "image_load",
    "auth_success": "authentication",
    "auth_failure": "authentication",
}
# Canonical type -> (Windows channel/service, EventID, Provider_Name).
_WINDOWS_EVENT = {
    "auth_success": ("security", 4624, "Microsoft-Windows-Security-Auditing"),
    "auth_failure": ("security", 4625, "Microsoft-Windows-Security-Auditing"),
    "privileged_logon": ("security", 4672, "Microsoft-Windows-Security-Auditing"),
    "account_create": ("security", 4720, "Microsoft-Windows-Security-Auditing"),
    "group_member_add": ("security", 4732, "Microsoft-Windows-Security-Auditing"),
    "scheduled_task_create": ("security", 4698, "Microsoft-Windows-Security-Auditing"),
    "log_cleared": ("security", 1102, "Microsoft-Windows-Eventlog"),
    "service_install": ("system", 7045, "Service Control Manager"),
}


@dataclass(frozen=True)
class SigmaHit:
    """One Sigma rule match on one event."""

    rule_id: str
    title: str
    level: str
    status: str
    technique_ids: Tuple[str, ...]
    tactics: Tuple[str, ...]
    source: str  # "sigmahq" | "lsadra"
    correlation: bool = False

    @property
    def raises_alert(self) -> bool:
        return LEVELS.index(self.level) >= LEVELS.index("medium")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "status": self.status,
            "techniques": list(self.technique_ids),
            "tactics": list(self.tactics),
            "source": self.source,
            "correlation": self.correlation,
        }


def sigma_mode() -> str:
    """Current mode from config; anything unknown falls back to ``shadow``."""
    from lsadra.config import SIGMA_MODE

    return SIGMA_MODE if SIGMA_MODE in MODES else "shadow"


# ── event mapping ──────────────────────────────────────────────────────────


def _attrs(value: Any) -> Dict[str, Any]:
    from lsadra.features.rule_features import _attrs as parse

    return parse(value)


def _first(attrs: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = attrs.get(key)
        if value not in (None, ""):
            return value
    return None


def _is_windows(attrs: Dict[str, Any], et: str, image: str) -> bool:
    if attrs.get("os") in ("windows", "linux", "macos"):
        return attrs["os"] == "windows"
    if "event_id" in attrs or "registry_key" in attrs or et == "registry_set":
        return True
    probe = " ".join(
        str(v) for v in (image, attrs.get("image_path"), attrs.get("task_command")) if v
    )
    return "\\" in probe or probe.lower().endswith(".exe") or ".exe " in probe.lower()


def _path(name: Any, windows: bool) -> Optional[str]:
    """Sigma rules match ``Image|endswith: '\\certutil.exe'``; give bare names a separator."""
    if not name:
        return None
    text = str(name)
    if "\\" in text or "/" in text:
        return text
    return ("\\" if windows else "/") + text


def _when(value: Any) -> datetime:
    """Event time as an aware datetime (fast path for ISO 8601 strings)."""
    if isinstance(value, datetime):  # includes pandas.Timestamp
        ts = value
    else:
        try:
            ts = datetime.fromisoformat(str(value))
        except (TypeError, ValueError):
            parsed = pd.to_datetime(value, utc=True, errors="coerce")
            if pd.isna(parsed):
                return datetime.now(timezone.utc)
            ts = parsed.to_pydatetime()
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts


def to_sigma_event(row: Dict[str, Any]):
    """Map one LSADRA event row onto Sigma's field taxonomy."""
    from sigma.matching import Event, EventLogSource

    attrs = _attrs(row.get("attributes"))
    et = row.get("canonical_event_type") or canonical_event_type(row.get("event_type"))
    image_raw = _first(attrs, "process_path", "image", "binary", "process_name", "service")
    windows = _is_windows(attrs, et, str(image_raw or ""))
    product = "windows" if windows else "linux"
    service = None
    data: Dict[str, Any] = {}

    category = _CATEGORY.get(et)
    if windows and et in _WINDOWS_EVENT and not category:
        service, event_id, provider = _WINDOWS_EVENT[et]
        data["EventID"] = int(attrs.get("event_id") or event_id)
        data["Provider_Name"] = provider
    elif windows and et in ("auth_success", "auth_failure"):
        service = "security"
        data["EventID"] = _WINDOWS_EVENT[et][1]

    image = _path(image_raw, windows)
    if image:
        data["Image"] = image
        base = image.replace("\\", "/").rsplit("/", 1)[-1]
        if windows:
            data["OriginalFileName"] = base
    cmd = _first(attrs, "cmdline", "command_line", "command", "CommandLine")
    if cmd:
        data["CommandLine"] = str(cmd)
    parent = _path(_first(attrs, "parent_process", "parent_image"), windows)
    if parent:
        data["ParentImage"] = parent
    parent_cmd = _first(attrs, "parent_cmdline", "parent_command_line")
    if parent_cmd:
        data["ParentCommandLine"] = str(parent_cmd)
    target = _first(attrs, "target_path", "file_path", "path", "dropped_path", "archive_path")
    if target:
        data["TargetFilename"] = str(target)
    if attrs.get("registry_key"):
        key = str(attrs["registry_key"])
        value = attrs.get("value_name")
        data["TargetObject"] = f"{key}\\{value}" if value else key
        if attrs.get("new_value") is not None:
            data["Details"] = str(attrs["new_value"])
    if attrs.get("service_name"):
        data["ServiceName"] = str(attrs["service_name"])
    if attrs.get("image_path"):
        data["ImagePath"] = str(attrs["image_path"])
    if attrs.get("task_name"):
        data["TaskName"] = str(attrs["task_name"])
    if row.get("effective_username"):
        data["User"] = str(row["effective_username"])
        data["TargetUserName"] = str(row["effective_username"])
    if row.get("source_ip"):
        data["SourceIp"] = str(row["source_ip"])
    dest = _first(attrs, "dest_ip", "dst_ip")
    if dest:
        data["DestinationIp"] = str(dest)
    port = _first(attrs, "dest_port", "dst_port")
    if port is not None:
        data["DestinationPort"] = port
    if et in ("auth_success", "auth_failure"):
        data["Outcome"] = "success" if et == "auth_success" else "failure"

    when = _when(row.get("timestamp"))
    return Event(
        timestamp=when,
        logsource=EventLogSource(category=category, product=product, service=service),
        data=data,
        raw=str(row.get("raw_message") or ""),
    )


# ── engine ─────────────────────────────────────────────────────────────────


class SigmaEngine:
    """Compiled rules, filters applied; evaluation is stateless per frame."""

    def __init__(
        self, rule_dirs: Sequence[Path] = (RULES_DIR,), extra_filters: Sequence[Path] = ()
    ) -> None:
        from sigma.collection import SigmaCollection
        from sigma.correlations import SigmaCorrelationRule
        from sigma.matching import SigmaMatcher
        from sigma.rule import SigmaRule

        paths: List[Path] = [p for d in rule_dirs for p in sorted(Path(d).rglob("*.yml"))]
        paths += [Path(p) for p in extra_filters]
        parts = []
        self._source: Dict[str, str] = {}
        for path in paths:
            part = SigmaCollection.from_yaml(
                path.read_text(encoding="utf-8"),
                collect_filters=True,
                resolve_references=False,
            )
            for r in part.rules:
                self._source[str(r.id)] = "sigmahq" if "sigmahq" in path.parts else "lsadra"
            parts.append(part)
        # Merging applies every filter (bundled and operator) to every rule.
        collection = SigmaCollection.merge(parts)
        if collection.errors:
            raise ValueError(f"Sigma rule errors: {collection.errors}")
        self.collection = collection
        self.rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
        self.correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
        self.filters = list(collection.filters)
        # Names of the rules each correlation consumes.
        self._corr_inputs = [
            {ref.reference for ref in c.rules}
            | {
                ref.rule.name
                for ref in c.rules
                if getattr(ref, "rule", None) is not None and ref.rule.name
            }
            for c in self.correlations
        ]
        self._base = SigmaMatcher(SigmaCollection(self.rules))
        # Context rows (history before the scored batch) only feed correlation
        # rules, so they run through the correlations' input rules alone.
        inputs = set().union(*self._corr_inputs) if self._corr_inputs else set()
        self._corr_base = SigmaMatcher(
            SigmaCollection([r for r in self.rules if r.name and r.name in inputs])
        )
        self._meta: Dict[Tuple[str, bool], SigmaHit] = {}
        self._lock = threading.Lock()

    # metadata ---------------------------------------------------------
    def meta(self, rule: Any, correlation: bool = False) -> SigmaHit:
        key = (str(rule.id), correlation)
        if key not in self._meta:
            self._meta[key] = self._build_meta(rule, correlation)
        return self._meta[key]

    def _build_meta(self, rule: Any, correlation: bool) -> SigmaHit:
        techniques: List[str] = []
        for tag in rule.tags or []:
            if tag.namespace != "attack" or not tag.name.lower().startswith("t"):
                continue
            tech = get_technique(tag.name.upper())
            if tech is None:
                continue
            if not tech.active and tech.revoked_by:
                tech = get_technique(tech.revoked_by)
            if tech is not None and tech.active and tech.id not in techniques:
                techniques.append(tech.id)
        tactics: List[str] = []
        for tid in techniques:
            for t in get_technique(tid).tactics:
                if t.name not in tactics:
                    tactics.append(t.name)
        if not tactics:
            # Some rules carry only a tactic tag (``attack.execution``).
            by_short = {t.shortname: t.name for t in attack_tactics().values()}
            for tag in rule.tags or []:
                name = by_short.get(tag.name.lower()) if tag.namespace == "attack" else None
                if name and name not in tactics:
                    tactics.append(name)
        return SigmaHit(
            rule_id=str(rule.id),
            title=rule.title,
            level=rule.level.name.lower() if rule.level else "medium",
            status=rule.status.name.lower() if rule.status else "experimental",
            technique_ids=tuple(techniques),
            tactics=tuple(tactics),
            source=self._source.get(str(rule.id), "lsadra"),
            correlation=correlation,
        )

    # evaluation -------------------------------------------------------
    def evaluate_frame(
        self, rows: List[Dict[str, Any]], scored: Optional[Sequence[bool]] = None
    ) -> List[List[SigmaHit]]:
        """
        Sigma hits for each row, in row order.

        Rows are replayed in time order. Correlation state is rebuilt for every
        frame, so nothing grows between runs. Rows where *scored* is false are
        context (stored history): they only feed correlation rules and never
        get hits of their own, so no row is reported twice across runs.
        Informational rules (such as correlation base rules) are not reported.
        """
        from sigma.matching import SigmaCorrelationRuleMatcher

        hits: List[List[SigmaHit]] = [[] for _ in rows]
        events = []
        for i, row in enumerate(rows):
            try:
                events.append((i, to_sigma_event(row)))
            except Exception:
                logger.exception("Could not map row %s to a Sigma event", row.get("id"))
        events.sort(key=lambda pair: (pair[1].timestamp, pair[0]))
        correlators = [
            (SigmaCorrelationRuleMatcher(c), self._corr_inputs[i])
            for i, c in enumerate(self.correlations)
        ]

        with self._lock:
            for i, event in events:
                is_scored = scored is None or bool(scored[i])
                matcher = self._base if is_scored else self._corr_base
                for match in matcher.match(event):
                    hit = self.meta(match.rule)
                    if is_scored and hit.level != "informational":
                        hits[i].append(hit)
                    name = getattr(match.rule, "name", None)
                    if not name:
                        continue
                    for corr, inputs in correlators:
                        if name in inputs:
                            for cm in corr.receive_match(match, name):
                                if is_scored:
                                    hits[i].append(self.meta(cm.rule, correlation=True))
        for h in hits:
            h.sort(key=lambda x: LEVELS.index(x.level), reverse=True)
        return hits


_ENGINE: Optional[SigmaEngine] = None
_ENGINE_FAILED = False
_ENGINE_LOCK = threading.Lock()


def get_engine() -> Optional[SigmaEngine]:
    """The process-wide engine, or ``None`` when the layer is off or failed to load."""
    global _ENGINE, _ENGINE_FAILED
    if sigma_mode() == "off" or _ENGINE_FAILED:
        return None
    if _ENGINE is None:
        with _ENGINE_LOCK:
            if _ENGINE is None and not _ENGINE_FAILED:
                from lsadra.config import SIGMA_SUPPRESSIONS

                try:
                    extra = [Path(SIGMA_SUPPRESSIONS)] if SIGMA_SUPPRESSIONS else []
                    _ENGINE = SigmaEngine(extra_filters=extra)
                    logger.info(
                        "Sigma layer (%s): %d rules, %d correlations, %d filters",
                        sigma_mode(),
                        len(_ENGINE.rules),
                        len(_ENGINE.correlations),
                        len(_ENGINE.filters),
                    )
                except Exception:
                    _ENGINE_FAILED = True
                    logger.exception("Sigma layer failed to load; continuing without it")
    return _ENGINE
