"""Read-only host posture checks for the Linux agent (gap G-31).

Runs the checks in ``posture_checks_linux.yml`` (tagged with CIS Controls v8.1
Implementation Group 1 safeguards) and turns each result into a contract-v1
event (``event_type: posture_check``) for the agent to send with its normal
batches.

Nothing here changes the host: checks read files, file permissions and the
sshd configuration, or run one allow-listed status command without a shell.

Standard library only, like the agent. PyYAML is used when installed; otherwise
a small loader reads the restricted YAML subset the check file is written in.

Run on a host to see the report without sending anything::

    python3 posture.py
"""

from __future__ import annotations

import glob
import json
import os
import platform
import re
import shutil
import stat
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

CHECKS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "posture_checks_linux.yml")

PASS, FAIL, NOT_APPLICABLE, ERROR = "pass", "fail", "not_applicable", "error"

# Status commands a check may run. Anything else in a check file is refused.
ALLOWED_COMMANDS = frozenset({"systemctl", "ufw", "nft", "lsblk"})
COMMAND_TIMEOUT_S = 10
MAX_READ_BYTES = 1024 * 1024
_MAX_ATTR = 1024

Result = Tuple[str, str]  # (status, short detail)
CommandRunner = Callable[[List[str]], Optional[str]]


# ── Loading the check file ────────────────────────────────────────────────


def load_checks(path: str = CHECKS_FILE) -> List[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    try:
        import yaml  # type: ignore
    except ImportError:
        data = load_yaml_subset(text)
    else:
        data = yaml.safe_load(text)
    checks = data.get("checks") if isinstance(data, dict) else None
    if not isinstance(checks, list):
        raise ValueError(f"{path}: expected a top-level 'checks' list")
    return checks


def _scalar(token: str) -> Any:
    token = token.strip()
    if token.startswith('"') or token.startswith("["):
        return json.loads(token)  # double-quoted strings and lists of them
    if token.startswith("'") and token.endswith("'") and len(token) >= 2:
        return token[1:-1].replace("''", "'")
    return token


def load_yaml_subset(text: str) -> Any:
    """Parse the block-style YAML subset used by the check files.

    Supports nested mappings and lists, plain, single- and double-quoted
    scalars, and flow lists of double-quoted strings. No anchors, tags,
    multi-line scalars or inline comments.
    """
    lines: List[List[Any]] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append([len(raw) - len(raw.lstrip(" ")), stripped])

    def block(i: int, indent: int) -> Tuple[Any, int]:
        if lines[i][1].startswith("- "):
            return seq(i, indent)
        return mapping(i, indent)

    def seq(i: int, indent: int) -> Tuple[List[Any], int]:
        out: List[Any] = []
        while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            rest = lines[i][1][2:].strip()
            if ":" in rest and not rest.startswith(('"', "'", "[")):
                lines[i] = [indent + 2, rest]  # "- key: v" opens a mapping
                item, i = mapping(i, indent + 2)
            else:
                item, i = _scalar(rest), i + 1
            out.append(item)
        return out, i

    def mapping(i: int, indent: int) -> Tuple[Dict[str, Any], int]:
        out: Dict[str, Any] = {}
        while i < len(lines) and lines[i][0] == indent and not lines[i][1].startswith("- "):
            key, sep, rest = lines[i][1].partition(":")
            if not sep:
                raise ValueError(f"expected 'key: value', got {lines[i][1]!r}")
            rest = rest.strip()
            if rest:
                out[key.strip()] = _scalar(rest)
                i += 1
            else:
                if i + 1 >= len(lines) or lines[i + 1][0] <= indent:
                    raise ValueError(f"key {key!r} has no value")
                out[key.strip()], i = block(i + 1, lines[i + 1][0])
        return out, i

    if not lines:
        return None
    data, end = block(0, lines[0][0])
    if end != len(lines):
        raise ValueError(f"unexpected indentation near {lines[end][1]!r}")
    return data


# ── Check types ───────────────────────────────────────────────────────────


def _run_command(argv: List[str]) -> Optional[str]:
    """stdout of an allow-listed status command, or None if not installed."""
    if not argv or argv[0] not in ALLOWED_COMMANDS:
        raise PermissionError(f"command not allowed: {argv[:1]}")
    exe = shutil.which(argv[0])
    if exe is None:
        return None
    proc = subprocess.run(  # noqa: S603 - fixed argv from the allow-list, no shell
        [exe, *argv[1:]],
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_S,
        check=False,
    )
    return proc.stdout


def _host_path(root: str, path: str) -> str:
    return os.path.join(root, path.lstrip("/"))


def _read(root: str, path: str) -> Optional[str]:
    full = _host_path(root, path)
    if not os.path.exists(full):
        return None
    with open(full, encoding="utf-8", errors="replace") as f:
        return f.read(MAX_READ_BYTES)


def _sshd_lines(root: str, path: str, depth: int = 0) -> List[str]:
    """Global sshd_config lines in order, with Include files expanded."""
    text = _read(root, path)
    if text is None or depth > 4:
        return []
    out: List[str] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        word = re.split(r"[\s=]+", line, maxsplit=1)
        key = word[0].lower()
        if key == "match":
            break  # everything after the first Match block is conditional
        if key == "include" and len(word) > 1:
            for pattern in word[1].split():
                if not pattern.startswith("/"):
                    pattern = "/etc/ssh/" + pattern
                for inc in sorted(glob.glob(_host_path(root, pattern))):
                    rel = "/" + os.path.relpath(inc, root).replace(os.sep, "/")
                    out.extend(_sshd_lines(root, rel, depth + 1))
            continue
        out.append(line)
    return out


def _check_sshd_option(check: Dict[str, Any], root: str, _run: CommandRunner) -> Result:
    if not os.path.exists(_host_path(root, "/etc/ssh/sshd_config")):
        return NOT_APPLICABLE, "no SSH server configuration"
    key = str(check["key"]).lower()
    value = str(check.get("default", "")).lower()
    source = "default"
    for line in _sshd_lines(root, "/etc/ssh/sshd_config"):
        parts = re.split(r"[\s=]+", line, maxsplit=1)
        if parts[0].lower() == key and len(parts) > 1:
            value, source = parts[1].strip().lower(), "configured"
            break  # sshd uses the first value it reads
    allowed = [str(a).lower() for a in check["allowed"]]
    return (PASS if value in allowed else FAIL), f"{key} is {value} ({source})"


def _check_file_regex(check: Dict[str, Any], root: str, _run: CommandRunner) -> Result:
    try:
        text = _read(root, check["path"])
    except OSError as exc:
        return ERROR, f"cannot read {check['path']}: {exc.strerror}"
    if text is None:
        return NOT_APPLICABLE, f"{check['path']} not present"
    found = re.search(check["pattern"], text, re.MULTILINE) is not None
    want = check.get("expect", "match") == "match"
    return (PASS if found == want else FAIL), f"pattern {'found' if found else 'not found'} in {check['path']}"


def _mode_of(path: str) -> int:
    """Permission bits of a file (a seam for tests)."""
    return stat.S_IMODE(os.stat(path).st_mode)


def _check_file_mode(check: Dict[str, Any], root: str, _run: CommandRunner) -> Result:
    full = _host_path(root, check["path"])
    if not os.path.exists(full):
        return NOT_APPLICABLE, f"{check['path']} not present"
    mode = _mode_of(full)
    limit = int(str(check["max_mode"]), 8)
    extra = mode & ~limit
    detail = f"{check['path']} mode {mode:04o} (limit {limit:04o})"
    return (FAIL if extra else PASS), detail


def _check_command(check: Dict[str, Any], _root: str, run: CommandRunner) -> Result:
    argv = [str(a) for a in check["argv"]]
    out = run(argv)
    if out is None:
        return NOT_APPLICABLE, f"{argv[0]} not installed"
    found = re.search(check["pattern"], out, re.MULTILINE) is not None
    return (PASS if found else FAIL), f"`{' '.join(argv)}` {'matched' if found else 'did not match'}"


def _check_any_of(check: Dict[str, Any], root: str, run: CommandRunner) -> Result:
    results = [evaluate(sub, root, run) for sub in check["any_of"]]
    statuses = [s for s, _ in results]
    for status, detail in results:
        if status == PASS:
            return PASS, detail
    if FAIL in statuses:
        return FAIL, "; ".join(d for s, d in results if s == FAIL)
    if ERROR in statuses:
        return ERROR, "; ".join(d for s, d in results if s == ERROR)
    return NOT_APPLICABLE, "; ".join(d for _, d in results)


_TYPES = {
    "sshd_option": _check_sshd_option,
    "file_regex": _check_file_regex,
    "file_mode": _check_file_mode,
    "command": _check_command,
    "any_of": _check_any_of,
}


def evaluate(check: Dict[str, Any], root: str = "/", run: CommandRunner = _run_command) -> Result:
    """Status and a short detail for one check. Never raises."""
    handler = _TYPES.get(check.get("type", ""))
    if handler is None:
        return ERROR, f"unknown check type {check.get('type')!r}"
    try:
        return handler(check, root, run)
    except subprocess.TimeoutExpired:
        return ERROR, "status command timed out"
    except Exception as exc:  # a broken check must not stop the others
        return ERROR, f"{type(exc).__name__}: {exc}"[:200]


# ── Results as contract-v1 events ─────────────────────────────────────────


def run_all(
    checks: Optional[List[Dict[str, Any]]] = None,
    root: str = "/",
    run: CommandRunner = _run_command,
) -> List[Dict[str, Any]]:
    checks = load_checks() if checks is None else checks
    results = []
    for check in checks:
        status, detail = evaluate(check, root, run)
        results.append(
            {
                "id": check["id"],
                "title": check["title"],
                "cis": [str(c) for c in check.get("cis", [])],
                "status": status,
                "detail": detail,
            }
        )
    return results


def to_events(results: List[Dict[str, Any]], host: Optional[str] = None) -> List[Dict[str, Any]]:
    """One ``posture_check`` event per result, valid against event schema v1."""
    host = (host or platform.node())[:255]
    now = datetime.now(timezone.utc).isoformat()
    events = []
    for r in results:
        cis = ",".join(r["cis"])
        events.append(
            {
                "schema_version": "1",
                "timestamp": now,
                "event_type": "posture_check",
                "host": host,
                "raw_message": f"CIS IG1 {cis}: {r['title']}: {r['status'].upper()}"[:4096],
                "attributes": {
                    "check_id": r["id"][:_MAX_ATTR],
                    "title": r["title"][:_MAX_ATTR],
                    "cis_safeguards": cis[:_MAX_ATTR],
                    "status": r["status"],
                    "detail": r["detail"][:_MAX_ATTR],
                    "severity": "MEDIUM" if r["status"] == FAIL else "INFO",
                },
            }
        )
    return events


def main() -> None:
    results = run_all()
    width = max(len(r["id"]) for r in results)
    for r in results:
        print(f"{r['status'].upper():<15} {r['id']:<{width}}  CIS {','.join(r['cis']):<8} {r['title']}")
        print(f"{'':<15} {'':<{width}}  {r['detail']}")
    failed = sum(r["status"] == FAIL for r in results)
    print(f"\n{len(results)} checks, {failed} failed")


if __name__ == "__main__":
    main()
