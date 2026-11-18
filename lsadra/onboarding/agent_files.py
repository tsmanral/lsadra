"""
LSADRA — the files the Linux agent install flow downloads, and their hashes.

The server serves exactly two files to hosts being enrolled: the installer
script and the agent itself. Until releases are signed, integrity rests on
SHA-256 hashes the dashboard shows next to the install command:

* the generated command downloads the installer to a file and runs
  ``sha256sum -c`` on it before ``sudo bash`` ever sees it, and
* the installer refuses to install an agent whose hash differs from the one
  passed in ``--agent-sha256``.

So a file swapped in transit, or on the server after the dashboard was loaded,
is refused instead of run as root. Over plain HTTP an attacker who can rewrite
the dashboard page itself could also rewrite the hashes, which is why the
command says so and why HTTPS stays the default outside dev mode.
"""

from __future__ import annotations

import hashlib
import shlex
import threading
from pathlib import Path
from typing import Dict, Tuple

_PKG_ROOT = Path(__file__).resolve().parent.parent  # .../lsadra

INSTALLER_FILE: Path = _PKG_ROOT / "onboarding" / "installer_linux.sh"
AGENT_FILE: Path = _PKG_ROOT / "endpoint_agent" / "linux_agent.py"

INSTALLER_PATH = "/static/installer_linux.sh"
AGENT_PATH = "/agent/linux_agent.py"

# Optional files the agent loads from its own directory (for example the CIS IG1
# posture checks). Each one that exists is served at /agent/<name>, listed with
# its hash in the install command, and verified by the installer like the agent.
# Nothing else in lsadra/endpoint_agent/ is served.
AGENT_EXTRA_FILE_NAMES = ("posture.py", "posture_checks_linux.yml")


def agent_extra_files() -> Dict[str, Path]:
    """Extra agent files present in this build, by served name."""
    base = AGENT_FILE.parent
    return {n: base / n for n in AGENT_EXTRA_FILE_NAMES if (base / n).is_file()}


_cache: Dict[Path, Tuple[float, str]] = {}
_lock = threading.Lock()


def file_sha256(path: Path) -> str:
    """Hex SHA-256 of *path*, cached until the file's mtime changes."""
    mtime = path.stat().st_mtime
    with _lock:
        hit = _cache.get(path)
        if hit and hit[0] == mtime:
            return hit[1]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    with _lock:
        _cache[path] = (mtime, digest)
    return digest


def install_hashes() -> Dict[str, object]:
    return {
        "installer_sha256": file_sha256(INSTALLER_FILE),
        "agent_sha256": file_sha256(AGENT_FILE),
        "extra_files": {n: file_sha256(p) for n, p in agent_extra_files().items()},
    }


def linux_install_command(server_url: str, token: str) -> str:
    """The one-liner a user pastes on the host to enrol it.

    It downloads the installer to a file, verifies its hash, and only then runs
    it with sudo, passing the expected agent hash along.
    """
    server_url = server_url.rstrip("/")
    hashes = install_hashes()
    q = shlex.quote
    insecure = " --allow-insecure-http" if server_url.startswith("http://") else ""
    extras = "".join(
        f" --file {q(name + '=' + sha)}" for name, sha in sorted(hashes["extra_files"].items())
    )
    return (
        f"curl -fsSLo lsadra-install.sh {q(server_url + INSTALLER_PATH)}"
        f" && echo {q(hashes['installer_sha256'] + '  lsadra-install.sh')} | sha256sum -c -"
        f" && sudo bash lsadra-install.sh --token {q(token)} --server {q(server_url)}"
        f" --agent-sha256 {hashes['agent_sha256']}{extras}{insecure}"
    )
