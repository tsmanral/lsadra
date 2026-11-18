"""Data-at-rest file permissions (G-27, CIS 3.3).

The data directory holds the SQLite database (raw log lines, user accounts,
device key hashes), trained models, backups and the TLS key. At start-up the
server restricts it to its own account: directories 0700, files 0600, and a
process umask of 077 so files created later (WAL, models, backups) start
private too. POSIX only; on Windows the directory inherits the user profile's
ACL, and full-disk encryption (BitLocker / FileVault / LUKS) is the documented
baseline on every OS (docs/security/data-inventory.md).
"""

import logging
import os
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


def restrict_data_dir(data_dir: Path) -> List[str]:
    """Tighten permissions under *data_dir*; returns the paths changed."""
    if os.name != "posix":
        return []
    os.umask(0o077)
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    changed: List[str] = []

    def _fix(path: Path, mode: int) -> None:
        try:
            st = path.lstat()
        except FileNotFoundError:
            return
        if path.is_symlink():
            return
        if st.st_mode & 0o777 != mode:
            try:
                os.chmod(path, mode)
                changed.append(str(path))
            except PermissionError:
                logger.warning("Could not restrict permissions on %s", path)

    _fix(data_dir, 0o700)
    for root, dirs, files in os.walk(data_dir, followlinks=False):
        for d in dirs:
            _fix(Path(root) / d, 0o700)
        for f in files:
            _fix(Path(root) / f, 0o600)
    if changed:
        logger.info("Restricted permissions on %d path(s) under %s", len(changed), data_dir)
    return changed
