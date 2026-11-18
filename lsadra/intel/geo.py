"""
Local IP geolocation from a MaxMind-format ``.mmdb`` file.

Lookups read a file on this machine and never send the IP anywhere. The file
is runtime-tier data (ADR 0004): GeoLite2's licence forbids redistribution, so
it is downloaded by the operator, never committed, and ``*.mmdb`` is
gitignored.

``download()`` fetches GeoLite2-City when a MaxMind account ID and licence key
are set (free account), and otherwise the keyless DB-IP "IP to City Lite"
database (CC BY 4.0, attribution shown in the UI), so the lite tier works
without any key. Both use the same ``.mmdb`` format.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import ipaddress
import logging
import os
import tarfile
import threading
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_NAMES = (
    "GeoLite2-City.mmdb",
    "GeoLite2-Country.mmdb",
    "dbip-city-lite.mmdb",
    "dbip-country-lite.mmdb",
)
DBIP_ATTRIBUTION = "IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0"
MAXMIND_ATTRIBUTION = "This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com)"

_lock = threading.Lock()
_reader = None
_reader_path: Optional[Path] = None
_reader_mtime: float = 0.0


def candidate_paths() -> List[Path]:
    from lsadra.config import GEO_DIR, GEOIP_DB

    if GEOIP_DB:
        return [Path(GEOIP_DB)]
    return [Path(GEO_DIR) / n for n in DEFAULT_NAMES]


def database_path() -> Optional[Path]:
    for p in candidate_paths():
        if p.is_file():
            return p
    return None


def _get_reader():
    """Open (or reopen after an update) the mmdb reader; None if unavailable."""
    global _reader, _reader_path, _reader_mtime
    path = database_path()
    if path is None:
        return None
    mtime = path.stat().st_mtime
    with _lock:
        if _reader is not None and _reader_path == path and _reader_mtime == mtime:
            return _reader
        try:
            import maxminddb
        except ImportError:
            logger.warning("maxminddb is not installed; local geolocation is off.")
            return None
        if _reader is not None:
            try:
                _reader.close()
            except Exception:
                pass
        try:
            _reader = maxminddb.open_database(str(path))
        except Exception as exc:
            logger.error("Cannot open geolocation database %s: %s", path, exc)
            _reader = None
            return None
        _reader_path, _reader_mtime = path, mtime
        return _reader


def _attribution(db_type: str) -> str:
    return DBIP_ATTRIBUTION if "dbip" in db_type.lower() or "db-ip" in db_type.lower() \
        else MAXMIND_ATTRIBUTION


def status() -> Dict[str, Any]:
    reader = _get_reader()
    if reader is None:
        return {
            "available": False,
            "searched": [str(p) for p in candidate_paths()],
            "hint": "run `python -m lsadra.intel geo-update` or set LSADRA_GEOIP_DB",
        }
    md = reader.metadata()
    return {
        "available": True,
        "database_type": md.database_type,
        "build_date": date.fromtimestamp(md.build_epoch).isoformat(),
        "attribution": _attribution(md.database_type),
    }


def lookup(ip: str) -> Optional[Dict[str, Any]]:
    """Country/city/coordinates for a public IP; None when unknown or unavailable."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    from lsadra.intel import is_public

    if not is_public(addr):
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        rec = reader.get(str(addr))
    except Exception:
        return None
    if not rec:
        return None

    def name(node):
        return (node or {}).get("names", {}).get("en", "")

    country = rec.get("country") or rec.get("registered_country") or {}
    loc = rec.get("location") or {}
    subdivisions = rec.get("subdivisions") or [{}]
    return {
        "country_code": country.get("iso_code", ""),
        "country": name(country),
        "region": name(subdivisions[0]),
        "city": name(rec.get("city")),
        "latitude": loc.get("latitude"),
        "longitude": loc.get("longitude"),
        "source": reader.metadata().database_type,
    }


# ── Download (operator-run) ──────────────────────────────────────────────


def _atomic_write(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(data)
    import maxminddb  # validate before replacing the working copy

    maxminddb.open_database(str(tmp)).close()
    os.replace(tmp, dest)


def download(client=None, today: Optional[date] = None) -> Path:
    """Download a geolocation database into GEO_DIR and return its path."""
    import httpx
    from lsadra.config import GEO_DIR, MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY

    own = client is None
    if own:
        client = httpx.Client(timeout=300.0, follow_redirects=True)
    try:
        geo_dir = Path(GEO_DIR)
        if MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY:
            auth = (MAXMIND_ACCOUNT_ID, MAXMIND_LICENSE_KEY)
            base = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download"
            r = client.get(base, params={"suffix": "tar.gz"}, auth=auth)
            r.raise_for_status()
            s = client.get(base, params={"suffix": "tar.gz.sha256"}, auth=auth)
            s.raise_for_status()
            expected = s.text.split()[0].strip().lower()
            if hashlib.sha256(r.content).hexdigest() != expected:
                raise ValueError("GeoLite2 download does not match its published SHA-256")
            with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as tar:
                member = next(m for m in tar.getmembers()
                              if m.isfile() and m.name.endswith("GeoLite2-City.mmdb"))
                data = tar.extractfile(member).read()
            dest = geo_dir / "GeoLite2-City.mmdb"
        else:
            today = today or date.today()
            months = [today.replace(day=1)]
            prev = months[0] - timedelta(days=1)
            months.append(prev.replace(day=1))
            last_exc: Optional[Exception] = None
            data = b""
            for m in months:
                url = f"https://download.db-ip.com/free/dbip-city-lite-{m:%Y-%m}.mmdb.gz"
                try:
                    r = client.get(url)
                    r.raise_for_status()
                    data = gzip.decompress(r.content)
                    break
                except Exception as exc:
                    last_exc = exc
            if not data:
                raise RuntimeError(f"DB-IP Lite download failed: {last_exc}")
            dest = geo_dir / "dbip-city-lite.mmdb"
        _atomic_write(dest, data)
        return dest
    finally:
        if own:
            client.close()
