"""
Build the bundled intel tier: intel-YYYYMMDD.sqlite + manifest.json (+ manifest.sig).

Only sources on ``bundle.ALLOWED_BUNDLED_SOURCES`` go in. Today that is:

- ``cisa_kev``: CISA Known Exploited Vulnerabilities catalog (U.S. Government
  work, published under CC0 1.0 by CISA's kev-data repository).
- ``mitre_attack_enterprise``: MITRE ATT&CK Enterprise techniques (royalty-free
  licence with attribution; see LICENSES.md).

The output is deterministic for the same inputs: rows are inserted in sorted
order and the file is VACUUMed, so a rebuild with unchanged upstream data gives
the same hash and the refresh workflow opens no pull request.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from lsadra.intel import bundle, signing

KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/"
    "known_exploited_vulnerabilities.json"
)
ATTACK_INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"

SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE kev (
    cve_id               TEXT PRIMARY KEY,
    vendor               TEXT,
    product              TEXT,
    name                 TEXT,
    date_added           TEXT,
    due_date             TEXT,
    known_ransomware_use TEXT,
    short_description    TEXT,
    required_action      TEXT,
    cwes                 TEXT
);
CREATE INDEX idx_kev_date_added ON kev(date_added);
CREATE TABLE attack_technique (
    technique_id    TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    tactics         TEXT,
    is_subtechnique INTEGER NOT NULL,
    url             TEXT
);
"""


def _fetch(url: str, timeout: float = 120.0) -> bytes:
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.content


# ── Source parsers (pure, unit-tested) ───────────────────────────────────


def parse_kev(raw: bytes) -> Tuple[str, List[Tuple]]:
    data = json.loads(raw)
    rows = []
    for v in data.get("vulnerabilities", []):
        cve = str(v.get("cveID", "")).strip().upper()
        if not cve.startswith("CVE-"):
            continue
        rows.append((
            cve,
            v.get("vendorProject", ""),
            v.get("product", ""),
            v.get("vulnerabilityName", ""),
            v.get("dateAdded", ""),
            v.get("dueDate", ""),
            v.get("knownRansomwareCampaignUse", ""),
            v.get("shortDescription", ""),
            v.get("requiredAction", ""),
            ",".join(v.get("cwes") or []),
        ))
    rows.sort(key=lambda r: r[0])
    return str(data.get("catalogVersion", "")), rows


def parse_attack(raw: bytes) -> List[Tuple]:
    data = json.loads(raw)
    rows = {}
    for o in data.get("objects", []):
        if o.get("type") != "attack-pattern":
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next(
            (r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ref or not str(ref.get("external_id", "")).startswith("T"):
            continue
        tactics = sorted(
            p["phase_name"]
            for p in o.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        )
        tid = ref["external_id"]
        rows[tid] = (
            tid,
            o.get("name", ""),
            ",".join(tactics),
            1 if o.get("x_mitre_is_subtechnique") else 0,
            ref.get("url", ""),
        )
    return [rows[k] for k in sorted(rows)]


def latest_attack_version(index_raw: bytes) -> Tuple[str, str]:
    index = json.loads(index_raw)
    coll = next(c for c in index["collections"] if c["name"] == "Enterprise ATT&CK")
    v = coll["versions"][0]
    return v["version"], v["url"]


# ── Build ────────────────────────────────────────────────────────────────


def write_sqlite(path: Path, kev_rows: Iterable[Tuple], attack_rows: Iterable[Tuple],
                 meta: Dict[str, str]) -> None:
    if path.exists():
        path.unlink()
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.executemany("INSERT INTO meta VALUES (?, ?)", sorted(meta.items()))
        conn.executemany("INSERT INTO kev VALUES (?,?,?,?,?,?,?,?,?,?)", kev_rows)
        conn.executemany("INSERT INTO attack_technique VALUES (?,?,?,?,?)", attack_rows)
        conn.commit()
        conn.execute("VACUUM")
    finally:
        conn.close()


def build(
    out_dir: Path,
    kev_raw: Optional[bytes] = None,
    attack_raw: Optional[bytes] = None,
    attack_version: Optional[str] = None,
    attack_url: Optional[str] = None,
    today: Optional[_dt.date] = None,
    now: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch (unless given), build the SQLite file, and write manifest.json. Unsigned."""
    out_dir.mkdir(parents=True, exist_ok=True)
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    now = now or _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()

    if kev_raw is None:
        kev_raw = _fetch(KEV_URL)
    if attack_raw is None:
        attack_version, attack_url = latest_attack_version(_fetch(ATTACK_INDEX_URL))
        attack_raw = _fetch(attack_url, timeout=300.0)

    kev_version, kev_rows = parse_kev(kev_raw)
    attack_rows = parse_attack(attack_raw)
    if not kev_rows or not attack_rows:
        raise ValueError("refusing to build an intel bundle with an empty source")

    name = f"intel-{today:%Y%m%d}.sqlite"
    for old in out_dir.glob("intel-*.sqlite"):
        if old.name != name:
            old.unlink()
    sqlite_path = out_dir / name
    write_sqlite(
        sqlite_path, kev_rows, attack_rows,
        {"schema": "1", "kev_version": kev_version, "attack_version": attack_version or ""},
    )

    sources = [
        {
            "id": "cisa_kev",
            "name": "CISA Known Exploited Vulnerabilities",
            "url": KEV_URL,
            "version": kev_version,
            "license": "CC0-1.0",
            "records": len(kev_rows),
            "upstream_sha256": hashlib.sha256(kev_raw).hexdigest(),
            "retrieved_at": now,
        },
        {
            "id": "mitre_attack_enterprise",
            "name": "MITRE ATT&CK Enterprise",
            "url": attack_url or "",
            "version": attack_version or "",
            "license": "MITRE ATT&CK Terms of Use (royalty-free, attribution required)",
            "records": len(attack_rows),
            "upstream_sha256": hashlib.sha256(attack_raw).hexdigest(),
            "retrieved_at": now,
        },
    ]
    data = sqlite_path.read_bytes()
    manifest = {
        "format": bundle.MANIFEST_FORMAT,
        "file": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "built_at": now,
        "sources": sources,
    }
    (out_dir / bundle.MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    sig = out_dir / bundle.SIGNATURE_NAME
    if sig.exists():
        sig.unlink()  # stale: the manifest changed
    return manifest


def sign_dir(out_dir: Path, private_key_b64: str) -> str:
    """Sign out_dir/manifest.json; return the key id used."""
    key = signing.load_private_key(private_key_b64)
    manifest_bytes = (out_dir / bundle.MANIFEST_NAME).read_bytes()
    (out_dir / bundle.SIGNATURE_NAME).write_text(signing.sign(manifest_bytes, key),
                                                  encoding="utf-8")
    return signing.key_id_for(key.public_key())


def upstream_unchanged(new_manifest: Dict[str, Any], old_manifest_text: str) -> bool:
    """True when every source's upstream hash matches the previous manifest."""
    try:
        old = json.loads(old_manifest_text)
    except ValueError:
        return False
    def hashes(m):
        return {s["id"]: s.get("upstream_sha256") for s in m.get("sources", [])}
    return hashes(old) == hashes(new_manifest)
