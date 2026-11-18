"""
Regenerate lsadra/detection/data/attack-enterprise.json from MITRE ATT&CK.

LSADRA pins one ATT&CK Enterprise release. This script downloads that
release's STIX bundle from the official mitre-attack/attack-stix-data
repository and writes a compact table of every technique and tactic: ID, name,
tactics, and whether it is deprecated or revoked. ``lsadra/detection/attack_map.py``
loads the table, and ``tests/test_attack_map.py`` checks every technique the
code, the rules and the demo corpus use against it.

To move to a new ATT&CK release, change ``ATTACK_VERSION`` here and in
``attack_map.py``, rerun this script, and fix whatever the tests report.

Usage:
    python scripts/update_attack_data.py            # download the pinned release
    python scripts/update_attack_data.py bundle.json  # use a local STIX bundle

ATT&CK is (c) The MITRE Corporation, used under its Terms of Use
(https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ATTACK_VERSION = "20.1"
URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
OUT = Path(__file__).resolve().parent.parent / "lsadra" / "detection" / "data" / "attack-enterprise.json"


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build_table(bundle: dict) -> dict:
    tactics = {}
    techniques = {}
    ids_by_stix = {o["id"]: _attack_id(o) for o in bundle["objects"] if o.get("type") == "attack-pattern"}
    revoked_by = {
        o["source_ref"]: ids_by_stix.get(o["target_ref"])
        for o in bundle["objects"]
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by"
    }
    for obj in bundle["objects"]:
        if obj.get("type") == "x-mitre-tactic":
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            tactics[obj["x_mitre_shortname"]] = {"id": _attack_id(obj), "name": obj["name"]}
        elif obj.get("type") == "attack-pattern":
            tid = _attack_id(obj)
            if not tid:
                continue
            phases = [
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ]
            entry = {"name": obj["name"], "tactics": sorted(phases)}
            if obj.get("revoked"):
                entry["revoked"] = True
                if revoked_by.get(obj["id"]):
                    entry["revoked_by"] = revoked_by[obj["id"]]
            if obj.get("x_mitre_deprecated"):
                entry["deprecated"] = True
            techniques[tid] = entry
    return {
        "attack_version": ATTACK_VERSION,
        "source": URL,
        "terms_of_use": "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/",
        "tactics": dict(sorted(tactics.items(), key=lambda kv: kv[1]["id"])),
        "techniques": dict(sorted(techniques.items())),
    }


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        bundle = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    else:
        with urllib.request.urlopen(URL, timeout=120) as resp:  # noqa: S310 - fixed https URL
            bundle = json.load(resp)
    table = build_table(bundle)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(table, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(table['techniques'])} techniques, {len(table['tactics'])} tactics)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
