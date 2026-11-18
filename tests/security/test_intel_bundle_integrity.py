"""
Bundled intel integrity (ADR 0004): the intel DB feeds detections and the
narrative engine, so a tampered, unsigned, or licence-violating bundle must be
refused before it is opened, and the tier must fail closed.

Also pins that the simulated threat-intel scores are gone from both UIs.
SYNTHETIC data only (RFC 5737 addresses, made-up CVE rows).
"""

import json
from pathlib import Path

import pytest

from lsadra.intel import build, bundle, signing

REPO = Path(__file__).resolve().parents[2]

KEV = json.dumps({
    "catalogVersion": "2099.01.01",
    "vulnerabilities": [
        {"cveID": "CVE-2099-0001", "vendorProject": "ExampleCo", "product": "Widget",
         "vulnerabilityName": "Widget RCE", "dateAdded": "2099-01-01",
         "dueDate": "2099-01-22", "knownRansomwareCampaignUse": "Known",
         "shortDescription": "synthetic", "requiredAction": "patch", "cwes": ["CWE-20"]},
    ],
}).encode()
ATTACK = json.dumps({"objects": [
    {"type": "attack-pattern", "name": "Brute Force",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1110",
                              "url": "https://attack.mitre.org/techniques/T1110"}],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                            "phase_name": "credential-access"}]},
]}).encode()


@pytest.fixture
def signed(tmp_path):
    kid, priv, pub = signing.generate_keypair()
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({"keys": [{"key_id": kid, "public_key": pub}]}))
    d = tmp_path / "bundle"
    build.build(d, kev_raw=KEV, attack_raw=ATTACK, attack_version="1.0")
    build.sign_dir(d, priv)
    return d, signing.load_trusted_keys(keys), priv


def test_valid_bundle_verifies(signed):
    d, trusted, _ = signed
    vb = bundle.verify_dir(d, trusted)
    assert vb.sqlite_path.name.startswith("intel-")


def test_packaged_bundle_verifies_against_committed_keys():
    vb = bundle.verify_dir(bundle.PACKAGED_DIR)
    assert {s["id"] for s in vb.manifest["sources"]} <= bundle.ALLOWED_BUNDLED_SOURCES


def test_tampered_database_is_refused(signed):
    d, trusted, _ = signed
    db = next(d.glob("intel-*.sqlite"))
    data = bytearray(db.read_bytes())
    data[-1] ^= 0xFF
    db.write_bytes(bytes(data))
    with pytest.raises(bundle.BundleError, match="hash|size"):
        bundle.verify_dir(d, trusted)


def test_edited_manifest_breaks_signature(signed):
    d, trusted, _ = signed
    m = json.loads((d / "manifest.json").read_text())
    m["sha256"] = "0" * 64
    (d / "manifest.json").write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    with pytest.raises(bundle.BundleError, match="signature"):
        bundle.verify_dir(d, trusted)


def test_unsigned_bundle_is_refused(signed):
    d, trusted, _ = signed
    (d / "manifest.sig").unlink()
    with pytest.raises(bundle.BundleError, match="manifest.sig"):
        bundle.verify_dir(d, trusted)


def test_untrusted_key_is_refused(signed):
    d, _, _ = signed
    _, other_priv, _ = signing.generate_keypair()
    build.sign_dir(d, other_priv)
    with pytest.raises(bundle.BundleError, match="not trusted"):
        bundle.verify_dir(d, signing.load_trusted_keys())


def test_runtime_tier_source_in_bundle_is_refused_even_if_signed(signed):
    # A correctly signed manifest still may not smuggle in licence-encumbered data.
    d, trusted, priv = signed
    m = json.loads((d / "manifest.json").read_text())
    m["sources"].append({"id": "maxmind_geolite2"})
    (d / "manifest.json").write_text(json.dumps(m))
    build.sign_dir(d, priv)
    with pytest.raises(bundle.BundleError, match="allowlist"):
        bundle.verify_dir(d, trusted)


def test_bad_override_fails_closed_to_packaged(tmp_path, monkeypatch):
    import lsadra.config as config

    evil = tmp_path / "evil"
    build.build(evil, kev_raw=KEV, attack_raw=ATTACK, attack_version="1.0")
    _, priv, _ = signing.generate_keypair()  # not in trusted_keys.json
    build.sign_dir(evil, priv)
    monkeypatch.setattr(config, "INTEL_BUNDLE_DIR", str(evil))
    try:
        vb = bundle.load(force=True)
        assert vb is not None and vb.directory == bundle.PACKAGED_DIR
        assert bundle.lookup_cve("CVE-2099-0001") is None
    finally:
        monkeypatch.undo()
        bundle.load(force=True)


def test_bundle_opens_read_only():
    import sqlite3

    conn = bundle._connect()
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM kev")
    finally:
        conn.close()


def test_simulated_intel_scores_are_gone():
    tsx = (REPO / "frontend/src/pages/ThreatIntel.tsx").read_text(encoding="utf-8")
    py = (REPO / "lsadra/ui/pages/threat_intel.py").read_text(encoding="utf-8")
    for src in (tsx, py):
        assert "BUILTIN_INTEL" not in src
        assert "185.15.202.13" not in src
    assert "Math.random" not in tsx
