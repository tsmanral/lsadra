"""
Two-tier threat intel (ADR 0004): bundled lookups, runtime feeds with
conditional GETs, keyless defaults, local geolocation, and the /api/intel
routes. SYNTHETIC data only: RFC 5737 / RFC 3849 addresses, *.demo users.
"""

import asyncio
import ipaddress
import json

import httpx
import pytest

from lsadra import intel
from lsadra.intel import bundle, feeds, geo, runtime
from tests.fixtures import setup_test_db


@pytest.fixture(autouse=True)
def _fresh(tmp_path, monkeypatch):
    import lsadra.config as config

    setup_test_db(tmp_path)
    monkeypatch.setattr(config, "INTEL_RUNTIME_DB", tmp_path / "intel_runtime.db")
    monkeypatch.setattr(config, "INTEL_FEEDS", [])
    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "")
    monkeypatch.setattr(config, "GEOIP_DB", str(tmp_path / "missing.mmdb"))
    # Synthetic data uses documentation ranges; let them count as public here.
    monkeypatch.setattr(
        intel,
        "TREAT_AS_PUBLIC",
        tuple(
            ipaddress.ip_network(n)
            for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
        ),
    )


# ── Bundled tier ─────────────────────────────────────────────────────────


def test_bundled_tier_works_with_no_keys_and_no_network():
    s = bundle.status()
    assert s["available"] is True
    ids = {src["id"] for src in s["sources"]}
    assert ids == {"cisa_kev", "mitre_attack_enterprise"}
    assert all(src["records"] > 0 for src in s["sources"])
    # Log4Shell has been in KEV since 2021-12-10 and is a stable anchor.
    row = bundle.lookup_cve("cve-2021-44228")
    assert row["vendor"] == "Apache" and row["known_ransomware_use"] is True
    assert bundle.lookup_technique("T1110")["name"] == "Brute Force"
    assert "credential-access" in bundle.lookup_technique("t1110.001")["tactics"]


def test_bundled_lookups_reject_malformed_ids():
    assert bundle.lookup_cve("'; DROP TABLE kev; --") is None
    assert bundle.lookup_technique("T1") is None
    # LIKE wildcards are escaped, so "%" matches only a literal percent sign.
    assert bundle.search_kev("%", limit=5) == []


def test_kev_search_is_newest_first_and_bounded():
    rows = bundle.search_kev("", limit=5)
    assert len(rows) == 5
    assert rows == sorted(rows, key=lambda r: (r["date_added"], r["cve_id"]), reverse=True)
    assert len(bundle.search_kev("", limit=10_000)) <= 500


def test_build_is_deterministic(tmp_path):
    from tests.security.test_intel_bundle_integrity import ATTACK, KEV
    from lsadra.intel import build

    a = build.build(tmp_path / "a", kev_raw=KEV, attack_raw=ATTACK, now="2099-01-01T00:00:00")
    b = build.build(tmp_path / "b", kev_raw=KEV, attack_raw=ATTACK, now="2099-01-01T00:00:00")
    assert a["sha256"] == b["sha256"]
    assert build.upstream_unchanged(b, json.dumps(a))


# ── Runtime tier: nothing invented, nothing sent by default ──────────────


def test_unknown_public_ip_is_unknown_not_scored():
    res = intel.lookup_ip("198.51.100.7")
    assert res["verdict"]["level"] == "unknown"
    assert res["abuseipdb"] is None and res["feed_matches"] == []
    assert intel.legacy_view(res) is None  # the narrative gets nothing, not a 0


def test_private_ip_is_internal():
    assert intel.lookup_ip("10.1.2.3")["verdict"]["level"] == "internal"
    assert intel.lookup_ip("not-an-ip") == {"ip": "not-an-ip", "valid": False}


def test_abuseipdb_without_key_sends_nothing():
    calls = []
    transport = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(500))

    async def go():
        async with httpx.AsyncClient(transport=transport) as c:
            return await feeds.query_abuseipdb("198.51.100.7", client=c)

    assert asyncio.run(go()) is None
    assert calls == []


def test_abuseipdb_with_key_is_cached_in_runtime_db(monkeypatch):
    import lsadra.config as config

    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "synthetic-test-key")
    calls = []

    def handler(req):
        calls.append(req)
        return httpx.Response(
            200,
            json={
                "data": {
                    "abuseConfidenceScore": 88,
                    "countryCode": "ZZ",
                    "totalReports": 3,
                    "isTor": False,
                    "isp": "Example ISP",
                    "domain": "example.net",
                }
            },
        )

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            await feeds.query_abuseipdb("198.51.100.7", client=c)
            await feeds.query_abuseipdb("198.51.100.7", client=c)  # cache hit

    asyncio.run(go())
    assert len(calls) == 1 and calls[0].headers["Key"] == "synthetic-test-key"
    res = intel.lookup_ip("198.51.100.7")
    assert res["abuseipdb"]["abuse_score"] == 88
    assert res["verdict"]["level"] == "malicious"
    assert intel.legacy_view(res)["abuse_score"] == 88


# ── Runtime feeds ────────────────────────────────────────────────────────

FEODO = json.dumps([{"ip_address": "192.0.2.10", "malware": "ExampleBot"}]).encode()
DROP4 = (
    b'{"cidr":"198.51.100.0/24","sblid":"SBL000001","rir":"demo"}\n'
    b'{"type":"metadata","records":1}\n'
)
DROP6 = b'{"cidr":"2001:db8::/32","sblid":"SBL000002","rir":"demo"}\n'
TOR = b"# synthetic\n203.0.113.9\n"


def _feed_transport(log):
    bodies = {
        "feodotracker.abuse.ch": FEODO,
        "drop_v4": DROP4,
        "drop_v6": DROP6,
        "torproject": TOR,
    }

    def handler(req):
        log.append(req)
        if req.headers.get("If-None-Match") == '"v1"':
            return httpx.Response(304)
        for key, body in bodies.items():
            if key in str(req.url):
                return httpx.Response(200, content=body, headers={"ETag": '"v1"'})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_feeds_are_off_by_default():
    assert feeds.update_feeds() == []


def test_feed_update_matches_ips_and_cidrs_and_uses_conditional_get():
    log = []
    with httpx.Client(transport=_feed_transport(log)) as c:
        first = feeds.update_feeds(["feodo", "spamhaus_drop", "tor_exits"], client=c)
        assert [r["status"] for r in first] == ["ok"] * 4
        second = feeds.update_feeds(["feodo", "spamhaus_drop", "tor_exits"], client=c)
        assert [r["status"] for r in second] == ["not_modified"] * 4
    assert all(r.headers.get("If-None-Match") == '"v1"' for r in log[4:])

    c2 = runtime.match_ip("192.0.2.10")
    assert [m["label"] for m in c2] == ["ExampleBot"]
    assert [m["value"] for m in runtime.match_ip("198.51.100.77")] == ["198.51.100.0/24"]
    assert [m["value"] for m in runtime.match_ip("2001:db8::1")] == ["2001:db8::/32"]
    assert runtime.match_ip("192.0.2.11") == []


def test_feed_verdicts(monkeypatch):
    import lsadra.config as config

    monkeypatch.setattr(config, "INTEL_FEEDS", ["feodo", "tor_exits"])
    with httpx.Client(transport=_feed_transport([])) as c:
        feeds.update_feeds(client=c)
    assert intel.lookup_ip("192.0.2.10")["verdict"]["level"] == "malicious"
    assert intel.lookup_ip("203.0.113.9")["verdict"]["level"] == "suspicious"
    clean = intel.lookup_ip("192.0.2.200")
    assert clean["verdict"]["level"] == "not_listed"
    assert sorted(clean["sources_checked"]) == ["feodo", "tor_exits"]
    view = intel.legacy_view(intel.lookup_ip("203.0.113.9"))
    assert view["is_tor"] is True and "abuse_score" not in view


def test_failed_or_empty_feed_keeps_previous_data():
    with httpx.Client(transport=_feed_transport([])) as c:
        feeds.update_feeds(["feodo"], client=c)
    broken = httpx.MockTransport(lambda req: httpx.Response(200, content=b"[]"))
    with httpx.Client(transport=broken) as c:
        [res] = feeds.update_feeds(["feodo"], client=c)
    assert res["status"] == "error"
    assert runtime.match_ip("192.0.2.10")  # still there


# ── Local geolocation ────────────────────────────────────────────────────


class _FakeReader:
    class _Md:
        database_type = "DBIP-City-Lite"
        build_epoch = 4070908800

    def metadata(self):
        return self._Md()

    def get(self, ip):
        if ip == "192.0.2.1":
            return {
                "country": {"iso_code": "ZZ", "names": {"en": "Testland"}},
                "city": {"names": {"en": "Demo City"}},
                "location": {"latitude": 1.5, "longitude": 2.5},
            }
        return None


def test_geo_is_unavailable_without_a_local_database():
    assert geo.status()["available"] is False
    assert geo.lookup("192.0.2.1") is None


def test_geo_lookup_reads_the_local_file(monkeypatch):
    monkeypatch.setattr(geo, "_get_reader", lambda: _FakeReader())
    g = geo.lookup("192.0.2.1")
    assert g["country_code"] == "ZZ" and g["city"] == "Demo City"
    assert "DB-IP" in geo.status()["attribution"]


def test_geo_resolver_makes_no_network_calls(monkeypatch):
    import lsadra.jobs.geo_resolver as gr

    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(httpx, "get", boom)
    monkeypatch.setattr(httpx.Client, "send", boom)
    assert gr.run() == 0  # no local database: skipped, nothing sent


# ── Narrative: no made-up score ──────────────────────────────────────────


def test_narrative_does_not_print_a_score_it_does_not_have():
    from lsadra.explainability.narrative_builder import _para_executive_summary

    text = _para_executive_summary(
        "203.0.113.9",
        {"attack_type": "brute_force"},
        [],
        {"country_code": "ZZ", "is_tor": True, "feed_matches": ["Tor exit nodes: tor-exit"]},
    )
    assert "AbuseIPDB" not in text and "Tor exit node" in text


# ── API ──────────────────────────────────────────────────────────────────


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from server import app

    return TestClient(app)


def _auth(role, uid=None):
    from lsadra.auth import create_access_token, hash_password
    from lsadra.storage.database import create_user

    uid = uid or f"u-{role.lower()}"
    name = f"{role.lower()}.demo"
    create_user(uid, name, hash_password("Synthetic-Pass-123!"), role)
    return {"Authorization": "Bearer " + create_access_token(uid, name, role)}


def test_api_requires_auth(client):
    assert client.get("/api/intel/status").status_code in (401, 403)
    assert client.get("/api/intel/ip/198.51.100.7").status_code in (401, 403)


def test_api_status_and_lookups(client):
    h = _auth("VIEWER")
    s = client.get("/api/intel/status", headers=h).json()
    assert s["bundled"]["available"] is True
    assert s["runtime"]["abuseipdb"]["configured"] is False
    assert client.get("/api/intel/cve/CVE-2021-44228", headers=h).json()["product"] == "Log4j2"
    assert client.get("/api/intel/cve/CVE-1999-0000", headers=h).status_code == 404
    assert client.get("/api/intel/technique/T1110", headers=h).status_code == 200
    assert len(client.get("/api/intel/kev?limit=3", headers=h).json()) == 3
    ip = client.get("/api/intel/ip/198.51.100.7", headers=h).json()
    assert ip["verdict"]["level"] == "unknown"
    assert client.get("/api/intel/ip/nope", headers=h).status_code == 422


def test_viewer_cannot_trigger_remote_lookup(client, monkeypatch):
    import lsadra.config as config

    monkeypatch.setattr(config, "ABUSEIPDB_API_KEY", "synthetic-test-key")
    called = []

    async def fake(ip, client=None):
        called.append(ip)
        return None

    monkeypatch.setattr(feeds, "query_abuseipdb", fake)
    client.get("/api/intel/ip/198.51.100.7?remote=true", headers=_auth("VIEWER"))
    assert called == []
    client.get("/api/intel/ip/198.51.100.7?remote=true", headers=_auth("ANALYST"))
    assert called == ["198.51.100.7"]


def test_feed_refresh_is_admin_only(client):
    assert client.post("/api/intel/feeds/refresh", headers=_auth("ANALYST")).status_code == 403
    assert client.post("/api/intel/feeds/refresh", headers=_auth("ADMIN")).status_code == 409


def test_flagged_ips_are_public_only_and_scoped(client):
    from lsadra.storage.database import insert_anomaly

    def anomaly(ip, uid):
        insert_anomaly(
            {
                "device_id": "dev-1",
                "user_id": uid,
                "source_ip": ip,
                "severity_score": 0.8,
                "severity_label": "HIGH",
                "is_anomaly": True,
            }
        )

    analyst = _auth("ANALYST", uid="u-analyst")
    admin = _auth("ADMIN", uid="u-admin")
    anomaly("198.51.100.20", "u-analyst")
    anomaly("198.51.100.20", "u-analyst")
    anomaly("10.0.0.5", "u-analyst")
    anomaly("203.0.113.30", "u-other")
    mine = client.get("/api/intel/flagged-ips", headers=analyst).json()
    assert [(r["ip"], r["anomalies"]) for r in mine] == [("198.51.100.20", 2)]
    assert mine[0]["verdict"] == "unknown"
    every = {r["ip"] for r in client.get("/api/intel/flagged-ips", headers=admin).json()}
    assert every == {"198.51.100.20", "203.0.113.30"}
