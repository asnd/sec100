"""Unit tests for pure helpers across the five security feature scripts."""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import struct
import sys

import pytest

EPDG = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, EPDG)


def _load(name: str, filename: str):
    path = os.path.join(EPDG, filename)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    orig = sys.argv[:]
    sys.argv = [filename]
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.argv = orig
    return mod


@pytest.fixture(scope="module")
def diameter_mod():
    return _load("diameter_mod", "3gpppub-diameter-discovery.py")


@pytest.fixture(scope="module")
def rsp_mod():
    return _load("rsp_mod", "3gpppub-rsp-discovery.py")


@pytest.fixture(scope="module")
def tls_mod():
    return _load("tls_mod", "3gpppub-tls-ike-probe.py")


@pytest.fixture(scope="module")
def baseline_mod():
    return _load("baseline_mod", "3gpppub-baseline-report.py")


@pytest.fixture(scope="module")
def passive_mod():
    return _load("passive_mod", "3gpppub-passive-discovery.py")


def test_diameter_realm_templates(diameter_mod):
    tmpls = diameter_mod.REALM_TEMPLATES
    assert any(t.startswith("epc.mnc") for t in tmpls)
    bare = [t for t in tmpls if t.startswith("mnc{")]
    assert bare, "bare mnc realm template required"
    rendered = bare[0].format(mnc=1, mcc=310)
    assert rendered == "mnc001.mcc310.3gppnetwork.org"
    assert not rendered.startswith("mnc.mnc")


def test_rsp_candidates_no_plus_label(rsp_mod):
    cands = rsp_mod.build_rsp_candidates(1, 310)
    fqdns = [c[0] for c in cands]
    assert any(f.startswith("smdp.") for f in fqdns)
    for f in fqdns:
        assert "smdp+." not in f, f"invalid DNS label: {f}"


def test_rsp_fingerprint_vendor(rsp_mod):
    assert rsp_mod.fingerprint_vendor("CN=x", "O=Thales") == "Thales"
    assert rsp_mod.fingerprint_vendor("IDEMIA CA", "") == "IDEMIA"


def test_decode_peer_cert_empty():
    from tls_cert_util import decode_peer_cert

    assert decode_peer_cert(b"") == {}
    assert decode_peer_cert(b"not-a-cert") == {}


def test_ike_packet_layout(tls_mod):
    pkt = tls_mod._build_ike_sa_init()
    assert len(pkt) == 52
    assert pkt[17] == 0x20
    assert pkt[18] == 34
    assert pkt[16] == 40


def test_ike_vendor_match(tls_mod):
    assert tls_mod._match_vendor_id("4048b7d56ebce885aabb") == "OpenIKEv2"
    assert tls_mod._match_vendor_id("deadbeef") == ""


def test_ike_weak_crypto_not_from_unknown_vendor(tls_mod, monkeypatch):
    """Responding with no SA weak transforms must not set weak_crypto."""
    # Build a minimal valid IKEv2 response with only a vendor-id payload.
    header = bytearray(28)
    header[16] = 43  # next = vendor-id
    header[17] = 0x20
    vid = b"\xde\xad\xbe\xef"
    payload = struct.pack(">BBH", 0, 0, 4 + len(vid)) + vid
    resp = bytes(header) + payload

    class FakeSock:
        def settimeout(self, t): pass
        def sendto(self, *a): return len(a[0])
        def recvfrom(self, n): return resp, ("1.2.3.4", 500)
        def close(self): pass

    monkeypatch.setattr(tls_mod.socket, "socket", lambda *a, **k: FakeSock())
    result = tls_mod.probe_ike("epdg.example", "1.2.3.4", 500, 1.0)
    assert result["responded"] == 1
    assert result["weak_crypto"] == 0


def test_baseline_collectors_match_producer_schemas(baseline_mod, diameter_mod, rsp_mod, tls_mod, passive_mod):
    conn = sqlite3.connect(":memory:")
    conn.executescript(tls_mod.SCHEMA_TLS_IKE)
    conn.executescript(diameter_mod.SCHEMA_DIAMETER)
    conn.executescript(rsp_mod.SCHEMA_RSP)
    conn.executescript(passive_mod.SCHEMA_PASSIVE)
    conn.executescript(baseline_mod.SCHEMA_BASELINE)
    conn.execute(
        "CREATE TABLE available_fqdns (operator TEXT, fqdn TEXT, mcc INT, mnc INT, country_name TEXT)"
    )
    conn.execute(
        "INSERT INTO available_fqdns VALUES ('OpA','bsf.mnc001.mcc310.pub.3gppnetwork.org',310,1,'US')"
    )
    conn.execute(
        """INSERT INTO ike_probes(fqdn,ip,port,operator,mcc,mnc,country_name,weak_crypto,vendor_ids,weak_reasons)
           VALUES ('e.example','1.1.1.1',500,'OpA',310,1,'US',1,'x','weak-encr-transform')"""
    )
    conn.execute(
        """INSERT INTO diameter_realms(mnc,mcc,operator,country_name,realm,naptr_found,naptr_services)
           VALUES (1,310,'OpA','US','epc.mnc001.mcc310.3gppnetwork.org',1,'aaa+ap23')"""
    )
    conn.execute(
        """INSERT INTO rsp_endpoints(operator,mcc,mnc,country_name,fqdn,role,resolved_ips)
           VALUES ('OpA',310,1,'US','smdp.example','SM-DP+','9.9.9.9')"""
    )
    conn.execute(
        """INSERT INTO discovered_hosts(source,fqdn,service_prefix,zone,is_new_candidate,mnc,mcc,operator,country_name)
           VALUES ('crtsh','foo.mnc001.mcc310.pub.3gppnetwork.org','foo','pub',1,1,310,'OpA','US')"""
    )
    conn.commit()

    # Each collector must succeed against real producer schemas.
    ike = baseline_mod.collect_ike_findings(conn)
    assert len(ike) == 1
    assert "weak-encr-transform" in ike[0]["evidence"]

    diam = baseline_mod.collect_diameter_findings(conn)
    assert len(diam) == 1
    assert "aaa+ap23" in diam[0]["evidence"]

    rsp = baseline_mod.collect_rsp_findings(conn)
    assert len(rsp) == 1
    assert rsp[0]["finding_type"] == "rsp_smdp_exposed"

    ct = baseline_mod.collect_ct_findings(conn)
    assert len(ct) == 1

    missing = baseline_mod.collect_missing_service_findings(conn)
    assert any(f["finding_type"] == "missing_epdg" for f in missing)

    n = baseline_mod.save_findings(conn, ike + diam + rsp + ct + missing)
    assert n >= 4
    rows = conn.execute("SELECT COUNT(*) FROM risk_findings").fetchone()[0]
    assert rows >= 4


def test_passive_enrich_without_operators(passive_mod):
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(passive_mod.SCHEMA_PASSIVE)
    op, country = passive_mod.enrich_from_db(conn, 1, 310)
    assert op is None and country is None


def test_html_escape_in_report(baseline_mod):
    findings = [{
        "severity": "HIGH",
        "operator": "<script>x</script>",
        "mcc": 310,
        "mnc": 1,
        "control_ref": "C",
        "title": "T&T",
        "evidence": "a<b>",
    }]
    html_out = baseline_mod.generate_html(findings, top_n=5, summary_only=False)
    assert "<script>x</script>" not in html_out
    assert "&lt;script&gt;x&lt;/script&gt;" in html_out
    assert "T&amp;T" in html_out
