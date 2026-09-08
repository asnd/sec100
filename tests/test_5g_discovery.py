import importlib.util
import sqlite3
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "epdg" / "3gpppub-5g-discovery.py"
SPEC = importlib.util.spec_from_file_location("discovery_5g", MODULE_PATH)
discovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(discovery)


class Answer:
    def __init__(self, address):
        self.address = address


class NaptrAnswer:
    def __init__(self, replacement):
        self.replacement = replacement


class FakeResolver:
    def __init__(self):
        self.queries = []

    def resolve(self, name, record_type):
        self.queries.append((name, record_type))
        if record_type == "NAPTR":
            return [NaptrAnswer("n3iwf.5gc.mnc012.mcc345.pub.3gppnetwork.org.")]
        if name.startswith("n3iwf.5gc") or name.startswith("tac-"):
            return [Answer("192.0.2.10")]
        raise discovery.NXDOMAIN


class N3IWFFQDNTests(unittest.TestCase):
    def test_standard_fqdn_forms(self):
        self.assertEqual(
            discovery.operator_n3iwf_fqdn(12, 345),
            "n3iwf.5gc.mnc012.mcc345.pub.3gppnetwork.org",
        )
        self.assertEqual(
            discovery.tai_n3iwf_fqdn(12, 345, 0x0B1A21),
            "tac-lb21.tac-mb1a.tac-hb0b.5gstac.n3iwf.5gc.mnc012.mcc345.pub.3gppnetwork.org",
        )
        self.assertEqual(
            discovery.tai_n3iwf_fqdn(12, 345, 0x1A21, three_octet=False),
            "tac-lb21.tac-hb1a.tac.n3iwf.5gc.mnc012.mcc345.pub.3gppnetwork.org",
        )
        self.assertEqual(
            discovery.visited_country_n3iwf_fqdn(345),
            "n3iwf.5gc.mcc345.visited-country.pub.3gppnetwork.org",
        )
        self.assertEqual(
            discovery.visited_country_n3iwf_fqdn(345, onboarding=True),
            "onboarding.n3iwf.5gc.mcc345.visited-country.pub.3gppnetwork.org",
        )

    def test_tai_range_validation(self):
        with self.assertRaises(ValueError):
            discovery.tai_n3iwf_fqdn(12, 345, 0x10000, three_octet=False)
        with self.assertRaises(ValueError):
            discovery.tai_n3iwf_fqdn(12, 345, 0x1000000)

    def test_visited_country_naptr_targets_are_probed_and_labeled(self):
        resolver = FakeResolver()
        result = discovery.probe_operator_5g(
            {"mcc": 345, "mnc": 12, "operator": "Example", "countryName": "Test"},
            [], ["A"], resolver, "10.0.0.53", False, [0x0B1A21], True, False,
        )
        self.assertEqual(result["dns_source"], "grx")
        self.assertTrue(any(e["dns_zone"] == "n3iwf-tai-5gs" for e in result["found"]))
        self.assertTrue(any(e["record_type"] == "NAPTR" for e in result["found"]))
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(discovery.SCHEMA_5G)
        discovery.save_5g_result(conn, result)
        self.assertEqual(conn.execute("SELECT DISTINCT dns_source FROM fiveg_fqdns").fetchone()[0], "grx")


if __name__ == "__main__":
    unittest.main()
