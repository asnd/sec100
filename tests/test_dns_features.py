import importlib.util
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "epdg"))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "epdg" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = load("scanner_dns", "3gpppub-dns-database-population.py")
naptr = load("naptr", "3gpppub-naptr-discovery.py")


class FakeRdata:
    def __init__(self, address):
        self.address = address


class FakeAnswers:
    def __init__(self, addresses):
        self.rrset = [FakeRdata(address) for address in addresses]


class DnsFeatureTests(unittest.TestCase):
    def test_ip_classification(self):
        self.assertEqual(scanner.classify_ips(["198.51.100.4"]), "NON_PUBLIC_IP")
        self.assertEqual(scanner.classify_ips(["127.0.0.1"]), "LOOPBACK_127")
        self.assertEqual(scanner.classify_ips(["8.8.8.8"]), "PUBLIC_IP")
        self.assertEqual(scanner.classify_ips(["not-an-ip", "192.0.2.1"]), "NON_PUBLIC_IP")

    def test_resolve_fqdn_statuses(self):
        with patch.object(scanner.dns.resolver, "resolve", return_value=FakeAnswers(["8.8.8.8"])):
            self.assertEqual(scanner.resolve_fqdn("example", "A", retries=0), ("ANSWERED", "PUBLIC_IP", ["8.8.8.8"]))
        with patch.object(scanner.dns.resolver, "resolve", return_value=FakeAnswers([])):
            self.assertEqual(scanner.resolve_fqdn("example", "A", retries=0), ("NODATA", "NONE", []))

    def test_naptr_replacement_filters_non_srv_records(self):
        records = [
            {"flags": "S", "replacement": "_sip._tcp.example."},
            {"flags": "sU", "replacement": "_sip._udp.example."},
            {"flags": "A", "replacement": "ignored.example."},
            {"flags": "S", "replacement": "."},
        ]
        self.assertEqual(
            naptr.naptr_srv_names(records),
            ["_sip._tcp.example.", "_sip._udp.example."],
        )

    def test_save_naptr_result_is_idempotent(self):
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.executescript(naptr.SCHEMA_NAPTR)
        result = {
            "fqdn": "ims.mnc001.mcc310.pub.3gppnetwork.org", "mnc": 1, "mcc": 310,
            "operator": "Example", "country_name": "US",
            "naptr": [{"order_val": 10, "preference": 10, "flags": "S", "service": "SIP+D2U",
                       "regexp": "", "replacement": "_sip._udp.example."}],
            "srv": [{"query_name": "_sip._udp.example.", "priority": 10, "weight": 5,
                     "port": 5060, "target": "sip.example.", "source_fqdn": "ims.mnc001.mcc310.pub.3gppnetwork.org"}],
        }
        naptr.save_naptr_result(db, result)
        naptr.save_naptr_result(db, result)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM naptr_records").fetchone()[0], 1)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM srv_records").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
