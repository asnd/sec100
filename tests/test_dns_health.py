import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "epdg"))
from dns_health import probe_health, save_health


class Item:
    def __init__(self, text): self.text = text
    def to_text(self): return self.text


class Answer:
    def __init__(self, values, ttl=300):
        self.rrset = type("Rrset", (), {"ttl": ttl})() if values else None
        self.response = type("Response", (), {"flags": 0})()
        self.values = values
    def __iter__(self): return iter(Item(v) for v in self.values)


class Resolver:
    def resolve(self, fqdn, record_type, **kwargs):
        if record_type == "NS":
            return Answer(["ns1.example."])
        if record_type == "SOA":
            return Answer(["ns1.example. hostmaster.example. 1 2 3 4 5"])
        if record_type == "CNAME":
            return Answer([])
        return Answer(["192.0.2.53"])


class DnsHealthTests(unittest.TestCase):
    def test_probe_checks_delegation_and_nameserver_health(self):
        result = probe_health("example.org", Resolver(), "test")
        self.assertEqual(result["ns_status"], "NOERROR")
        self.assertEqual(result["soa_status"], "NOERROR")
        self.assertEqual(result["cname_status"], "NODATA")
        self.assertEqual(result["nameserver_health"]["ns1.example"], "NOERROR")

    def test_health_is_persisted(self):
        db = sqlite3.connect(":memory:")
        result = probe_health("example.org", Resolver(), "test")
        save_health(db, result)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM dns_health").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
