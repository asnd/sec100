import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "epdg"))
from resolver_observations import compare_latest, init_observation_db, probe_fqdn, save_observation


class Rdata:
    def __init__(self, text):
        self.text = text

    def to_text(self):
        return self.text


class Rrset:
    ttl = 120


class Response:
    flags = 0


class Answer:
    rrset = Rrset()
    response = Response()

    def __iter__(self):
        return iter([Rdata("192.0.2.10")])


class Resolver:
    nameservers = ["192.0.2.53"]

    def resolve(self, *args, **kwargs):
        return Answer()


class ResolverCompareTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        init_observation_db(self.db)

    def test_probe_captures_answers_ttl_and_source(self):
        row = probe_fqdn("example.org", "A", Resolver(), "test", "AS64500", "NO")
        self.assertEqual(row["response_code"], "NOERROR")
        self.assertEqual(row["dnssec_status"], "INSECURE")
        self.assertEqual(row["ttl"], 120)
        self.assertEqual(row["answers"], ["192.0.2.10"])
        save_observation(self.db, row)
        latest = compare_latest(self.db, "example.org")
        self.assertEqual(latest[0]["source_country"], "NO")

    def test_latest_comparison_returns_one_row_per_resolver(self):
        first = {"fqdn": "example.org", "record_type": "A", "resolver_name": "one",
                 "resolver_address": "1.1.1.1", "source_asn": None, "source_country": None,
                 "response_code": "NOERROR", "dnssec_status": "INSECURE", "ttl": 60,
                 "answers": ["192.0.2.1"], "observed_at": "2026-01-01T00:00:00+00:00"}
        second = {**first, "resolver_name": "two", "observed_at": "2026-01-01T00:00:00+00:00"}
        save_observation(self.db, first)
        save_observation(self.db, second)
        self.assertEqual([r["resolver_name"] for r in compare_latest(self.db, "example.org")], ["one", "two"])


if __name__ == "__main__":
    unittest.main()
