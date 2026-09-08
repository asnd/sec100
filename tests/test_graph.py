import sqlite3
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "epdg"))
from graph import build_graph, export_graph, graph_rows, graph_summary


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE available_fqdns (
              mnc INTEGER, mcc INTEGER, operator TEXT, country_name TEXT,
              fqdn TEXT, record_type TEXT, service TEXT, dns_status TEXT,
              resolved_ips TEXT
            );
            CREATE TABLE ip_enrichment (
              fqdn TEXT, record_type TEXT, ip TEXT, asn TEXT, asn_org TEXT,
              hosting_provider TEXT
            );
            CREATE TABLE naptr_records (base_fqdn TEXT, replacement TEXT);
            CREATE TABLE srv_records (source_fqdn TEXT, query_name TEXT, target TEXT);
            CREATE TABLE fiveg_fqdns (fqdn TEXT, mcc INTEGER, mnc INTEGER,
              nf_type TEXT, dns_status TEXT, dns_source TEXT);
        """)
        self.db.executemany("INSERT INTO available_fqdns VALUES (?,?,?,?,?,?,?,?,?)", [
            (1, 310, "Alpha", "US", "epdg.epc.mnc001.mcc310.pub.3gppnetwork.org", "A", "epdg.epc", "ANSWERED", "192.0.2.10"),
            (2, 310, "Beta", "US", "epdg.epc.mnc002.mcc310.pub.3gppnetwork.org", "A", "epdg.epc", "ANSWERED", "192.0.2.10"),
        ])
        self.db.execute("INSERT INTO ip_enrichment VALUES (?,?,?,?,?,?)", ("epdg.epc.mnc001.mcc310.pub.3gppnetwork.org", "A", "192.0.2.10", "AS64500", "Transit", "Example Cloud"))
        self.db.execute("INSERT INTO naptr_records VALUES (?,?)", ("ims.mnc001.mcc310.pub.3gppnetwork.org", "sip.example.net."))
        self.db.execute("INSERT INTO srv_records VALUES (?,?,?)", ("ims.mnc001.mcc310.pub.3gppnetwork.org", "_sip._tcp.example", "sip.example.net."))
        self.db.execute("INSERT INTO fiveg_fqdns VALUES (?,?,?,?,?,?)", ("n3iwf.5gc.mnc001.mcc310.pub.3gppnetwork.org", 310, 1, "n3iwf", "ANSWERED", "public"))

    def test_graph_builds_shared_infrastructure_and_5g(self):
        first = build_graph(self.db)
        second = build_graph(self.db)
        self.assertEqual(first["nodes"], second["nodes"])
        self.assertEqual(first["edges"], second["edges"])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM graph_nodes WHERE node_type='ip'").fetchone()[0], 1)
        relations = {row["relationship"] for row in graph_rows(self.db)}
        self.assertTrue({"resolves_to", "announced_by", "hosted_by", "naptr_replacement", "srv_target"} <= relations)
        self.assertTrue(any(r["target"] == "n3iwf.5gc.mnc001.mcc310.pub.3gppnetwork.org"
                            for r in graph_rows(self.db, relationship="publishes")))

    def test_exports_are_machine_readable(self):
        build_graph(self.db)
        payload = export_graph(self.db, "json")
        self.assertIn('"nodes"', payload)
        self.assertIn("resolves_to", payload)
        self.assertIn("source_type", export_graph(self.db, "csv"))


if __name__ == "__main__":
    unittest.main()
