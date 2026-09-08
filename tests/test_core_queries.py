import importlib.util
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "epdg"))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "epdg" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scanner = load("scanner", "3gpppub-dns-database-population.py")
diff = load("diff", "3gpppub-diff.py")
from db_queries import compute_scores, query_fqdns, summary_stats
from subdomains import fqdn_to_service, sql_case_when


class CoreQueryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(scanner.SCHEMA)

    def test_service_mapping_and_sql_mapping_stay_consistent(self):
        fqdn = "pcscf.ims.mnc001.mcc310.pub.3gppnetwork.org"
        self.assertEqual(fqdn_to_service(fqdn), "pcscf.ims")
        row = self.db.execute(
            f"SELECT ({sql_case_when(repr(fqdn))}) AS service"
        ).fetchone()
        self.assertEqual(row[0], "pcscf.ims")

    def test_save_result_keeps_confirmed_answer_after_timeout(self):
        base = {
            "mnc": 1, "mcc": 310, "operator": "Example", "country_name": "US",
            "country_code": "US", "records": [{
                "fqdn": "epdg.epc.mnc001.mcc310.pub.3gppnetwork.org",
                "record_type": "A", "dns_status": "ANSWERED", "ip_class": "PUBLIC_IP",
                "resolved_ips": "192.0.2.10",
            }],
        }
        scanner.save_result(self.db, base)
        timeout = {**base, "records": [{**base["records"][0], "dns_status": "TIMEOUT", "ip_class": "NONE", "resolved_ips": ""}]}
        scanner.save_result(self.db, timeout)
        row = self.db.execute("SELECT dns_status,last_query_status,resolved_ips FROM available_fqdns").fetchone()
        self.assertEqual(tuple(row), ("ANSWERED", "TIMEOUT", "192.0.2.10"))

    def test_queries_filter_answered_and_score_5g(self):
        result = {
            "mnc": 1, "mcc": 310, "operator": "Example", "country_name": "US", "country_code": "US",
            "records": [
                {"fqdn": "epdg.epc.mnc001.mcc310.pub.3gppnetwork.org", "record_type": "A", "dns_status": "ANSWERED", "ip_class": "PUBLIC_IP", "resolved_ips": "192.0.2.10"},
                {"fqdn": "ims.mnc001.mcc310.pub.3gppnetwork.org", "record_type": "A", "dns_status": "NXDOMAIN", "ip_class": "NONE", "resolved_ips": ""},
            ],
        }
        scanner.save_result(self.db, result)
        df = query_fqdns(self.db, services=["epdg.epc"], operator="exam")
        self.assertEqual(len(df), 1)
        self.assertEqual(df.iloc[0]["service"], "epdg.epc")
        self.db.execute("CREATE TABLE fiveg_fqdns (mcc INTEGER,mnc INTEGER)")
        self.db.execute("INSERT INTO fiveg_fqdns VALUES (310,1)")
        scores = compute_scores(self.db, df)
        self.assertEqual(int(scores.iloc[0]["score"]), 40)
        self.assertIn("5G SA", scores.iloc[0]["capabilities"])

    def test_snapshot_diff_reports_ip_change_and_confirmed_removal(self):
        db = sqlite3.connect(":memory:")
        db.row_factory = sqlite3.Row
        db.executescript(diff.SCHEMA_DIFF)
        self.db = db
        self.db.execute("""CREATE TABLE available_fqdns (
            fqdn TEXT, record_type TEXT, resolved_ips TEXT, dns_status TEXT,
            operator TEXT, country_name TEXT, mnc INTEGER, mcc INTEGER)""")
        row = ("epdg.epc.mnc001.mcc310.pub.3gppnetwork.org", "A", "192.0.2.1", "ANSWERED", "Example", "US", 1, 310)
        self.db.execute("INSERT INTO available_fqdns VALUES (?,?,?,?,?,?,?,?)", row)
        first = diff.take_snapshot(self.db, "before")
        self.db.execute("UPDATE available_fqdns SET resolved_ips='192.0.2.2', dns_status='ANSWERED'")
        second = diff.take_snapshot(self.db, "changed")
        events = diff.diff_snapshots(self.db, first, second)
        self.assertEqual(len(events["ip_changed"]), 1)
        self.db.execute("UPDATE available_fqdns SET dns_status='NXDOMAIN'")
        third = diff.take_snapshot(self.db, "removed")
        events = diff.diff_snapshots(self.db, second, third)
        self.assertEqual(len(events["removed"]), 1)


if __name__ == "__main__":
    unittest.main()
