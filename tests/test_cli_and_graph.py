import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]


class CliAndGraphTests(unittest.TestCase):
    def make_db(self, directory):
        path = Path(directory) / "database.db"
        db = sqlite3.connect(path)
        db.execute("""CREATE TABLE available_fqdns (
            mnc INTEGER,mcc INTEGER,operator TEXT,country_name TEXT,fqdn TEXT,
            record_type TEXT,service TEXT,dns_status TEXT,resolved_ips TEXT)""")
        db.execute("INSERT INTO available_fqdns VALUES (?,?,?,?,?,?,?,?,?)", (
            1, 310, "Example", "US", "epdg.epc.mnc001.mcc310.pub.3gppnetwork.org",
            "A", "epdg.epc", "ANSWERED", "192.0.2.10"))
        db.commit()
        db.close()
        return path

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, *args], cwd=ROOT, text=True,
            capture_output=True, check=False,
        )

    def test_graph_cli_json_and_csv_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = self.make_db(directory)
            output = Path(directory) / "graph.json"
            result = self.run_cli(
                "epdg/3gpppub-graph.py", "--db", str(db_path), "--summary",
                "--output", str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("'nodes': 4", result.stdout)
            payload = json.loads(output.read_text())
            self.assertEqual(len(payload["edges"]), 4)
            csv_result = self.run_cli(
                "epdg/3gpppub-graph.py", "--db", str(db_path), "--format", "csv",
                "--relationship", "resolves_to",
            )
            self.assertEqual(csv_result.returncode, 0, csv_result.stderr)
            self.assertIn("resolves_to", csv_result.stdout)

    def test_graph_help_is_available(self):
        result = self.run_cli("epdg/3gpppub-graph.py", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("PLMN-to-infrastructure", result.stdout)


if __name__ == "__main__":
    unittest.main()
