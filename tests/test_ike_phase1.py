"""Offline protocol, transport, and SQLite compatibility checks for Phase 1."""

import importlib.util
import json
import socket
import sqlite3
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

EPDG = Path(__file__).parents[1] / "epdg"
sys.path.insert(0, str(EPDG))
import ike_phase1 as ike

spec = importlib.util.spec_from_file_location("tls_ike", EPDG / "3gpppub-tls-ike-probe.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


def cookie_response(request):
    # RFC 7296: initial cookie challenges may have an all-zero responder SPI.
    return (request[:8] + bytes.fromhex(
        "0000000000000000 29202220 00000000 00000034"
        "00000018 00004006 00112233445566778899aabbccddeeff"))


class Phase1Tests(unittest.TestCase):
    def test_valid_sa_ke_nonce_proposal(self):
        request = ike.build_request()
        self.assertEqual(request[16:24], bytes.fromhex("2120220800000000"))
        self.assertEqual(struct.unpack("!I", request[24:28])[0], len(request))
        # SA (48), KE (264), Nonce (36); four RFC 7296 transforms.
        self.assertEqual(request[28:40], bytes.fromhex("220000300000002c01010004"))
        self.assertEqual(request[40:76], bytes.fromhex(
            "0300000c0100000c800e0080 0300000802000005"
            "030000080300000c 000000080400000e"))
        self.assertEqual(request[76:84], bytes.fromhex("28000108000e0000"))
        public = int.from_bytes(request[84:340], "big")
        self.assertGreater(public, 1)
        self.assertLess(public, ike.MODP_2048 - 1)
        self.assertEqual(request[340:344], bytes.fromhex("00000024"))
        self.assertEqual(len(request), 376)

    def test_cookie_and_natt_response(self):
        request = ike.build_request()
        for port, prefix in [(500, b""), (4500, b"\0" * 4)]:
            with self.subTest(port=port):
                result = ike.parse_response(prefix + cookie_response(request), request, 2, port)
                self.assertEqual(result["status"], "COOKIE_CHALLENGE")
                self.assertEqual(result["responded"], 1)
                self.assertEqual(result["notifications"][0]["name"], "COOKIE")
                self.assertEqual(result["responder_spi"], "0" * 16)

    def test_malformed_or_unmatched_responses_are_not_success(self):
        request = ike.build_request()
        valid = cookie_response(request)
        variants = [b"short", b"wrongspi" + valid[8:], valid[:17] + b"\x10" + valid[18:],
                    valid[:19] + b"\x08" + valid[20:], valid[:24] + b"\0" * 4 + valid[28:],
                    valid[:30] + b"\0\x03" + valid[32:], valid + b"trailing"]
        for response in variants:
            with self.subTest(response=response.hex()):
                with self.assertRaises(ValueError):
                    ike.parse_response(response, request, 2, 500)
        with self.assertRaises(ValueError):
            ike.parse_response(valid, request, 2, 4500)

    def test_ikev1_proposal_and_error_notify(self):
        request = ike.build_request(1)
        self.assertEqual(request[16:20], bytes.fromhex("01100200"))
        self.assertEqual(len(request), 76)
        # ISAKMP informational, DOI=IPSEC, NO_PROPOSAL_CHOSEN.
        response = request[:8] + b"\0" * 8 + bytes.fromhex(
            "0b1005000000000000000028 0000000c000000010100000e")
        result = ike.parse_response(response, request, 1, 500)
        self.assertEqual(result["status"], "IKE_NOTIFY_ERROR")
        self.assertEqual(result["notifications"][0]["name"], "NO_PROPOSAL_CHOSEN")

    def mock_probe(self, outcome, version=2, port=500, ip="81.23.22.231"):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.getsockname.return_value = ("192.0.2.10", 54321)
        if isinstance(outcome, Exception):
            sock.recv.side_effect = outcome
        elif outcome == "cookie":
            def receive(_):
                sent = sock.send.call_args.args[0]
                prefix = b"\0" * 4 if port == 4500 else b""
                return prefix + cookie_response(sent[len(prefix):])
            sock.recv.side_effect = receive
        else:
            sock.recv.return_value = outcome
        with patch.object(ike.socket, "socket", return_value=sock) as factory:
            result = ike.probe_phase1(ip, port, 0.1, version, "test-host")
        self.assertEqual(sock.send.call_count, 1)
        sock.__exit__.assert_called_once()
        return result, sock, factory

    def test_ipv6_nat_t_and_no_cookie_retries(self):
        result, sock, factory = self.mock_probe("cookie", port=4500, ip="2a02:2378:1000:80::7")
        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.connect.assert_called_once_with(("2a02:2378:1000:80::7", 4500))
        self.assertEqual(sock.send.call_args.args[0][:4], b"\0" * 4)
        self.assertEqual(result["status"], "COOKIE_CHALLENGE")
        self.assertEqual(result["local_ip"], "192.0.2.10")
        self.assertEqual(result["source_label"], "test-host")
        self.assertIsNotNone(result["rtt_ms"])

    def test_timeout_socket_error_and_invalid_reply_are_distinct(self):
        for outcome, status in [(socket.timeout(), "TIMEOUT"),
                                (OSError(101, "Network unreachable"), "SOCKET_ERROR"),
                                (b"garbage", "INVALID_RESPONSE")]:
            with self.subTest(status=status):
                result, _, _ = self.mock_probe(outcome)
                self.assertEqual(result["status"], status)
                self.assertEqual(result["responded"], 0)
                self.assertIsNotNone(result["error"])

    def test_existing_db_and_versioned_history(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        # Emulate a pre-feature database, then apply the extended schema twice.
        db.executescript(tool.SCHEMA_TLS_IKE.split("CREATE TABLE IF NOT EXISTS ike_phase1_observations")[0])
        target = dict(fqdn="epdg.example", ip="81.23.22.231", port=500,
                      operator="Kyivstar", country_name="Ukraine", mnc=3, mcc=255)
        db.execute("INSERT INTO ike_probes (fqdn,ip,port,responded) VALUES (?,?,?,1) "
                   "ON CONFLICT(fqdn,ip,port) DO UPDATE SET responded=1",
                   ("old.example", "81.23.22.231", 500))
        for _ in range(2):
            db.executescript(tool.SCHEMA_TLS_IKE)
        result, _, _ = self.mock_probe("cookie")
        tool.upsert_ike_probe(db, target, result)
        tool.upsert_ike_probe(db, target, result)  # retrying persistence is idempotent
        timeout, _, _ = self.mock_probe(socket.timeout())
        tool.upsert_ike_probe(db, target, timeout)
        v1, _, _ = self.mock_probe(socket.timeout(), version=1)
        tool.upsert_ike_probe(db, target, v1)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM ike_phase1_observations").fetchone()[0], 3)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM ike_probes").fetchone()[0], 2)
        self.assertEqual(db.execute("SELECT responded,weak_crypto FROM ike_probes WHERE fqdn='epdg.example'").fetchone(), (0, 0))
        self.assertEqual(db.execute("SELECT responded FROM ike_probes WHERE fqdn='old.example'").fetchone()[0], 1)
        stored = db.execute("SELECT notifications FROM ike_phase1_observations WHERE status='COOKIE_CHALLENGE'").fetchone()[0]
        self.assertEqual(json.loads(stored)[0]["type"], 16390)

    def test_target_filters_versions_and_loopback_exclusion(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        db.executescript("CREATE TABLE available_fqdns (fqdn TEXT PRIMARY KEY, service TEXT, "
                         "resolved_ips TEXT, operator TEXT, country_name TEXT, mnc INTEGER, mcc INTEGER, record_type TEXT)")
        for name, mnc, service, ips in [("target", 3, "epdg.epc", "81.23.22.231,127.0.0.1,invalid,81.23.22.231"),
                                       ("other-mnc", 6, "epdg.epc", "212.58.175.228"),
                                       ("tls", 3, "xcap.ims", "81.23.22.231")]:
            db.execute("INSERT INTO available_fqdns VALUES (?,?,?,'Test','Ukraine',?,255,'A') "
                       "ON CONFLICT(fqdn) DO UPDATE SET resolved_ips=excluded.resolved_ips", (name, service, ips, mnc))
        targets = tool.get_probe_targets(db, None, 255, 3, True, True)
        self.assertEqual(len(targets), 4)
        self.assertEqual({(t["port"], t["ike_version"]) for t in targets}, {(500, 1), (500, 2), (4500, 1), (4500, 2)})
        self.assertEqual({t["fqdn"] for t in targets}, {"target"})


if __name__ == "__main__":
    unittest.main()
