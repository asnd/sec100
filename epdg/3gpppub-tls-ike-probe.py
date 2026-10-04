#!/usr/bin/env python3
"""
Feature: TLS & IKEv2 Endpoint Intelligence + Vendor Fingerprinting
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Connects to already-discovered 3GPP endpoints and fingerprints their TLS
certificates and IKE endpoints (validated initiation replies and vendor IDs).

Reads FQDNs from available_fqdns WHERE service IN (xcap.ims, pcscf.ims, rcs,
ims, epdg.epc) and resolves the appropriate port/protocol from SERVICE_TO_PORT.

New tables created:
  tls_certs   — TLS certificate metadata per (fqdn, ip, port)
  ike_probes  — IKEv2 probe results per (fqdn, ip, port)
  ike_phase1_observations — timestamped IKEv2/IKEv1 results with source context

Usage:
  # Dry-run: show what WOULD be probed and display existing DB results
  python3 3gpppub-tls-ike-probe.py --db database.db

  # Active probing (real connections)
  python3 3gpppub-tls-ike-probe.py --db database.db --active

  # Active probing with custom parallelism and timeout
  python3 3gpppub-tls-ike-probe.py --db database.db --active --workers 20 --timeout 5

  # Limit rows and show summary only
  python3 3gpppub-tls-ike-probe.py --db database.db --active --limit 100 --summary-only

  # Summary of previously collected results
  python3 3gpppub-tls-ike-probe.py --db database.db --summary-only

  # Probe Kyivstar IKEv2 plus optional IKEv1, with one datagram per IP/port/version
  python3 3gpppub-tls-ike-probe.py --db database.db --active --ike-only --ikev1 --mcc 255 --mnc 3
"""

import argparse
import ipaddress
import logging
import socket
import sqlite3
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent))
from ike_phase1 import SCHEMA as SCHEMA_PHASE1, build_request, probe_phase1, save_observation

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)

# ── Service → port/protocol map ───────────────────────────────────────────────

SERVICE_TO_PORT: Dict[str, List[Tuple[int, str]]] = {
    "xcap.ims":  [(443, "tls")],
    "pcscf.ims": [(443, "tls"), (5061, "tls")],
    "rcs":       [(443, "tls")],
    "ims":       [(443, "tls")],
    "epdg.epc":  [(500, "ike"), (4500, "ike")],
}

# ── DB schema ─────────────────────────────────────────────────────────────────

SCHEMA_TLS_IKE = """
CREATE TABLE IF NOT EXISTS tls_certs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn           TEXT    NOT NULL,
    ip             TEXT    NOT NULL,
    port           INTEGER NOT NULL,
    operator       TEXT,
    country_name   TEXT,
    mnc            INTEGER,
    mcc            INTEGER,
    subject        TEXT,
    issuer         TEXT,
    san            TEXT,
    not_before     INTEGER,
    not_after      INTEGER,
    key_type       TEXT,
    key_bits       INTEGER,
    sig_algorithm  TEXT,
    vendor         TEXT,
    is_expired     INTEGER DEFAULT 0,
    is_self_signed INTEGER DEFAULT 0,
    is_weak_sig    INTEGER DEFAULT 0,
    first_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn, ip, port)
);

CREATE TABLE IF NOT EXISTS ike_probes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn           TEXT    NOT NULL,
    ip             TEXT    NOT NULL,
    port           INTEGER NOT NULL,
    operator       TEXT,
    country_name   TEXT,
    mnc            INTEGER,
    mcc            INTEGER,
    responded      INTEGER DEFAULT 0,
    vendor_ids     TEXT,
    weak_crypto    INTEGER DEFAULT 0,
    weak_reasons   TEXT,
    first_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn, ip, port)
);

CREATE INDEX IF NOT EXISTS idx_tls_fqdn   ON tls_certs(fqdn);
CREATE INDEX IF NOT EXISTS idx_tls_vendor ON tls_certs(vendor);
CREATE INDEX IF NOT EXISTS idx_ike_fqdn   ON ike_probes(fqdn);
""" + SCHEMA_PHASE1

# ── Known IKEv2 Vendor ID hex prefixes ────────────────────────────────────────

IKE_VENDOR_IDS: Dict[str, str] = {
    "4048b7d56ebce885": "OpenIKEv2",
    "afcad71368a1f1c9": "DPD-RFC3706",
    "90cb80913ebb696e": "IKE-fragmentation",
    "4a131c81070358455c5728f20e95452f": "IKE-NAT-T-RFC3947",
    "7d9419a65310ca6f2c179d9215529d56": "draft-ietf-ipsec-nat-t-ike-02",
    "cd60464335df21f87cfdb2fc68b6a448": "draft-ietf-ipsec-nat-t-ike-03",
    "8f8d83826d246b6fc7a8a6a428c11de8": "draft-ietf-ipsec-nat-t-ike-04",
    "9909b64eed937c6573de52ace952fa6b": "draft-ietf-ipsec-nat-t-ike-05",
    "4d1e0e136deafa34c4f3ea9f02ec7285": "draft-ietf-ipsec-nat-t-ike-06",
    "439b59f8ba676c4c7737ae22eab8f582": "draft-ietf-ipsec-nat-t-ike-07",
    "3947a0fde8dc4768db34557c2bda31a2": "Cisco-Unity",
    "12f5f28c457168a9702d9fe274cc0100": "Cisco-VPN-Concentrator",
    "09002689dfd6b712": "XAUTH",
}


# ── TLS vendor fingerprinting ─────────────────────────────────────────────────

def fingerprint_tls_vendor(issuer_cn: str, issuer_o: str, sans: list[str]) -> str:
    """
    Identify the telecom vendor/PKI from the certificate issuer fields and SANs.
    Returns a human-readable vendor label.
    """
    haystack = " ".join([issuer_cn or "", issuer_o or ""] + sans).upper()
    if "ERICSSON" in haystack:
        return "Ericsson"
    if "NOKIA" in haystack or "NSN" in haystack:
        return "Nokia"
    if "HUAWEI" in haystack:
        return "Huawei"
    if "CISCO" in haystack:
        return "Cisco"
    if "MAVENIR" in haystack:
        return "Mavenir"
    if "ORACLE" in haystack:
        return "Oracle"
    if "THALES" in haystack or "GEMALTO" in haystack:
        return "Thales"
    if "IDEMIA" in haystack or "OBERTHUR" in haystack:
        return "IDEMIA"
    if "VALID" in haystack:
        return "Valid"
    return "Unknown"


# ── TLS probe ─────────────────────────────────────────────────────────────────

def probe_tls(fqdn: str, ip: str, port: int, timeout: float) -> Optional[Dict]:
    """
    Open a TLS connection to ip:port and extract certificate metadata.
    Returns a dict on success, None on failure.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        raw_sock = socket.create_connection((ip, port), timeout=timeout)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=fqdn)
        try:
            cert_dict = tls_sock.getpeercert()
        finally:
            tls_sock.close()
    except Exception as exc:
        log.debug("TLS %s:%d (%s) failed: %s", fqdn, port, ip, exc)
        return None

    if not cert_dict:
        return None

    def _rdn(rdn_seq, oid: str) -> str:
        for rdn in rdn_seq:
            for attr in rdn:
                if attr[0] == oid:
                    return attr[1]
        return ""

    subject_seq = cert_dict.get("subject", ())
    issuer_seq  = cert_dict.get("issuer", ())
    subject_cn  = _rdn(subject_seq, "commonName")
    subject_o   = _rdn(subject_seq, "organizationName")
    issuer_cn   = _rdn(issuer_seq, "commonName")
    issuer_o    = _rdn(issuer_seq, "organizationName")

    subject_str = f"CN={subject_cn}" + (f", O={subject_o}" if subject_o else "")
    issuer_str  = f"CN={issuer_cn}"  + (f", O={issuer_o}"  if issuer_o  else "")

    san_list: List[str] = []
    for san_type, san_val in cert_dict.get("subjectAltName", ()):
        san_list.append(f"{san_type}:{san_val}")
    san_str = ", ".join(san_list)

    not_before_str = cert_dict.get("notBefore", "")
    not_after_str  = cert_dict.get("notAfter",  "")
    not_before = int(ssl.cert_time_to_seconds(not_before_str)) if not_before_str else 0
    not_after  = int(ssl.cert_time_to_seconds(not_after_str))  if not_after_str  else 0

    sig_algorithm = cert_dict.get("signatureAlgorithm", "")
    is_expired     = 1 if (not_after and time.time() > not_after)       else 0
    is_self_signed = 1 if (issuer_cn == subject_cn and issuer_cn != "") else 0
    is_weak_sig    = 1 if any(w in sig_algorithm.lower() for w in ("sha1", "md5")) else 0

    vendor = fingerprint_tls_vendor(issuer_cn, issuer_o, san_list)

    # Key info is not always available from getpeercert(); best-effort
    key_type = None
    key_bits = None
    # Binary certificate decoding would require an additional library.

    return {
        "subject":       subject_str,
        "issuer":        issuer_str,
        "san":           san_str,
        "not_before":    not_before,
        "not_after":     not_after,
        "key_type":      key_type,
        "key_bits":      key_bits,
        "sig_algorithm": sig_algorithm,
        "vendor":        vendor,
        "is_expired":    is_expired,
        "is_self_signed": is_self_signed,
        "is_weak_sig":   is_weak_sig,
    }


# ── IKEv2 probe ───────────────────────────────────────────────────────────────

def _build_ike_sa_init() -> bytes:
    """Build a complete SA/KE/Nonce initiation request."""
    return build_request(2)


def _match_vendor_id(vid_hex: str) -> str:
    """Return a label if the hex string matches a known Vendor ID prefix."""
    vid_lower = vid_hex.lower()
    for prefix, label in IKE_VENDOR_IDS.items():
        if vid_lower.startswith(prefix):
            return label
    return ""


def probe_ike(fqdn: str, ip: str, port: int, timeout: float,
              version: int = 2, source_label: str = "local-host") -> Dict:
    """Return a detailed Phase 1 observation, without completing authentication."""
    return probe_phase1(ip, port, timeout, version, source_label)


# ── DB helpers ────────────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_TLS_IKE)
    conn.commit()
    return conn


def get_probe_targets(conn: sqlite3.Connection, limit: Optional[int],
                      mcc: int | None = None, mnc: int | None = None,
                      ike_only: bool = False, ikev1: bool = False,
                      source_label: str = "local-host") -> List[Dict]:
    """
    Return rows from available_fqdns for services we can probe.
    Each row is expanded to one target per (fqdn, ip, port, protocol).
    """
    services = ["epdg.epc"] if ike_only else list(SERVICE_TO_PORT.keys())
    placeholders = ",".join("?" * len(services))
    query = f"""
        SELECT fqdn, resolved_ips, service, operator, country_name, mnc, mcc
        FROM available_fqdns
        WHERE service IN ({placeholders})
          AND resolved_ips IS NOT NULL
          AND resolved_ips != ''
    """
    params = list(services)
    for column, value in (("mcc", mcc), ("mnc", mnc)):
        if value is not None:
            query += f" AND {column} = ?"
            params.append(value)
    query += " ORDER BY fqdn, record_type"
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)

    rows = conn.execute(query, params).fetchall()
    targets = []
    seen = set()
    for row in rows:
        fqdn    = row["fqdn"]
        service = row["service"]
        for ip in (i.strip() for i in (row["resolved_ips"] or "").split(",") if i.strip()):
            try:
                address = ipaddress.ip_address(ip)
            except ValueError:
                log.debug("Skipping invalid address %s for %s", ip, fqdn)
                continue
            if not address.is_global:
                continue
            ip = str(address)
            for port, proto in SERVICE_TO_PORT.get(service, []):
                versions = ([2, 1] if ikev1 else [2]) if proto == "ike" else [None]
                for version in versions:
                    key = (fqdn, ip, port, proto, version)
                    if key in seen:
                        continue
                    seen.add(key)
                    targets.append({
                        "fqdn":         fqdn,
                        "ip":           ip,
                        "port":         port,
                        "proto":        proto,
                        "operator":     row["operator"],
                        "country_name": row["country_name"],
                        "mnc":          row["mnc"],
                        "mcc":          row["mcc"],
                        "ike_version":  version,
                        "source_label": source_label,
                    })
    return targets


def upsert_tls_cert(conn: sqlite3.Connection, target: dict, cert: dict) -> None:
    conn.execute(
        """
        INSERT INTO tls_certs
            (fqdn, ip, port, operator, country_name, mnc, mcc,
             subject, issuer, san, not_before, not_after,
             key_type, key_bits, sig_algorithm, vendor,
             is_expired, is_self_signed, is_weak_sig)
        VALUES
            (:fqdn, :ip, :port, :operator, :country_name, :mnc, :mcc,
             :subject, :issuer, :san, :not_before, :not_after,
             :key_type, :key_bits, :sig_algorithm, :vendor,
             :is_expired, :is_self_signed, :is_weak_sig)
        ON CONFLICT(fqdn, ip, port) DO UPDATE SET
            subject       = excluded.subject,
            issuer        = excluded.issuer,
            san           = excluded.san,
            not_before    = excluded.not_before,
            not_after     = excluded.not_after,
            key_type      = excluded.key_type,
            key_bits      = excluded.key_bits,
            sig_algorithm = excluded.sig_algorithm,
            vendor        = excluded.vendor,
            is_expired    = excluded.is_expired,
            is_self_signed = excluded.is_self_signed,
            is_weak_sig   = excluded.is_weak_sig
        """,
        {**target, **cert},
    )


def upsert_ike_probe(conn: sqlite3.Connection, target: dict, probe: dict) -> None:
    save_observation(conn, target, probe)
    if probe["ike_version"] != 2:
        return
    # Maintain the legacy latest-IKEv2 table for existing consumers. An unknown
    # vendor or a cookie challenge is not evidence of weak cryptography.
    legacy = {
        **probe,
        "vendor_ids": ", ".join(_match_vendor_id(vid) or vid for vid in probe["vendor_ids"]),
        "weak_crypto": 0, "weak_reasons": "",
    }
    conn.execute(
        """
        INSERT INTO ike_probes
            (fqdn, ip, port, operator, country_name, mnc, mcc,
             responded, vendor_ids, weak_crypto, weak_reasons)
        VALUES
            (:fqdn, :ip, :port, :operator, :country_name, :mnc, :mcc,
             :responded, :vendor_ids, :weak_crypto, :weak_reasons)
        ON CONFLICT(fqdn, ip, port) DO UPDATE SET
            responded   = excluded.responded,
            vendor_ids  = excluded.vendor_ids,
            weak_crypto = excluded.weak_crypto,
            weak_reasons = excluded.weak_reasons
        """,
        {**target, **legacy},
    )


# ── Worker function ───────────────────────────────────────────────────────────

def probe_target(target: Dict, timeout: float) -> Tuple[Dict, Optional[Dict], Optional[Dict]]:
    """
    Probe a single (fqdn, ip, port, proto) target.
    Returns (target, tls_result_or_None, ike_result_or_None).
    """
    if target["proto"] == "tls":
        tls = probe_tls(target["fqdn"], target["ip"], target["port"], timeout)
        return target, tls, None
    else:  # ike
        ike = probe_ike(target["fqdn"], target["ip"], target["port"], timeout,
                        target.get("ike_version", 2), target.get("source_label", "local-host"))
        return target, None, ike


# ── Summary ───────────────────────────────────────────────────────────────────

def print_summary(conn: sqlite3.Connection) -> None:
    # ── TLS summary ──────────────────────────────────────────────────────────
    print("\n─── TLS Certificate Summary ─────────────────────────────────────────")
    tls_total = conn.execute("SELECT COUNT(*) FROM tls_certs").fetchone()[0]
    print(f"  Total TLS certs collected : {tls_total}")
    if tls_total:
        expired     = conn.execute("SELECT COUNT(*) FROM tls_certs WHERE is_expired=1").fetchone()[0]
        self_signed = conn.execute("SELECT COUNT(*) FROM tls_certs WHERE is_self_signed=1").fetchone()[0]
        weak_sig    = conn.execute("SELECT COUNT(*) FROM tls_certs WHERE is_weak_sig=1").fetchone()[0]
        print(f"  Expired certs             : {expired}")
        print(f"  Self-signed certs         : {self_signed}")
        print(f"  Weak signature (MD5/SHA1) : {weak_sig}")

        print("\n─── TLS Vendor Distribution ─────────────────────────────────────────")
        vendor_rows = conn.execute(
            """
            SELECT vendor, COUNT(*) AS cnt
            FROM tls_certs
            WHERE vendor IS NOT NULL
            GROUP BY vendor
            ORDER BY cnt DESC
            """
        ).fetchall()
        total = sum(r[1] for r in vendor_rows) or 1
        for vendor, cnt in vendor_rows:
            bar = "█" * int(30 * cnt / total)
            print(f"  {vendor:<20} {cnt:>5}  {bar}")

        print("\n─── TLS: Operators with expired certs ───────────────────────────────")
        expired_ops = conn.execute(
            """
            SELECT DISTINCT operator, country_name
            FROM tls_certs
            WHERE is_expired = 1
            ORDER BY country_name, operator
            LIMIT 20
            """
        ).fetchall()
        for op, country in expired_ops:
            print(f"  [{country or '??'}] {op}")

    # ── IKE summary ──────────────────────────────────────────────────────────
    print("\n─── IKEv2 Probe Summary ──────────────────────────────────────────────")
    ike_total = conn.execute("SELECT COUNT(*) FROM ike_probes").fetchone()[0]
    print(f"  Total IKE probes stored   : {ike_total}")
    if ike_total:
        responded   = conn.execute("SELECT COUNT(*) FROM ike_probes WHERE responded=1").fetchone()[0]
        weak_crypto = conn.execute("SELECT COUNT(*) FROM ike_probes WHERE weak_crypto=1").fetchone()[0]
        print(f"  Responded                 : {responded}")
        print(f"  Legacy weak-crypto flags  : {weak_crypto}")

        print("\n─── IKEv2 Vendor ID Distribution ────────────────────────────────────")
        vid_rows = conn.execute(
            """
            SELECT vendor_ids, COUNT(*) AS cnt
            FROM ike_probes
            WHERE responded = 1 AND vendor_ids IS NOT NULL AND vendor_ids != ''
            GROUP BY vendor_ids
            ORDER BY cnt DESC
            LIMIT 15
            """
        ).fetchall()
        for vids, cnt in vid_rows:
            print(f"  {vids[:55]:<55} {cnt:>4}")

    print("\n─── IKE Phase 1 Observation History ─────────────────────────────────")
    for version, source, status, count in conn.execute(
        "SELECT ike_version, source_label, status, COUNT(*) FROM ike_phase1_observations "
        "GROUP BY ike_version, source_label, status ORDER BY ike_version, source_label, status"
    ):
        print(f"  IKEv{version}  {source}  {status}: {count}")
    print("  TIMEOUT means no reply from this vantage point; it does not establish downtime.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Probe 3GPP endpoints for TLS certificate and IKEv2 intelligence."
    )
    parser.add_argument("--db",           default="database.db",
                        help="Path to the SQLite database (default: database.db)")
    parser.add_argument("--active",       action="store_true", default=False,
                        help="Perform real connections (default: dry-run / summary only)")
    parser.add_argument("--workers",      type=int, default=10,
                        help="Concurrent probe workers (default: 10)")
    parser.add_argument("--timeout",      type=float, default=5.0,
                        help="Per-connection timeout in seconds (default: 5.0)")
    parser.add_argument("--limit",        type=int, default=None,
                        help="Max FQDN rows to probe (default: all)")
    parser.add_argument("--summary-only", action="store_true",
                        help="Print existing DB summary and exit (no probing)")
    parser.add_argument("--ike-only", action="store_true", help="Probe only ePDG IKE endpoints")
    parser.add_argument("--ikev1", action="store_true", help="Also send one IKEv1 Main Mode SA proposal per endpoint")
    parser.add_argument("--mcc", type=int, help="Filter targets by MCC (e.g. 255)")
    parser.add_argument("--mnc", type=int, help="Filter targets by MNC (e.g. 3)")
    parser.add_argument("--source-label", default="local-host",
                        help="Descriptive label for this execution host; does not select a remote probe")
    args = parser.parse_args()
    if args.workers < 1 or args.timeout <= 0 or (args.limit is not None and args.limit < 1):
        parser.error("--workers, --timeout and --limit must be positive")

    if not Path(args.db).is_file():
        log.error("Database %s not found. Run the population script first.", args.db)
        sys.exit(1)

    conn = init_db(args.db)

    if args.summary_only:
        print_summary(conn)
        conn.close()
        return

    targets = get_probe_targets(conn, args.limit, args.mcc, args.mnc,
                                args.ike_only, args.ikev1, args.source_label)

    if not targets:
        log.info("No probe targets found. Run a DNS scan first.")
        print_summary(conn)
        conn.close()
        return

    tls_targets = [t for t in targets if t["proto"] == "tls"]
    ike_targets = [t for t in targets if t["proto"] == "ike"]
    log.info(
        "Found %d probe targets  (%d TLS, %d IKE)",
        len(targets), len(tls_targets), len(ike_targets),
    )

    if not args.active:
        print("\n[DRY-RUN] Pass --active to perform real connections.")
        print(f"  Would probe {len(tls_targets)} TLS endpoint(s) and {len(ike_targets)} IKE endpoint(s).")
        print("\nSample targets (up to 10):")
        for t in targets[:10]:
            protocol = f"IKEv{t['ike_version']}" if t["proto"] == "ike" else "TLS"
            print(f"  {protocol:>5}  {t['fqdn']}  [{t['ip']}]:{t['port']}")
        print_summary(conn)
        conn.close()
        return

    log.info("Starting probes with %d workers, %.1fs timeout …", args.workers, args.timeout)

    tls_ok = tls_fail = ike_responded = ike_silent = 0
    commit_batch = 50

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(probe_target, t, args.timeout): t for t in targets
        }
        pending = len(futures)
        done    = 0

        for future in as_completed(futures):
            done += 1
            try:
                target, tls_result, ike_result = future.result()
            except Exception as exc:
                log.warning("Probe worker exception: %s", exc)
                continue

            if tls_result is not None:
                upsert_tls_cert(conn, target, tls_result)
                tls_ok += 1
            elif target["proto"] == "tls":
                tls_fail += 1

            if ike_result is not None:
                upsert_ike_probe(conn, target, ike_result)
                log.info("IKEv%d %s [%s]:%d: %s%s", ike_result["ike_version"], target["fqdn"],
                         target["ip"], target["port"], ike_result["status"],
                         f" — {ike_result['error']}" if ike_result["error"] else "")
                if ike_result["responded"]:
                    ike_responded += 1
                else:
                    ike_silent += 1

            if done % commit_batch == 0:
                conn.commit()
                log.info(
                    "Progress %d/%d — TLS ok=%d fail=%d | IKE responded=%d no-matched-reply=%d",
                    done, pending, tls_ok, tls_fail, ike_responded, ike_silent,
                )

    conn.commit()
    log.info(
        "Done. TLS: %d collected, %d failed. IKE: %d responded, %d without a matched reply.",
        tls_ok, tls_fail, ike_responded, ike_silent,
    )
    print_summary(conn)
    conn.close()


if __name__ == "__main__":
    main()
