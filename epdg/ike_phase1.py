"""Bounded, unauthenticated IKE initiation probes and their observation schema.

One datagram per probe; no cookie retry, IKE_AUTH, or tunnel establishment.
Only the Python standard library is required.
"""

import ipaddress
import json
import os
import socket
import struct
import time
import uuid
from datetime import datetime, timezone


SCHEMA = """
CREATE TABLE IF NOT EXISTS ike_phase1_observations (
    observation_id TEXT PRIMARY KEY,
    fqdn TEXT NOT NULL,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    operator TEXT,
    country_name TEXT,
    mnc INTEGER,
    mcc INTEGER,
    ike_version INTEGER NOT NULL,
    stage TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source_label TEXT NOT NULL,
    local_ip TEXT,
    local_port INTEGER,
    timeout_seconds REAL NOT NULL,
    status TEXT NOT NULL,
    responded INTEGER NOT NULL,
    rtt_ms REAL,
    error TEXT,
    initiator_spi TEXT NOT NULL,
    responder_spi TEXT,
    proposal TEXT NOT NULL,
    response_hex TEXT,
    payload_types TEXT NOT NULL,
    notifications TEXT NOT NULL,
    vendor_ids TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ike_phase1_endpoint
    ON ike_phase1_observations(fqdn, ip, port, ike_version, observed_at);
"""

# RFC 3526 group 14, generator 2.
MODP_2048 = int("""
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", ""), 16)

PROPOSALS = {
    2: "AES-CBC-128/PRF-HMAC-SHA2-256/AUTH-HMAC-SHA2-256-128/MODP-2048",
    1: "AES-CBC-128/SHA1/PSK/MODP-2048 (proposal only)",
}
NOTIFICATIONS = {
    2: {14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD", 7: "INVALID_SYNTAX",
        16390: "COOKIE", 16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP"},
    1: {14: "NO_PROPOSAL_CHOSEN", 16: "PAYLOAD_MALFORMED"},
}


def build_request(version: int = 2) -> bytes:
    """Build IKEv2 SA+KE+Nonce or IKEv1 Main Mode's initial SA proposal."""
    if version not in PROPOSALS:
        raise ValueError("IKE version must be 1 or 2")
    spi = os.urandom(8)
    if version == 2:
        def transform(kind, identifier, last=False, attributes=b""):
            return struct.pack("!BBHBBH", 0 if last else 3, 0,
                               8 + len(attributes), kind, 0, identifier) + attributes

        transforms = b"".join([
            transform(1, 12, attributes=struct.pack("!HH", 0x800e, 128)),
            transform(2, 5), transform(3, 12), transform(4, 14, last=True),
        ])
        proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 4) + transforms
        sa = struct.pack("!BBH", 34, 0, 4 + len(proposal)) + proposal
        public_key = pow(2, int.from_bytes(os.urandom(40), "big") + 2, MODP_2048).to_bytes(256, "big")
        ke = struct.pack("!BBHHH", 40, 0, 264, 14, 0) + public_key
        nonce = struct.pack("!BBH", 0, 0, 36) + os.urandom(32)
        body = sa + ke + nonce
        first, exchange, flags = 33, 34, 0x08
    else:
        attributes = b"".join(struct.pack("!HH", 0x8000 | t, v)
                              for t, v in [(1, 7), (14, 128), (2, 2), (3, 1), (4, 14)])
        transform = struct.pack("!BBHBBH", 0, 0, 8 + len(attributes), 1, 1, 0) + attributes
        proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
        body = struct.pack("!BBHII", 0, 0, 12 + len(proposal), 1, 1) + proposal
        first, exchange, flags = 1, 2, 0
    return spi + b"\0" * 8 + struct.pack("!BBBBII", first, version << 4, exchange,
                                         flags, 0, 28 + len(body)) + body


def parse_response(data: bytes, request: bytes, version: int, port: int) -> dict:
    """Validate the response header and payload chain before claiming an IKE reply."""
    if port == 4500:
        if data[:4] != b"\0" * 4:
            raise ValueError("Missing UDP 4500 non-ESP marker")
        data = data[4:]
    if len(data) < 28:
        raise ValueError("Truncated IKE header")
    first, wire_version, exchange, flags, message_id, length = struct.unpack("!BBBBII", data[16:28])
    if data[:8] != request[:8] or wire_version != version << 4:
        raise ValueError("Initiator SPI or IKE version mismatch")
    if length != len(data) or message_id != 0:
        raise ValueError("IKE length or initial message ID mismatch")
    if version == 2 and (exchange != 34 or flags & 0x28 != 0x20):
        raise ValueError("Not an IKE_SA_INIT responder message")
    if version == 1 and (exchange not in (2, 5) or flags & 1):
        raise ValueError("Not a cleartext IKEv1 Main Mode/Informational response")
    payload_types, notifications, vendor_ids = [], [], []
    offset, kind = 28, first
    while kind:
        if offset + 4 > length:
            raise ValueError("Truncated payload header")
        next_kind, _, size = struct.unpack("!BBH", data[offset:offset + 4])
        if size < 4 or offset + size > length:
            raise ValueError("Invalid payload length")
        body = data[offset + 4:offset + size]
        payload_types.append(kind)
        if kind == (41 if version == 2 else 11):
            notify = body if version == 2 else body[4:]  # IKEv1 DOI precedes Notify
            if len(notify) < 4:
                raise ValueError("Truncated notification")
            protocol, spi_size, code = struct.unpack("!BBH", notify[:4])
            if len(notify) < 4 + spi_size:
                raise ValueError("Truncated notification SPI")
            notifications.append({"type": code, "name": NOTIFICATIONS[version].get(code, str(code)),
                                  "protocol_id": protocol, "data_hex": notify[4 + spi_size:].hex()})
        elif kind == (43 if version == 2 else 13):
            vendor_ids.append(body.hex())
        offset += size
        kind = next_kind
    if offset != length or not payload_types:
        raise ValueError("Empty payload chain or trailing bytes")
    if version == 2 and any(n["type"] == 16390 for n in notifications):
        status = "COOKIE_CHALLENGE"
    elif any(n["type"] < 16384 for n in notifications):
        status = "IKE_NOTIFY_ERROR"
    else:
        status = "IKE_RESPONSE"
    return {"responded": 1, "status": status, "responder_spi": data[8:16].hex(),
            "payload_types": payload_types, "notifications": notifications, "vendor_ids": vendor_ids}


def probe_phase1(ip: str, port: int, timeout: float, version: int = 2,
                 source_label: str = "local-host") -> dict:
    """Send one initiation packet, recording silence separately from socket errors.

    local_ip is the socket address before any NAT, not a claimed public source IP.
    Invalid datagrams are retained but never counted as matched IKE responses.
    """
    if timeout <= 0 or port not in (500, 4500):
        raise ValueError("A positive timeout and UDP port 500 or 4500 are required")
    address = ipaddress.ip_address(ip)
    request = build_request(version)
    result = {
        "observation_id": str(uuid.uuid4()), "ike_version": version,
        "stage": "IKE_SA_INIT" if version == 2 else "MAIN_MODE_SA",
        "observed_at": datetime.now(timezone.utc).isoformat(), "source_label": source_label,
        "local_ip": None, "local_port": None, "timeout_seconds": timeout,
        "status": "TIMEOUT", "responded": 0, "rtt_ms": None, "error": None,
        "initiator_spi": request[:8].hex(), "responder_spi": None,
        "proposal": PROPOSALS[version], "response_hex": None,
        "payload_types": [], "notifications": [], "vendor_ids": [],
    }
    try:
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))  # Kernel restricts replies to this endpoint.
            result["local_ip"], result["local_port"] = sock.getsockname()[:2]
            start = time.monotonic()
            sock.send((b"\0" * 4 if port == 4500 else b"") + request)
            data = sock.recv(65535)
            result["rtt_ms"] = round((time.monotonic() - start) * 1000, 3)
            result["response_hex"] = data.hex()
            try:
                result.update(parse_response(data, request, version, port))
            except ValueError as exc:
                result.update(status="INVALID_RESPONSE", error=str(exc))
    except socket.timeout:
        result["error"] = f"No UDP reply within {timeout:g} seconds"
    except OSError as exc:
        result.update(status="SOCKET_ERROR", error=f"{type(exc).__name__}: {exc}")
    return result


def save_observation(conn, target: dict, result: dict) -> None:
    row = {key: target.get(key) for key in ("fqdn", "ip", "port", "operator", "country_name", "mnc", "mcc")}
    row.update(result)
    for key in ("payload_types", "notifications", "vendor_ids"):
        row[key] = json.dumps(row[key])
    columns = ", ".join(row)
    placeholders = ", ".join(f":{key}" for key in row)
    updates = ", ".join(f"{key}=excluded.{key}" for key in row if key != "observation_id")
    conn.execute(f"INSERT INTO ike_phase1_observations ({columns}) VALUES ({placeholders}) "
                 f"ON CONFLICT(observation_id) DO UPDATE SET {updates}", row)
