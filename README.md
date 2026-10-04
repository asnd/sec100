# sec100 — 3GPP Network Security Research Toolkit

A multi-component toolkit for researching 3GPP network infrastructure:
discovery, scanning, analysis, and visualisation of mobile operator services.

## Components

| Component | Language | Description |
|---|---|---|
| `go-3gpp-scanner/` | Go 1.24 | High-performance concurrent DNS scanner, cross-platform builds |
| `epdg/` | Python 3.11 | DNS population, ASN enrichment, 5G discovery, Streamlit dashboard |

---

## Go Scanner (`go-3gpp-scanner/`)

High-performance, cross-platform binary for scanning 3GPP public DNS records.

```bash
cd go-3gpp-scanner
make build-linux-x86
./bin/3gpp-scanner-linux-x86_64 --help

# Build all platforms (Linux x86/ARM, macOS, Windows)
make build-all
```

See [GEMINI.md](./GEMINI.md) for architecture and CI build details.

---

## Python Toolkit (`epdg/`)

### What is `pub.3gppnetwork.org`?

Mobile operators publish service endpoints here so phones can discover
operator infrastructure from untrusted networks (Wi-Fi, internet).

| Service | Purpose |
|---|---|
| `epdg.epc.*` | ePDG — VoWiFi / Wi-Fi Calling gateway (IKEv2) |
| `ss.epdg.epc.*` | ePDG steering / load-balancing prefix (T-Mobile US) |
| `sos.epdg.epc.*` | Emergency ePDG for SOS calls over Wi-Fi |
| `vowifi.*` | Non-standard VoWiFi alias (AT&T, some US operators) |
| `n3iwf.5gc.*` | N3IWF — 5G untrusted non-3GPP access (replaces ePDG in 5GS) |
| `ims.*` | IMS core — VoLTE registration |
| `pcscf.ims.*` | P-CSCF discovery — SIP signaling entry point |
| `mmtel.ims.*` | MMTel supplementary services (call forwarding, barring) |
| `xcap.ims.*` | XCAP — device / supplementary service config |
| `ut.ims.*` | Ut interface — supplementary service config (TS 24.623) |
| `sos.*` | SOS / Emergency services |
| `sos.ims.*` | Emergency IMS |
| `aes.*` | Auth/Emergency services (T-Mobile MX, MCC 334) |
| `bsf.*` | Bootstrapping Server Function — 5G authentication (TS 33.220) |
| `gan.*` | GAN/UMA — unlicensed access network |
| `rcs.*` | Rich Communication Services (GSMA IR.94) |
| `subs.*` | Subscription/provisioning (Canadian MNOs, MCC 302) |
| `cota-sdk.*` | COTA — Carrier Over-The-Air config endpoint (T-Mobile MX) |

### Quick Start

```bash
pip install -r epdg/requirements.txt

# Scan all operators into SQLite
python3 epdg/3gpppub-dns-database-population.py --workers 20

# Launch dashboard
streamlit run epdg/stream-oplookup.py
```

### Scripts

| Script | Feature | Description |
|---|---|---|
| `3gpppub-dns-database-population.py` | Core | Parallel DNS scanner → SQLite |
| `3gpppub-asn-enricher.py` | 1 | BGP/ASN enrichment via Team Cymru; cloud provider fingerprinting |
| `3gpppub-5g-discovery.py` | 2 | 5G SA NF discovery (NRF, SEPP, AMF…) + DANE TLSA probing |
| `3gpppub-diff.py` | 3 | Snapshot + change detection across scan runs |
| `3gpppub-naptr-discovery.py` | 4 | NAPTR/SRV probing — IMS SIP topology, P-CSCF routing |
| `stream-oplookup.py` | 5 | 8-tab Streamlit dashboard: capability scoring, ASN/hosting, relationship graph |
| `3gpppub-graph.py` | 1 | PLMN → service → FQDN → IP/ASN/provider and NAPTR/SRV graph export |
| `3gpppub-resolver-compare.py` | 2 | Resolver/vantage comparison with response, TTL, DNSSEC and answer evidence |
| `3gpppub-dns-health.py` | 3 | Authoritative NS/SOA/CNAME, DNSSEC and nameserver health checks |
| `3gpppub-grx-access.py` | — | GRX/IPX DNS helper: RIPE Atlas, open-resolver discovery, zone walk |
| `3gpppub-dns-checker.py` | — | Lightweight TSV checker (no DB required) |

The 5G discovery script supports the TS 23.003 N3IWF discovery forms:

```bash
# Probe operator and visited-country N3IWF names through public DNS
python3 epdg/3gpppub-5g-discovery.py --nf-types nrf sepp --include-pub-zone

# Add 5GS TAI-based discovery; TAC accepts decimal or 0x-prefixed hex
python3 epdg/3gpppub-5g-discovery.py --tac 0x0B1A21 0x1234

# Use an authorized GRX/IPX resolver and label the source as GRX
python3 epdg/3gpppub-5g-discovery.py --dns-server 192.0.2.53 --tac 0x0B1A21

# Build and export the current relationship graph
python3 epdg/3gpppub-graph.py --db epdg/database.db --summary --output graph.json

# Compare system DNS with an authorized resolver and retain evidence
python3 epdg/3gpppub-resolver-compare.py \
  epdg.epc.mnc001.mcc310.pub.3gppnetwork.org \
  --resolver system --resolver grx=192.0.2.53 --source-country NO --json

# Check delegation health and persist the result
python3 epdg/3gpppub-dns-health.py pub.3gppnetwork.org --json
```

TAI, visited-country, onboarding, NAPTR replacement, DNS source, and resolver
observations are stored in `fiveg_fqdns`. See [ROADMAP.md](ROADMAP.md) for the
broader telco discovery roadmap and comparable tools.

The graph exporter keeps a current materialized view in `graph_nodes` and
`graph_edges`, while retaining inactive historical nodes and edges. It links
shared infrastructure across operators and can emit JSON, CSV, or TSV for
analysis in other tools.

### Operator Capability Scoring (0–120 pts)

| Service | Points | Indicator |
|---|---|---|
| VoWiFi (ePDG) | +20 | `epdg.epc.*` record present |
| 5G VoWiFi (N3IWF) | +15 | `n3iwf.5gc.*` record present |
| VoLTE (IMS) | +15 | `ims.*` record present |
| P-CSCF discovery | +10 | `pcscf.ims.*` record present |
| Device Mgmt (XCAP) | +10 | `xcap.ims.*` record present |
| 5G Auth (BSF) | +10 | `bsf.*` record present |
| RCS messaging | +10 | `rcs.*` record present |
| Emergency SOS | +5 | `sos.*` record present |
| UMA/GAN | +5 | `gan.*` record present |
| 5G SA (NRF/SEPP) | +20 | NRF/SEPP in `fiveg_fqdns` |

### Typical Workflow

```bash
python3 epdg/3gpppub-dns-database-population.py --workers 20
python3 epdg/3gpppub-asn-enricher.py
python3 epdg/3gpppub-naptr-discovery.py
python3 epdg/3gpppub-diff.py --snapshot --label "$(date +%Y-%m-%d)"
streamlit run epdg/stream-oplookup.py
```

### IKEv2 / IPsec Phase 1 reachability

`epdg/3gpppub-tls-ike-probe.py` reads discovered public addresses from
`available_fqdns`. It sends a complete IKEv2 `IKE_SA_INIT` (SA, MODP-2048 key
exchange, nonce), supports IPv4/IPv6 and the UDP 4500 non-ESP marker, and
optionally sends an IKEv1 Main Mode SA proposal. Each IP/port/version receives
one packet; there are no retransmissions, cookie retries, or authentication.
Loopback placeholders such as `127.0.0.1` and other non-global addresses are skipped.

```bash
# Preview Kyivstar targets from an existing scanner SQLite database
python3 epdg/3gpppub-tls-ike-probe.py --db /path/to/database.db \
  --ike-only --mcc 255 --mnc 3

# Run IKEv2 plus IKEv1 on UDP 500/4500 and persist outcomes
python3 epdg/3gpppub-tls-ike-probe.py --db /path/to/database.db \
  --active --ike-only --ikev1 --mcc 255 --mnc 3 \
  --workers 2 --timeout 6 --source-label local-host

python3 epdg/3gpppub-tls-ike-probe.py --db /path/to/database.db --summary-only
```

The additive schema creates `ike_phase1_observations` automatically in existing
databases, retaining each run separately by observation ID. It stores UTC time,
endpoint, IKE version/stage, offered proposal, source label, local socket address,
timeout, RTT, raw response hex, validated payload types, notifications, vendor
IDs, and any error. The existing `ike_probes` table remains the latest IKEv2
summary; IKEv1 observations do not overwrite it.

| Status | Meaning |
|---|---|
| `COOKIE_CHALLENGE` | Matching IKEv2 responder requested a cookie; no retry sent |
| `IKE_NOTIFY_ERROR` | Matching IKE error notification, e.g. `NO_PROPOSAL_CHOSEN` |
| `IKE_RESPONSE` | Other matching initial IKE response; authentication not completed |
| `TIMEOUT` | No UDP reply before the configured timeout |
| `SOCKET_ERROR` | Transport error, e.g. network unreachable or connection refused |
| `INVALID_RESPONSE` | Datagram received but not a valid, matching initial IKE reply |

Cookie challenges and error notifications demonstrate a responding IKE endpoint.
Silence does not establish downtime, and an unknown vendor does not establish weak
cryptography. `--source-label` describes the host executing the command; it does
not select a remote Ukrainian probe. `local_ip` is the pre-NAT socket address,
not necessarily the public source IP. Public ping looking glasses cannot execute
these IKE probes.

To inspect the stored evidence with a SQLite client:

```sql
SELECT observed_at, fqdn, ip, port, ike_version, source_label,
       status, rtt_ms, notifications, error
FROM ike_phase1_observations
WHERE mcc = 255 AND mnc = 3
ORDER BY observed_at DESC;
```

---

## CI Pipeline (`.gitlab-ci.yml`)

| Stage | Jobs |
|---|---|
| `build` | Go: linux-amd64, linux-arm64, linux-arm, macos-amd64, macos-arm64, windows-amd64, static |
| `lint` | python_syntax, python_lint (ruff), bash_lint (shellcheck), yaml_lint |
| `test` | python_imports, cli_help (--help smoke), db_schema (in-memory SQLite) |

GitHub Actions additionally runs the Python unit tests, Go tests, and a Docker
image build. The Docker build runs the discovery tests inside the image; use
`docker build -t 3gpp-explorer .` or the equivalent Podman command locally.
See [TESTING.md](TESTING.md) for the test matrix and local commands.

---

## References

- 3GPP TS 23.003 — Numbering, addressing and identification
- 3GPP TS 24.302 — ePDG / non-3GPP access
- 3GPP TS 29.510 — NRF APIs (5GC NF discovery)
- 3GPP TS 29.573 — SEPP N32 interface
- GSMA PRD IR.34/67/88 — GRX/IPX and LTE roaming guidelines
- RFC 3263 — Locating SIP Servers (NAPTR/SRV)
- RIPE Atlas — https://atlas.ripe.net
