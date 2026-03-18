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
| `stream-oplookup.py` | 5 | 7-tab Streamlit dashboard: capability scoring + ASN/hosting |
| `3gpppub-grx-access.py` | — | GRX/IPX DNS helper: RIPE Atlas, open-resolver discovery, zone walk |
| `3gpppub-dns-checker.py` | — | Lightweight TSV checker (no DB required) |

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

---

## CI Pipeline (`.gitlab-ci.yml`)

| Stage | Jobs |
|---|---|
| `build` | Go: linux-amd64, linux-arm64, linux-arm, macos-amd64, macos-arm64, windows-amd64, static |
| `lint` | python_syntax, python_lint (ruff), bash_lint (shellcheck), yaml_lint |
| `test` | python_imports, cli_help (--help smoke), db_schema (in-memory SQLite) |

---

## References

- 3GPP TS 23.003 — Numbering, addressing and identification
- 3GPP TS 24.302 — ePDG / non-3GPP access
- 3GPP TS 29.510 — NRF APIs (5GC NF discovery)
- 3GPP TS 29.573 — SEPP N32 interface
- GSMA PRD IR.34/67/88 — GRX/IPX and LTE roaming guidelines
- RFC 3263 — Locating SIP Servers (NAPTR/SRV)
- RIPE Atlas — https://atlas.ripe.net
