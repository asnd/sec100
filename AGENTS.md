# AGENTS.md — AI Agent Context

This file provides context for AI coding assistants (Claude Code, Copilot, etc.)
working in this repository.

---

## Project Purpose

Research toolkit for discovering and analysing DNS records in the
`pub.3gppnetwork.org` zone — the public-internet-accessible portion of 3GPP's
global mobile operator DNS namespace. Used for telecom security research,
operator infrastructure analysis, and VoWiFi/VoLTE deployment tracking.

---

## Repository Layout

```
epdg/
├── 3gpppub-dns-database-population.py  # Main scanner — populates database.db
├── 3gpppub-dns-checker.py              # Lightweight scanner, no DB
├── 3gpppub-asn-enricher.py             # Feature 1: BGP/ASN enrichment
├── 3gpppub-5g-discovery.py             # Feature 2: 5G SA NF discovery
├── 3gpppub-diff.py                     # Feature 3: snapshot + change detection
├── 3gpppub-naptr-discovery.py          # Feature 4: NAPTR/SRV probing
├── 3gpppub-grx-access.py               # GRX/IPX DNS access helper
├── stream-oplookup.py                  # Feature 5: Streamlit dashboard (7 tabs)
├── epdg-dns-checker.py                 # Legacy ePDG-only checker
├── epdg-plot.py                        # Legacy MCC distribution plotter
├── mcc-mnc-list.json                   # Local copy of MCC/MNC dataset
├── requirements.txt                    # Python dependencies
└── database.db                         # SQLite DB (gitignored, created at runtime)
```

---

## Key Conventions

### Python style
- Python 3.11+ syntax used throughout (including `list[str]`, `dict[str, int]`, `str | None`)
- Linting: `ruff check --select E,W,F --ignore E501,E402,F401,F811`
- No external test framework; CI runs syntax checks + `--help` smoke tests + DB schema tests
- All CLI scripts use `argparse` and support `--help`
- Logging via `logging` module, not bare `print` (except summary output)
- `sqlite3` only — no ORM, no migrations, schemas applied via `executescript()`

### Database
- Single file `database.db` in the `epdg/` directory
- All tables use `ON CONFLICT ... DO UPDATE` (upsert) — never plain `INSERT`
- Schema is defined as a module-level `SCHEMA` string constant and applied in `init_db()`
- `fqdn + record_type` is the natural unique key for DNS records
- Timestamps stored as ISO-8601 UTC strings

### DNS resolution
- `dnspython` (`dns.resolver`) used everywhere — never `subprocess`/`nslookup`
- Bare `except Exception: pass` is **not used** — always catch specific exceptions
  (`NXDOMAIN`, `NoAnswer`, `Timeout`) and let others propagate or log at DEBUG
- All scanning scripts support `--workers N` for `ThreadPoolExecutor` concurrency
- Rate-limiting is intentionally minimal (DNS is stateless); `--delay` flag for explicit throttling

### Streamlit dashboard (`stream-oplookup.py`)
- DB connection via `@st.cache_resource` — one connection for the app lifetime
- Data loading via `@st.cache_data(ttl=300)` — refreshed every 5 minutes
- All tabs access the same filtered `df` DataFrame (from sidebar filters) except
  tabs that need unfiltered data for scoring/ASN (they use `df_all` or a direct SQL query)
- Plotly Express used for all charts — no matplotlib in the dashboard

---

## 3GPP DNS Zones

| Zone | Resolvable from | Purpose |
|---|---|---|
| `pub.3gppnetwork.org` | Public internet ✅ | UE-accessible service endpoints |
| `5gc.mnc*.mcc*.3gppnetwork.org` | GRX/IPX DNS only ⚠️ | 5GC NF discovery |
| DANE TLSA records | Public internet ✅ | SEPP TLS cert pinning |

The `pub.` zone is the primary target. The `5gc.` zone requires GRX/IPX
connectivity; use `--dns-server <GRX_IP>` to target a GRX resolver.

### Known `pub.3gppnetwork.org` subdomains (18 total)

| Subdomain | Category | Notes |
|---|---|---|
| `epdg.epc` | VoWiFi | ePDG — IKEv2/IPsec Wi-Fi Calling gateway |
| `ss.epdg.epc` | VoWiFi | ePDG steering/load-balancing (T-Mobile US) |
| `sos.epdg.epc` | VoWiFi / Emergency | Emergency ePDG (SOS over Wi-Fi) |
| `vowifi` | VoWiFi | Non-standard alias (AT&T, some US operators) |
| `n3iwf.5gc` | 5G non-3GPP | N3IWF — replaces ePDG in 5GS (TS 23.502) |
| `ims` | IMS | IMS core — VoLTE registration |
| `pcscf.ims` | IMS | P-CSCF discovery — SIP entry point (TS 24.229) |
| `mmtel.ims` | IMS | MMTel supplementary services (TS 24.173) |
| `xcap.ims` | IMS | XCAP device/service config (TS 24.623) |
| `ut.ims` | IMS | Ut interface — supplementary service config (TS 24.623) |
| `sos` | Emergency | SOS/Emergency services |
| `sos.ims` | Emergency | Emergency IMS |
| `aes` | Emergency | Auth/Emergency services (T-Mobile MX, MCC 334) |
| `bsf` | Auth | Bootstrapping Server Function (TS 33.220) |
| `gan` | Access | GAN/UMA — unlicensed access network (TS 44.318) |
| `rcs` | Messaging | Rich Communication Services (GSMA IR.94) |
| `subs` | Provisioning | Subscription/provisioning (Canadian MNOs, MCC 302) |
| `cota-sdk` | Provisioning | COTA Over-The-Air config (T-Mobile MX) |

**FQDN pattern:** `<subdomain>.mnc<MNC:03d>.mcc<MCC:03d>.pub.3gppnetwork.org`

---

## CI Pipeline (`.gitlab-ci.yml`)

| Job | Stage | What it checks |
|---|---|---|
| `python_syntax` | lint | `python3 -m py_compile` on all `.py` files |
| `python_lint` | lint | `ruff` E/W/F rules |
| `bash_lint` | lint | `shellcheck` on `.sh` files |
| `yaml_lint` | lint | `yamllint` on `.yml` files |
| `python_imports` | test | Install deps + AST parse all `3gpppub-*.py` |
| `cli_help` | test | `--help` smoke test on every CLI script |
| `db_schema` | test | Each module's `SCHEMA` constant applies cleanly to `:memory:` SQLite |

CI jobs are triggered only when relevant files change (via `rules: changes:`).

---

## What NOT to do

- Do not add ORM dependencies (SQLAlchemy etc.) — keep it stdlib sqlite3
- Do not use `subprocess` for DNS lookups — use `dnspython`
- Do not add `time.sleep()` inside DNS resolution loops — use `--delay` flag instead
- Do not commit `database.db` — it is runtime-generated
- Do not use bare `except: pass` — catch specific DNS exceptions
- Do not add new Streamlit tabs without updating the tab tuple at line ~130

---

## Running locally

```bash
cd epdg

# Scan
python3 3gpppub-dns-database-population.py --workers 20

# Enrich
python3 3gpppub-asn-enricher.py
python3 3gpppub-naptr-discovery.py

# Dashboard
streamlit run stream-oplookup.py
```
