# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a security research toolkit for discovering and analyzing ePDG (evolved Packet Data Gateway) and 3GPP mobile network infrastructure through DNS reconnaissance. The tools enumerate 3GPP network subdomains (ePDG, IMS, BSF, GAN, XCAP) across global MCC-MNC (Mobile Country Code - Mobile Network Code) combinations to identify exposed telecom infrastructure.

## Repository Structure

- `epdg/` - Original Python toolkit for 3GPP network discovery
  - Python scripts for DNS enumeration and database population
  - Shell scripts for network connectivity testing
  - Text files with discovered FQDNs and IP addresses
  - `mcc-mnc-list.json` - Large reference file mapping MCC-MNC codes to operators worldwide

- `go-3gpp-scanner/` - **NEW: High-performance Go implementation**
  - Single unified binary replacing all Python/Bash scripts
  - Enhanced performance through concurrent DNS resolution
  - Same functionality with additional features (dual ping modes, flexible export)
  - Fully compatible with Python version (same database schema)

- `telegram-bot/` - **NEW: Telegram Bot for 3GPP Network Queries**
  - Interactive Telegram bot for querying 3GPP infrastructure
  - Supports country search, MCC/MNC lookup, MSISDN parsing, operator search
  - Real-time IP resolution with concurrent DNS workers
  - Rate limiting and query logging
  - Uses aiosqlite for async database operations

- `mcp-server/` - **MCP Server for Claude Desktop Integration**
  - Model Context Protocol server for 3GPP database queries
  - Provides tools for querying operators by MNC, MCC, or operator name
  - Real-time IP resolution integrated into responses
  - Designed for use with Claude Desktop app

## Key Tools

### DNS Discovery Scripts

1. **3gpppub-dns-checker.py** - Enumerates multiple 3GPP service types
   - Checks: ims, epdg.epc, bsf, gan, xcap.ims subdomains
   - Scans all MCC-MNC combinations from GitHub's mcc-mnc-list
   - Outputs discovered A records to stdout

2. **epdg-dns-checker.py** - Focused ePDG enumeration
   - Specifically targets epdg.epc subdomains only
   - Faster than the comprehensive checker

3. **3gpppub-dns-database-population.py** - Database builder
   - Creates SQLite database (`database.db`) with two tables:
     - `operators` table: mnc, mcc, operator
     - `available_fqdns` table: operator, fqdn
   - Populates database with discovered FQDNs during scan

### Network Testing

- **epdg-pinger.sh** - Connectivity tester
  - Takes a file of FQDNs as argument
  - Pings each FQDN with 1 packet, 0.3s timeout
  - Filters output to show only successful responses

### Data Analysis

- **stream-oplookup.py** - Streamlit web interface
  - Queries the SQLite database created by the database population script
  - Provides dropdowns to select MNC/MCC combinations
  - Displays available subdomains for selected operator

- **epdg-plot.py** - Visualizes MCC distribution
  - Reads from `epdg-fqdn-raw.txt`
  - Generates bar chart of discovered FQDNs by country code

## Common Commands

### Running DNS Discovery

```bash
# Comprehensive 3GPP subdomain scan (slow, queries all service types)
python3 epdg/3gpppub-dns-checker.py

# Fast ePDG-only scan
python3 epdg/epdg-dns-checker.py

# Build SQLite database of discovered FQDNs
python3 epdg/3gpppub-dns-database-population.py
```

### Testing Connectivity

```bash
# Ping discovered ePDG endpoints
./epdg/epdg-pinger.sh epdg/epdg-fqdn-raw.txt
```

### Analysis and Visualization

```bash
# Launch Streamlit operator lookup interface
streamlit run epdg/stream-oplookup.py

# Generate MCC distribution plot
python3 epdg/epdg-plot.py
```

### Linting (CI Pipeline)

The GitLab CI pipeline defined in `.gitlab-ci.yml` runs:
- `shellcheck *.sh` - Bash linting
- `yamllint your_config.yaml` - YAML validation

Note: The CI config references files that may not exist yet (`*.sh`, `your_config.yaml`) and would need updating to match actual files.

## Architecture Notes

### DNS Enumeration Pattern

All DNS checkers follow this pattern:
1. Fetch MCC-MNC list from GitHub (pbakondy/mcc-mnc-list)
2. Construct FQDNs using format: `{subdomain}.mnc{NNN}.mcc{MMM}.pub.3gppnetwork.org`
   - MNC/MCC are zero-padded to 3 digits
3. Resolve A records using dnspython
4. Sleep 0.5s between queries to avoid rate limiting
5. Silently skip NXDOMAIN and exceptions

### 3GPP Subdomains Scanned

- `epdg.epc` - Evolved Packet Data Gateway (VoWiFi, WiFi calling)
- `ims` - IP Multimedia Subsystem
- `bsf` - Bootstrapping Server Function
- `gan` - Generic Access Network
- `xcap.ims` - XML Configuration Access Protocol

### Data Flow

```
MCC-MNC List (GitHub) → DNS Checker Scripts → stdout / SQLite DB
                                                      ↓
                                                Streamlit UI

Text Files (FQDNs/IPs) → Pinger Script → Connectivity Results
                      → Plot Script → Visualization
```

## Dependencies

Python packages required (not formally specified in requirements.txt):
- `dnspython` - DNS resolution
- `requests` - HTTP for fetching MCC-MNC list
- `sqlite3` - Database (standard library)
- `streamlit` - Web UI for stream-oplookup.py
- `matplotlib` - Plotting for epdg-plot.py

## Security Context

This toolkit performs reconnaissance on mobile operator infrastructure. The discovered ePDG endpoints are:
- Publicly resolvable via DNS (no authorization bypass)
- Used by mobile devices for WiFi calling
- May be security-sensitive if misconfigured or exposed

Use responsibly and only for authorized security research, defensive security assessments, or educational purposes.

---

## Go Implementation (Recommended)

### Overview

The `go-3gpp-scanner/` directory contains a complete Go port of the Python toolkit. This unified implementation consolidates **5 Python scripts + 1 Bash script** into a **single binary** with significant performance improvements.

**Key Advantages:**
- ✅ **Single Binary**: No runtime dependencies, easy deployment
- ✅ **High Performance**: Concurrent DNS resolution (10-50x faster)
- ✅ **Enhanced Features**: Dual ping modes (ICMP + TCP), flexible export formats
- ✅ **Backward Compatible**: Same database schema, can read Python-created databases
- ✅ **Cross-Platform**: Builds for Linux, Windows, macOS

### Quick Start

```bash
# Build the binary
cd go-3gpp-scanner
make build-linux-x86

# Run DNS scan
./bin/3gpp-scanner-linux-x86_64 scan --mode=all --db=database.db

# Test connectivity (TCP method, no root required)
./bin/3gpp-scanner-linux-x86_64 ping --file=results.txt --method=tcp

# Query database
./bin/3gpp-scanner-linux-x86_64 query --mnc=001 --mcc=310 --db=database.db

# Generate statistics
./bin/3gpp-scanner-linux-x86_64 stats --db=database.db
```

### Binary Location

Pre-built binary: `go-3gpp-scanner/bin/3gpp-scanner-linux-x86_64`

### Available Commands

The Go binary provides these subcommands:

1. **scan** - DNS enumeration with multiple modes
   - `--mode=all` - All 5 subdomain types (ims, epdg.epc, bsf, gan, xcap.ims)
   - `--mode=epdg` - ePDG only
   - `--concurrency=N` - Parallel DNS workers (default: 10)
   - `--db=FILE` - Save to SQLite database
   - `--output=FILE` - Export to JSON/CSV/TXT

2. **ping** - Connectivity testing
   - `--method=icmp` - ICMP ping (requires root/CAP_NET_RAW)
   - `--method=tcp` - TCP connectivity check (no root required)
   - `--workers=N` - Concurrent ping workers (default: 10)
   - `--output=FILE` - Export results to JSON/CSV

3. **query** - Database queries
   - `--mnc=N --mcc=N` - Query by MNC/MCC
   - `--operator=NAME` - Query by operator name
   - `--export=FORMAT` - Export as JSON/CSV

4. **stats** - Statistics and analysis
   - `--file=FILE` - Analyze FQDN file
   - `--db=FILE` - Analyze database
   - `--format=json` - Export statistics as JSON

5. **fetch-mccmnc** - Download latest MCC-MNC list from GitHub

### Python vs Go Comparison

| Feature | Python Scripts | Go Binary |
|---------|---------------|-----------|
| **Installation** | Requires Python + dependencies | Single binary, no dependencies |
| **Performance** | Sequential (slow) | Concurrent (10-50x faster) |
| **Commands** | 6 separate scripts | 1 unified binary |
| **Ping Method** | ICMP only (bash script) | ICMP + TCP modes |
| **Export Formats** | Limited | JSON, CSV, TXT |
| **Database** | SQLite (compatible) | SQLite (same schema) |
| **Deployment** | Need Python env | Copy single file |

### Performance

The Go implementation offers significant speed improvements:

- **Concurrent DNS**: Configurable worker pools (default: 10 workers)
- **Rate Limiting**: Intelligent delays (default: 500ms between queries)
- **Example**: Scanning 3,000 MCC-MNC combinations × 5 subdomains
  - Python: ~2 hours (sequential)
  - Go (10 workers): ~12-15 minutes (concurrent)

### Full Documentation

See `go-3gpp-scanner/README.md` for complete documentation including:
- Installation and build instructions
- Detailed command usage and examples
- Performance tuning
- Troubleshooting
- Architecture details

### Compatibility Note

Both toolkits can be used interchangeably:
- Go binary can read databases created by Python scripts
- Same FQDN format and output structure
- Use whichever tool fits your needs!

---

## Telegram Bot (NEW)

### Overview

The `telegram-bot/` directory contains a production-ready Telegram bot that provides interactive queries of 3GPP infrastructure. Users can search by country name, MCC/MNC codes, phone numbers (MSISDN), or operator names.

**Key Features:**
- 🌍 **Country Search** - Fuzzy matching on country names
- 📡 **MCC/MNC Queries** - Direct lookup by mobile codes
- 📱 **MSISDN Parsing** - Extract operator info from phone numbers using Google's libphonenumber
- 🔍 **Operator Search** - Find specific operators with suggestions
- ⚡ **Real-time IP Resolution** - Concurrent DNS resolution (10 workers by default)
- ⏱️ **Rate Limiting** - 10 queries/min, 50/hour per user
- 📊 **Query Logging** - Track usage and analytics

### Quick Start

```bash
# 1. Install dependencies
cd telegram-bot
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Run database migration (adds countries and phone_codes tables)
cd migrations
python3 001_add_countries.py
cd ..

# 3. Configure bot
cp .env.example .env
# Edit .env and set TELEGRAM_BOT_TOKEN (get from @BotFather)

# 4. Run the bot
python3 main.py
```

### Bot Commands

| Command | Usage | Example |
|---------|-------|---------|
| `/start` | Welcome message | `/start` |
| `/help` | Command reference | `/help` |
| `/country` | Search by country | `/country Austria` |
| `/mcc` | Query by MCC | `/mcc 232` |
| `/mnc` | Query by MNC+MCC | `/mnc 1 232` |
| `/phone` | Parse phone number | `/phone +43-660-1234567` |
| `/operator` | Search operator | `/operator Vodafone` |

### Architecture

The bot uses:
- **python-telegram-bot** for Telegram API integration
- **aiosqlite** for async database queries
- **phonenumbers** (libphonenumber) for phone parsing
- **Concurrent DNS resolution** (ThreadPoolExecutor) from MCP server

Key components:
- `handlers/` - Command handlers for each bot command
- `services/` - Business logic (database, DNS, parsing, formatting)
- `migrations/` - Database schema upgrades
- `utils/` - Logging and utilities

### Database Schema Changes

The bot adds 3 new tables to the SQLite database:

1. **countries** - Maps country names/codes to MCCs (255 entries)
2. **phone_country_codes** - Maps E.164 phone codes to countries (182 entries)
3. **query_log** - Tracks bot usage for analytics

These tables are created by running the migration script.

### Configuration

All settings in `.env` file:
- `TELEGRAM_BOT_TOKEN` - From @BotFather (required)
- `ADMIN_USER_IDS` - Comma-separated admin IDs (bypass rate limits)
- `DB_PATH` - Path to database.db (default: `../go-3gpp-scanner/bin/database.db`)
- `MAX_QUERIES_PER_MINUTE` / `MAX_QUERIES_PER_HOUR` - Rate limits
- `DNS_RESOLUTION_TIMEOUT` / `DNS_CONCURRENT_WORKERS` - DNS settings

### Deployment

**Systemd service:**
```bash
sudo cp telegram-bot/telegram-bot.service /etc/systemd/system/
sudo systemctl enable telegram-bot
sudo systemctl start telegram-bot
```

**Docker:**
```bash
cd telegram-bot
docker build -t 3gpp-telegram-bot .
docker run -d --env-file .env 3gpp-telegram-bot
```

### Full Documentation

See `telegram-bot/README.md` for:
- Complete installation guide
- Configuration reference
- Troubleshooting
- Security considerations
- Development guide

---

## MCP Server

The `mcp-server/` directory contains a Model Context Protocol server for integrating 3GPP database queries into Claude Desktop.

**Features:**
- Query operators by MNC, MCC, or operator name
- Real-time IP resolution
- Formatted responses optimized for Claude

**Usage:**
```bash
cd mcp-server
python3 main.py
```

See `mcp-server/README.md` for full documentation.
