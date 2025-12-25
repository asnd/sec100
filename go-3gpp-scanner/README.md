# 3GPP Scanner (Go Port)

A high-performance Go implementation of the 3GPP security research toolkit for discovering and analyzing ePDG (evolved Packet Data Gateway) and 3GPP mobile network infrastructure through DNS reconnaissance.

This is a complete Go port of the Python-based toolkit, consolidating **5 Python scripts + 1 Bash script** into a **single, unified binary** with enhanced performance through concurrency.

## Features

- **DNS Enumeration**: Scan multiple 3GPP service types (ims, epdg.epc, bsf, gan, xcap.ims) across global MCC-MNC combinations
- **High Performance**: Concurrent DNS resolution with configurable worker pools and rate limiting
- **Connectivity Testing**: Dual-mode pinger supporting ICMP (requires root) and TCP connectivity checks
- **Database Integration**: SQLite database compatible with Python version for storing discovered FQDNs
- **Statistics & Analysis**: Analyze discovered infrastructure with MCC distribution and subdomain counts
- **Flexible Export**: Output to JSON, CSV, or plain text formats
- **Built-in Help System**: Comprehensive help text with usage examples for every command (`--help`)
- **Robust Validation**: Intelligent flag validation that catches common errors and provides helpful feedback
- **Single Binary**: No dependencies required at runtime (all-in-one executable)

## Installation

### Pre-built Binary (Recommended)

Download the pre-built Linux x86_64 binary:
```bash
# The binary is located at:
./bin/3gpp-scanner-linux-x86_64

# Make it executable (if needed)
chmod +x ./bin/3gpp-scanner-linux-x86_64

# Optionally, copy to your PATH
sudo cp ./bin/3gpp-scanner-linux-x86_64 /usr/local/bin/3gpp-scanner
```

### Build from Source

Requirements:
- Go 1.21 or later
- GCC (for SQLite CGO support)

```bash
# Install dependencies
make deps

# Build for Linux x86_64
make build-linux-x86

# Or build for current platform
make build

# Binary will be in bin/ directory
```

## Quick Start

### 1. Fetch MCC-MNC List

Download the latest MCC-MNC operator list from GitHub:
```bash
./bin/3gpp-scanner-linux-x86_64 fetch-mccmnc
```

### 2. Run a DNS Scan

Scan for ePDG endpoints only:
```bash
./bin/3gpp-scanner-linux-x86_64 scan --mode=epdg
```

Scan all 5 subdomain types with database storage:
```bash
./bin/3gpp-scanner-linux-x86_64 scan --mode=all --db=database.db
```

### 3. Test Connectivity

Ping discovered endpoints (requires root for ICMP):
```bash
sudo ./bin/3gpp-scanner-linux-x86_64 ping --file=epdg-fqdn-raw.txt --method=icmp
```

Or use TCP connectivity check (no root required):
```bash
./bin/3gpp-scanner-linux-x86_64 ping --file=epdg-fqdn-raw.txt --method=tcp
```

## Help System

Every command includes comprehensive help text with practical usage examples:

```bash
# Get help for any command
3gpp-scanner --help              # Main help
3gpp-scanner scan --help         # Scan command help with examples
3gpp-scanner ping --help         # Ping command help with examples
3gpp-scanner query --help        # Query command help with examples
3gpp-scanner stats --help        # Stats command help with examples
```

Each help page includes:
- Command description
- Practical usage examples
- Complete flag reference
- Default values

### Flag Validation

The CLI performs intelligent validation and provides helpful error messages:

```bash
# Missing required flags
$ 3gpp-scanner scan --mode=custom
Error: --subdomains required for custom mode

# Invalid flag combinations
$ 3gpp-scanner query --mnc=001
Error: --mnc and --mcc must be used together

# Invalid values
$ 3gpp-scanner scan --concurrency=0
Error: --concurrency must be positive
```

## Usage

### DNS Scanning

**Scan all 3GPP subdomain types:**
```bash
3gpp-scanner scan --mode=all
```

**Scan only ePDG endpoints:**
```bash
3gpp-scanner scan --mode=epdg
```

**Scan with custom subdomains:**
```bash
3gpp-scanner scan --mode=custom --subdomains=ims,bsf
```

**Scan and save to database:**
```bash
3gpp-scanner scan --mode=all --db=database.db
```

**Scan with custom concurrency and rate limiting:**
```bash
3gpp-scanner scan --mode=all \
  --concurrency=20 \
  --delay=250 \
  --output=results.json
```

**Use local MCC-MNC file:**
```bash
3gpp-scanner scan --mode=all --mccmnc-file=../epdg/mcc-mnc-list.json
```

**Scan command flags:**
- `--mode, -m`: Scan mode (all, epdg, ims, bsf, gan, xcap, custom)
- `--subdomains`: Comma-separated subdomain list (for custom mode)
- `--db`: Database file path for storing results
- `--output, -o`: Output file (supports .json, .csv, .txt)
- `--concurrency, -c`: Number of concurrent DNS workers (default: 10)
- `--delay`: Delay between queries in milliseconds (default: 500)
- `--mccmnc-file`: Use local MCC-MNC JSON file

### Connectivity Testing

**ICMP ping (requires root):**
```bash
sudo 3gpp-scanner ping --file=fqdns.txt --method=icmp
```

**TCP connectivity check (no root required):**
```bash
3gpp-scanner ping --file=fqdns.txt --method=tcp
```

**With custom timeout and workers:**
```bash
3gpp-scanner ping \
  --file=fqdns.txt \
  --method=tcp \
  --timeout=1000 \
  --workers=50 \
  --output=ping-results.json
```

**Ping command flags:**
- `--file, -f`: File containing FQDNs (one per line)
- `--method`: Ping method - icmp or tcp (default: icmp)
- `--timeout`: Timeout in milliseconds (default: 300)
- `--workers, -w`: Number of concurrent workers (default: 10)
- `--output, -o`: Output file (supports .json, .csv)

**Note:** ICMP ping requires root privileges or `CAP_NET_RAW` capability:
```bash
# Grant capability (alternative to running as root)
sudo setcap cap_net_raw+ep ./bin/3gpp-scanner-linux-x86_64
```

### Database Queries

**Query by MNC and MCC:**
```bash
3gpp-scanner query --mnc=001 --mcc=310 --db=database.db
```

**Query by operator name:**
```bash
3gpp-scanner query --operator="Verizon" --db=database.db
```

**Export query results:**
```bash
3gpp-scanner query --mnc=001 --mcc=310 --export=csv --db=database.db > results.csv
```

**Query command flags:**
- `--mnc`: Mobile Network Code
- `--mcc`: Mobile Country Code
- `--operator`: Operator name
- `--db`: Database file path (default: database.db)
- `--export`: Export format (json or csv)

### Statistics & Analysis

**Analyze FQDN file:**
```bash
3gpp-scanner stats --file=epdg-fqdn-raw.txt
```

**Analyze database:**
```bash
3gpp-scanner stats --db=database.db
```

**Export statistics as JSON:**
```bash
3gpp-scanner stats --file=epdg-fqdn-raw.txt --format=json > stats.json
```

**Stats command flags:**
- `--file, -f`: FQDN file to analyze
- `--db`: Database to analyze
- `--format`: Output format - text, json (default: text)

### Global Flags

Available for all commands:
- `--verbose, -v`: Enable verbose output
- `--quiet, -q`: Suppress output except errors
- `--version`: Show version information

## Architecture

### 3GPP Subdomain Types

The scanner enumerates these 3GPP service types:

- **epdg.epc**: Evolved Packet Data Gateway (VoWiFi, WiFi calling)
- **ims**: IP Multimedia Subsystem
- **bsf**: Bootstrapping Server Function
- **gan**: Generic Access Network
- **xcap.ims**: XML Configuration Access Protocol

### FQDN Pattern

FQDNs are constructed using the format:
```
{subdomain}.mnc{NNN}.mcc{MMM}.pub.3gppnetwork.org
```

Where:
- `{subdomain}`: Service type (e.g., epdg.epc, ims)
- `{NNN}`: Zero-padded 3-digit MNC (Mobile Network Code)
- `{MMM}`: Zero-padded 3-digit MCC (Mobile Country Code)

Example: `epdg.epc.mnc001.mcc310.pub.3gppnetwork.org`

### Database Schema

The SQLite database uses the same schema as the Python version for compatibility:

```sql
CREATE TABLE operators (
    mnc INTEGER,
    mcc INTEGER,
    operator TEXT
);

CREATE TABLE available_fqdns (
    operator TEXT,
    fqdn TEXT
);
```

## Performance

The Go implementation offers significant performance improvements:

- **Concurrent DNS Resolution**: Configurable worker pools (default: 10 workers)
- **Rate Limiting**: Intelligent rate limiting (default: 500ms between queries)
- **Efficient Memory Usage**: Streaming results instead of loading everything into memory
- **Fast Startup**: Single binary with no runtime dependencies

### Performance Tuning

Increase concurrency for faster scanning:
```bash
3gpp-scanner scan --mode=all --concurrency=50 --delay=100
```

**Warning**: High concurrency may trigger rate limiting by DNS servers. Adjust `--delay` accordingly.

## Examples

### Complete Workflow

```bash
# 1. Fetch MCC-MNC list
3gpp-scanner fetch-mccmnc

# 2. Scan all subdomains and save to database
3gpp-scanner scan --mode=all --db=database.db --output=results.txt

# 3. Test connectivity (TCP method, no root required)
3gpp-scanner ping --file=results.txt --method=tcp --output=ping-results.csv

# 4. Query specific operator
3gpp-scanner query --mnc=001 --mcc=310 --db=database.db

# 5. Generate statistics
3gpp-scanner stats --db=database.db --format=json > stats.json
```

### Comparison with Python Version

**Python (multiple commands):**
```bash
python3 epdg/3gpppub-dns-checker.py > output.txt
python3 epdg/3gpppub-dns-database-population.py
./epdg/epdg-pinger.sh epdg-fqdn-raw.txt
streamlit run epdg/stream-oplookup.py
python3 epdg/epdg-plot.py
```

**Go (single binary):**
```bash
3gpp-scanner scan --mode=all --db=database.db --output=output.txt
3gpp-scanner ping --file=output.txt --method=tcp
3gpp-scanner query --mnc=001 --mcc=310 --db=database.db
3gpp-scanner stats --db=database.db
```

## Building

### Build for Linux x86_64 (Primary Target)

```bash
make build-linux-x86
```

### Build for All Platforms

```bash
make build-all
```

This creates binaries for:
- Linux x86_64
- Windows x86_64
- macOS x86_64

### Build Options

```bash
make build           # Build for current platform
make build-static    # Build static binary
make test            # Run tests
make test-coverage   # Run tests with coverage
make clean           # Clean build artifacts
make deps            # Install dependencies
make help            # Show all targets
```

## Testing

The project includes comprehensive test coverage for CLI flag validation:

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./cmd/3gpp-scanner/... -v

# Run with coverage
make test-coverage
```

Test coverage includes:
- Flag validation for all commands (scan, ping, query, stats)
- Invalid flag combination detection
- Edge case handling (negative values, zero values, etc.)
- Proper error message validation

## Dependencies

Runtime: **None** (static binary)

Build-time:
- Go 1.21+
- GCC (for SQLite CGO support)

Go modules:
- `github.com/spf13/cobra` - CLI framework
- `github.com/miekg/dns` - DNS resolution
- `github.com/mattn/go-sqlite3` - SQLite driver
- `golang.org/x/net` - Network utilities (ICMP, IPv4/IPv6)
- `golang.org/x/time` - Rate limiting

## Security Context

This toolkit performs **authorized reconnaissance** on mobile operator infrastructure:

- ✅ Publicly resolvable DNS queries (no authorization bypass)
- ✅ Used for security research and defensive assessments
- ✅ Educational purposes and infrastructure mapping

**Use responsibly** and only for:
- Authorized security testing
- Defensive security assessments
- CTF challenges
- Educational research

## Troubleshooting

### ICMP Ping Permission Denied

```bash
# Option 1: Run with sudo
sudo 3gpp-scanner ping --file=fqdns.txt --method=icmp

# Option 2: Grant capability (preferred)
sudo setcap cap_net_raw+ep ./bin/3gpp-scanner-linux-x86_64

# Option 3: Use TCP method instead (no root required)
3gpp-scanner ping --file=fqdns.txt --method=tcp
```

### DNS Resolution Errors

If you encounter DNS resolution failures:
```bash
# Increase timeout and reduce concurrency
3gpp-scanner scan --mode=all --concurrency=5 --delay=1000
```

### Database Locked

If database is locked by another process:
```bash
# Check for other processes using the database
lsof database.db

# Kill the process or wait for it to finish
```

## Compatibility

This Go implementation is **fully compatible** with the Python version:

- ✅ Same database schema
- ✅ Same FQDN format
- ✅ Same MCC-MNC list source
- ✅ Can read databases created by Python scripts
- ✅ Can process files created by Python scripts

You can use both toolkits interchangeably!

## Contributing

Improvements welcome! Areas for contribution:

- [ ] IPv6 (AAAA record) support
- [ ] Additional output formats
- [x] Built-in help with usage examples
- [x] Flag validation with helpful error messages
- [x] Comprehensive test coverage
- [ ] Configuration file support
- [ ] Shell completion (bash/zsh)
- [ ] Parallel DNS server queries
- [ ] GeoIP integration for country mapping

## License

This is a security research tool. Use responsibly and only for authorized purposes.

## Version

**Version 1.0.0**

Built with Go 1.21+ for Linux x86_64

---

**Original Python Toolkit**: The Python scripts in `../epdg/` remain available and functional alongside this Go implementation.
