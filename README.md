# 3GPP Security Scanner (sec100)

A high-performance Go-based toolkit for scanning 3GPP network infrastructure.

## Project Status
- **CI/CD**: ✅ GitLab Pipeline Passing
- **Builds**: Linux (x86, ARM), Windows, macOS
- **Go Version**: 1.24+

## Features
- **Concurrent DNS Scanner**: Fast enumeration of 3GPP FQDNs.
- **Connectivity Testing**: Dual ICMP and TCP pinging.
- **Database Integration**: SQLite support compatible with legacy Python tools.
- **Multi-Platform**: Native binaries for Linux, Windows, and macOS.

## Quick Start

### Build from Source
```bash
cd go-3gpp-scanner
make build-linux-x86
./bin/3gpp-scanner-linux-x86_64 --help
```

### Build All Platforms
```bash
cd go-3gpp-scanner
make build-all
```

## Repository Structure
- `go-3gpp-scanner/`: Main Go implementation.
- `epdg/`: Original Python research scripts and reference data.
- `.gitlab-ci.yml`: Automated build pipeline for all platforms.

## CI/CD Pipeline
The project uses GitLab CI/CD to automatically build binaries for:
- **Linux**: amd64, arm64, arm
- **Windows**: x64 (using Mingw)
- **macOS**: amd64, arm64 (CGO disabled)

For reuse patterns and CI implementation details, see [GEMINI.md](./GEMINI.md).