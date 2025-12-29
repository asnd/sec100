# GEMINI Project Profile: sec100 (3GPP Security Scanner)

This file provides a standardized profile of the `sec100` project, capturing its architecture, CI/CD configuration, and key implementation details for reuse in other projects.

## Project Overview

- **Name**: sec100 (3GPP Security Scanner)
- **Primary Language**: Go (Golang) 1.24+
- **Purpose**: A high-performance security research toolkit for scanning 3GPP network infrastructure (ePDG, IMS, BSF, etc.) via DNS enumeration and connectivity testing.
- **Key Features**: Concurrent DNS scanning, SQLite database integration, ICMP/TCP pinging, and multi-platform support.

## Project Structure

```
/
├── .gitlab-ci.yml           # GitLab CI/CD configuration (Optimized for Go 1.24)
├── go-3gpp-scanner/         # Main Go application directory
│   ├── cmd/                 # CLI entry point (Cobra framework)
│   ├── internal/            # Core logic (dns, database, fetcher, models, etc.)
│   ├── Makefile             # Multi-platform build system
│   ├── go.mod               # Go module definition
│   └── go.sum               # Dependency checksums (Tracked)
└── epdg/                    # Original Python research scripts
```

## CI/CD Implementation (GitLab)

The project uses a refined GitLab CI/CD pipeline that has been optimized for Go 1.24 and cross-platform builds.

### Pipeline Configuration (`.gitlab-ci.yml`)
- **Stages**: `build` (Testing phase removed for rapid deployment).
- **Go Version**: 1.24 (Bullseye/Alpine based images).
- **Build Targets**:
  - Linux (amd64, arm64, arm) - CGO enabled where appropriate.
  - Windows (amd64) - Cross-compiled using `mingw-w64`.
  - macOS (amd64, arm64) - Cross-compiled with **CGO disabled** for compatibility.

### Key Fixes & Lessons Learned
1. **Go Version Alignment**: Ensure `.gitlab-ci.yml` matches the Go version in `go.mod` (e.g., upgraded from 1.21 to 1.24).
2. **Module Tracking**: `go.sum` MUST be tracked in Git. Remove it from `.gitignore` if present.
3. **CGO Cross-Compilation**:
   - macOS builds from Linux CI runners should use `CGO_ENABLED=0` to avoid missing SDK/clang errors.
   - Windows builds require `gcc-mingw-w64-x86-64` and `CC=x86_64-w64-mingw32-gcc`.
4. **Binary Stripping**: Use `-ldflags="-s -w"` to reduce binary size for distribution.

## Build System (`Makefile`)

The `Makefile` supports targeted builds for all major platforms:
- `make build-linux-x86`: Linux amd64 with CGO.
- `make build-windows`: Windows amd64 using Mingw.
- `make build-darwin`: macOS amd64 with CGO disabled.
- `make build-all`: Orchestrates builds for all primary platforms.

## Dependency Management

- **CLI**: `github.com/spf13/cobra`
- **DNS**: `github.com/miekg/dns`
- **Database**: `github.com/mattn/go-sqlite3` (Requires CGO for Linux/Windows)
- **Network**: `golang.org/x/net`, `golang.org/x/time/rate`

## Suggested Development Tools
- **VSCode Extensions**:
  - `golang.go`: Go language support.
- **CLI Tools**:
  - `go`: Go toolchain.
  - `golangci-lint`: Linter.
  - `cobra-cli`: For managing CLI commands.
- **MCP Servers**:
  - `filesystem`: For file access.