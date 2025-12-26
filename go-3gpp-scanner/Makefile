.PHONY: build build-linux-x86 build-all test clean help

# Binary name
BINARY_NAME=3gpp-scanner

# Build directory
BUILD_DIR=bin

# Go build flags
LDFLAGS=-ldflags="-s -w"

# Default target
all: build

# Build for current platform
build:
	@echo "Building for current platform..."
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/3gpp-scanner

# Build for Linux x86_64 (primary target)
build-linux-x86:
	@echo "Building for Linux x86_64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 \
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-x86_64 ./cmd/3gpp-scanner

# Build optimized static binary (requires gcc)
build-static:
	@echo "Building static binary..."
	CGO_ENABLED=1 \
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-static ./cmd/3gpp-scanner

# Build for all platforms
build-all: build-linux-x86 build-windows build-darwin
	@echo "Built binaries for all platforms"

# Build for Windows
build-windows:
	@echo "Building for Windows x86_64..."
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/3gpp-scanner

# Build for macOS (x86_64)
build-darwin:
	@echo "Building for macOS x86_64..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/3gpp-scanner

# Build for macOS (ARM64)
build-darwin-arm:
	@echo "Building for macOS ARM64..."
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/3gpp-scanner

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "Clean complete"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go get -v ./...
	go mod tidy

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  build              - Build for current platform"
	@echo "  build-linux-x86    - Build for Linux x86_64 (primary target)"
	@echo "  build-static       - Build static binary"
	@echo "  build-all          - Build for all platforms"
	@echo "  build-windows      - Build for Windows x86_64"
	@echo "  build-darwin       - Build for macOS x86_64"
	@echo "  build-darwin-arm   - Build for macOS ARM64"
	@echo "  test               - Run tests"
	@echo "  test-coverage      - Run tests with coverage"
	@echo "  clean              - Clean build artifacts"
	@echo "  deps               - Install dependencies"
	@echo "  fmt                - Format code"
	@echo "  lint               - Run linter"
	@echo "  help               - Show this help message"
