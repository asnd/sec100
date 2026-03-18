package models

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// MCCMNCEntry represents a single entry from the MCC-MNC list
type MCCMNCEntry struct {
	Type        string `json:"type"`
	CountryName string `json:"countryName"`
	CountryCode string `json:"countryCode"`
	MCC         string `json:"mcc"`
	MNC         string `json:"mnc"`
	Brand       string `json:"brand"`
	Operator    string `json:"operator"`
	Status      string `json:"status"`
	Bands       string `json:"bands"`
	Notes       string `json:"notes"`
}

// Validate checks that the MCCMNCEntry has valid, parseable MCC and MNC values.
// MCC must be a decimal integer in 1–999.
// MNC must be a decimal integer in 0–999.
// Both fields must be non-empty.
func (e MCCMNCEntry) Validate() error {
	mccStr := strings.TrimSpace(e.MCC)
	mncStr := strings.TrimSpace(e.MNC)

	if mccStr == "" {
		return fmt.Errorf("MCC is empty")
	}
	if mncStr == "" {
		return fmt.Errorf("MNC is empty")
	}

	mcc, err := strconv.Atoi(mccStr)
	if err != nil {
		return fmt.Errorf("MCC %q is not a valid integer: %w", mccStr, err)
	}
	if mcc < 1 || mcc > 999 {
		return fmt.Errorf("MCC %d out of range [1, 999]", mcc)
	}

	mnc, err := strconv.Atoi(mncStr)
	if err != nil {
		return fmt.Errorf("MNC %q is not a valid integer: %w", mncStr, err)
	}
	if mnc < 0 || mnc > 999 {
		return fmt.Errorf("MNC %d out of range [0, 999]", mnc)
	}

	return nil
}

// NormalizeOperator returns the operator name with leading/trailing whitespace
// stripped. If the result is empty, "Unknown" is returned.
func NormalizeOperator(name string) string {
	normalized := strings.TrimSpace(name)
	if normalized == "" {
		return "Unknown"
	}
	return normalized
}

// DNSResult represents the result of a DNS query
type DNSResult struct {
	FQDN      string    `json:"fqdn"`
	IPs       []string  `json:"ips"`
	Subdomain string    `json:"subdomain"`
	MNC       int       `json:"mnc"`
	MCC       int       `json:"mcc"`
	Operator  string    `json:"operator"`
	Timestamp time.Time `json:"timestamp"`
}

// ScanConfig holds configuration for DNS scanning
type ScanConfig struct {
	ParentDomain string
	Subdomains   []string
	QueryDelay   time.Duration
	Concurrency  int
	DatabasePath string
	MCCMNCSource string
	Verbose      bool
}

// PingConfig holds configuration for ping operations
type PingConfig struct {
	Method   string // "icmp" or "tcp"
	Timeout  time.Duration
	Workers  int
	TCPPorts []int // Ports to check for TCP mode (default: 443, 4500)
	Verbose  bool
}

// PingResult represents the result of a ping operation
type PingResult struct {
	FQDN      string        `json:"fqdn"`
	Success   bool          `json:"success"`
	Latency   time.Duration `json:"latency,omitempty"`
	IP        string        `json:"ip,omitempty"`
	Method    string        `json:"method"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// Stats represents statistics about discovered FQDNs
type Stats struct {
	TotalFQDNs      int            `json:"total_fqdns"`
	MCCDistribution map[string]int `json:"mcc_distribution"`
	SubdomainCounts map[string]int `json:"subdomain_counts"`
	CountryCounts   map[string]int `json:"country_counts"`
	UniqueOperators int            `json:"unique_operators"`
	TotalIPs        int            `json:"total_ips"`
}
