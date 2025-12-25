package models

import "time"

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
	Method      string // "icmp" or "tcp"
	Timeout     time.Duration
	Workers     int
	TCPPorts    []int // Ports to check for TCP mode (default: 443, 4500)
	Verbose     bool
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
	TotalFQDNs         int                 `json:"total_fqdns"`
	MCCDistribution    map[string]int      `json:"mcc_distribution"`
	SubdomainCounts    map[string]int      `json:"subdomain_counts"`
	CountryCounts      map[string]int      `json:"country_counts"`
	UniqueOperators    int                 `json:"unique_operators"`
	TotalIPs           int                 `json:"total_ips"`
}
