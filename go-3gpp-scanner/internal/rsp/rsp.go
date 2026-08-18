package rsp

import (
	"fmt"
	"strings"
	"time"
)

// RSPConfig holds configuration for RSP scanning operations
type RSPConfig struct {
	Timeout      time.Duration
	Workers      int
	ProbeHTTPS   bool
	Verbose      bool
}

// RSPEndpoint represents a discovered or known RSP (Remote SIM Provisioning) endpoint
type RSPEndpoint struct {
	Operator        string `json:"operator"`
	CountryName     string `json:"country_name"`
	MNC             int    `json:"mnc"`
	MCC             int    `json:"mcc"`
	FQDN            string `json:"fqdn"`
	Role            string `json:"role"`
	ResolvedIPs     string `json:"resolved_ips"`
	HTTPSReachable  bool   `json:"https_reachable"`
	HTTPStatus      int    `json:"http_status"`
	Vendor          string `json:"vendor"`
	TLSSubject      string `json:"tls_subject"`
	TLSIssuer       string `json:"tls_issuer"`
	SGP22Version    string `json:"sgp22_version"`
	DiscoveryMethod string `json:"discovery_method"`
}

// Scanner performs RSP endpoint discovery and probing
type Scanner struct {
	config *RSPConfig
}

// NewScanner creates a new RSP Scanner with the given configuration
func NewScanner(config *RSPConfig) *Scanner {
	return &Scanner{
		config: config,
	}
}

// KnownRSPEndpoints contains well-known public RSP endpoints
var KnownRSPEndpoints = []RSPEndpoint{
	{
		FQDN:            "gsma.smds.com",
		Role:            "SM-DS",
		Vendor:          "GSMA",
		DiscoveryMethod: "known",
	},
	{
		FQDN:            "prod.smds.rsp.goog",
		Role:            "SM-DS",
		Vendor:          "Google",
		DiscoveryMethod: "known",
	},
	{
		FQDN:            "lpa.ds.gsma.com",
		Role:            "SM-DS",
		Vendor:          "GSMA",
		DiscoveryMethod: "known",
	},
}

// BuildCandidates generates RSP endpoint candidates for a given MNC/MCC pair
// using the standard 3GPP pub.3gppnetwork.org domain pattern.
func BuildCandidates(mnc, mcc int) []RSPEndpoint {
	mnc3 := fmt.Sprintf("%03d", mnc)
	mcc3 := fmt.Sprintf("%03d", mcc)
	base := fmt.Sprintf("mnc%s.mcc%s.pub.3gppnetwork.org", mnc3, mcc3)

	return []RSPEndpoint{
		{
			FQDN:            "smdp." + base,
			Role:            "SM-DP+",
			DiscoveryMethod: "dns_pub",
		},
		// '+' is not a valid DNS label character; use a hyphenated form.
		{
			FQDN:            "smdp-plus." + base,
			Role:            "SM-DP+",
			DiscoveryMethod: "dns_pub",
		},
		{
			FQDN:            "smds." + base,
			Role:            "SM-DS",
			DiscoveryMethod: "dns_pub",
		},
		{
			FQDN:            "rsp." + base,
			Role:            "unknown",
			DiscoveryMethod: "dns_pub",
		},
		{
			FQDN:            "lpa." + base,
			Role:            "SM-DP+",
			DiscoveryMethod: "dns_pub",
		},
	}
}

// FingerprintVendor attempts to identify the RSP vendor from TLS certificate
// subject and issuer strings.
func FingerprintVendor(subject, issuer string) string {
	upper := strings.ToUpper(subject + " " + issuer)

	switch {
	case strings.Contains(upper, "THALES") ||
		strings.Contains(upper, "GEMALTO") ||
		strings.Contains(upper, "CINTERION"):
		return "Thales"
	case strings.Contains(upper, "IDEMIA") ||
		strings.Contains(upper, "OBERTHUR"):
		return "IDEMIA"
	case strings.Contains(upper, "VALID"):
		return "Valid"
	case strings.Contains(upper, "G+D") ||
		strings.Contains(upper, "GIESECKE"):
		return "G+D"
	case strings.Contains(upper, "STMICRO"):
		return "STMicro"
	case strings.Contains(upper, "APPLE"):
		return "Apple"
	default:
		return "Unknown"
	}
}

// DefaultRSPConfig returns a RSPConfig with sensible defaults
func DefaultRSPConfig() *RSPConfig {
	return &RSPConfig{
		Timeout: 5 * time.Second,
		Workers: 10,
	}
}
