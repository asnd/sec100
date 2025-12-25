package models

import (
	"testing"
	"time"
)

func TestDNSResult(t *testing.T) {
	result := DNSResult{
		FQDN:      "ims.mnc001.mcc310.pub.3gppnetwork.org",
		IPs:       []string{"192.0.2.1", "192.0.2.2"},
		Subdomain: "ims",
		MNC:       1,
		MCC:       310,
		Operator:  "Verizon",
		Timestamp: time.Now(),
	}

	if result.FQDN != "ims.mnc001.mcc310.pub.3gppnetwork.org" {
		t.Errorf("Expected FQDN to be 'ims.mnc001.mcc310.pub.3gppnetwork.org', got %s", result.FQDN)
	}

	if len(result.IPs) != 2 {
		t.Errorf("Expected 2 IPs, got %d", len(result.IPs))
	}

	if result.MNC != 1 {
		t.Errorf("Expected MNC 1, got %d", result.MNC)
	}

	if result.MCC != 310 {
		t.Errorf("Expected MCC 310, got %d", result.MCC)
	}
}

func TestPingResult(t *testing.T) {
	result := PingResult{
		FQDN:      "ims.mnc001.mcc310.pub.3gppnetwork.org",
		Success:   true,
		Latency:   100 * time.Millisecond,
		IP:        "192.0.2.1",
		Method:    "icmp",
		Timestamp: time.Now(),
	}

	if !result.Success {
		t.Errorf("Expected Success to be true, got false")
	}

	if result.Latency != 100*time.Millisecond {
		t.Errorf("Expected Latency 100ms, got %v", result.Latency)
	}

	if result.Method != "icmp" {
		t.Errorf("Expected Method 'icmp', got %s", result.Method)
	}
}

func TestMCCMNCEntry(t *testing.T) {
	entry := MCCMNCEntry{
		Type:        "mobile",
		CountryName: "United States",
		CountryCode: "US",
		MCC:         "310",
		MNC:         "001",
		Brand:       "Verizon",
		Operator:    "Verizon Wireless",
		Status:      "Active",
		Bands:       "GSM, LTE, 5G",
		Notes:       "Major carrier",
	}

	if entry.MCC != "310" {
		t.Errorf("Expected MCC '310', got %s", entry.MCC)
	}

	if entry.CountryCode != "US" {
		t.Errorf("Expected CountryCode 'US', got %s", entry.CountryCode)
	}
}

func TestScanConfig(t *testing.T) {
	config := &ScanConfig{
		ParentDomain: "pub.3gppnetwork.org",
		Subdomains:   []string{"ims", "epdg.epc"},
		QueryDelay:   500 * time.Millisecond,
		Concurrency:  10,
		Verbose:      false,
	}

	if config.ParentDomain != "pub.3gppnetwork.org" {
		t.Errorf("Expected ParentDomain 'pub.3gppnetwork.org', got %s", config.ParentDomain)
	}

	if len(config.Subdomains) != 2 {
		t.Errorf("Expected 2 subdomains, got %d", len(config.Subdomains))
	}

	if config.Concurrency != 10 {
		t.Errorf("Expected Concurrency 10, got %d", config.Concurrency)
	}
}

func TestPingConfig(t *testing.T) {
	config := &PingConfig{
		Method:   "tcp",
		Timeout:  300 * time.Millisecond,
		Workers:  20,
		TCPPorts: []int{443, 4500},
		Verbose:  true,
	}

	if config.Method != "tcp" {
		t.Errorf("Expected Method 'tcp', got %s", config.Method)
	}

	if config.Timeout != 300*time.Millisecond {
		t.Errorf("Expected Timeout 300ms, got %v", config.Timeout)
	}

	if len(config.TCPPorts) != 2 {
		t.Errorf("Expected 2 TCP ports, got %d", len(config.TCPPorts))
	}
}

func TestStats(t *testing.T) {
	stats := &Stats{
		TotalFQDNs: 100,
		MCCDistribution: map[string]int{
			"310": 45,
			"311": 35,
			"312": 20,
		},
		SubdomainCounts: map[string]int{
			"ims":      30,
			"epdg.epc": 40,
			"bsf":      20,
			"gan":      5,
			"xcap.ims": 5,
		},
		UniqueOperators: 25,
		TotalIPs:        150,
	}

	if stats.TotalFQDNs != 100 {
		t.Errorf("Expected TotalFQDNs 100, got %d", stats.TotalFQDNs)
	}

	if len(stats.MCCDistribution) != 3 {
		t.Errorf("Expected 3 MCCs in distribution, got %d", len(stats.MCCDistribution))
	}

	if stats.MCCDistribution["310"] != 45 {
		t.Errorf("Expected MCC 310 count 45, got %d", stats.MCCDistribution["310"])
	}
}
