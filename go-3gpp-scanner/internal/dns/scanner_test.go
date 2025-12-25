package dns

import (
	"context"
	"testing"
	"time"

	"3gpp-scanner/internal/models"
)

func TestNewScanner(t *testing.T) {
	config := &models.ScanConfig{
		ParentDomain: "pub.3gppnetwork.org",
		Subdomains:   []string{"ims", "epdg.epc"},
		QueryDelay:   500 * time.Millisecond,
		Concurrency:  10,
		Verbose:      false,
	}

	scanner := NewScanner(config)

	if scanner == nil {
		t.Fatalf("NewScanner returned nil")
	}

	if scanner.config != config {
		t.Errorf("Scanner config was not set correctly")
	}

	if scanner.rateLimiter == nil {
		t.Errorf("Rate limiter is nil")
	}

	if scanner.dnsClient == nil {
		t.Errorf("DNS client is nil")
	}
}

func TestBuildFQDN(t *testing.T) {
	tests := []struct {
		subdomain string
		mnc       int
		mcc       int
		expected  string
	}{
		{
			subdomain: "ims",
			mnc:       1,
			mcc:       310,
			expected:  "ims.mnc001.mcc310.pub.3gppnetwork.org",
		},
		{
			subdomain: "epdg.epc",
			mnc:       5,
			mcc:       311,
			expected:  "epdg.epc.mnc005.mcc311.pub.3gppnetwork.org",
		},
		{
			subdomain: "xcap.ims",
			mnc:       0,
			mcc:       460,
			expected:  "xcap.ims.mnc000.mcc460.pub.3gppnetwork.org",
		},
	}

	for _, tt := range tests {
		result := BuildFQDN(tt.subdomain, tt.mnc, tt.mcc, "pub.3gppnetwork.org")
		if result != tt.expected {
			t.Errorf("BuildFQDN(%s, %d, %d) = %s, expected %s",
				tt.subdomain, tt.mnc, tt.mcc, result, tt.expected)
		}
	}
}

func TestScanWithEmptyEntries(t *testing.T) {
	config := &models.ScanConfig{
		ParentDomain: "pub.3gppnetwork.org",
		Subdomains:   []string{"ims"},
		QueryDelay:   100 * time.Millisecond,
		Concurrency:  1,
		Verbose:      false,
	}

	scanner := NewScanner(config)
	ctx := context.Background()
	results, err := scanner.Scan(ctx, []models.MCCMNCEntry{})

	if err != nil {
		t.Errorf("Scan with empty entries failed: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty entries, got %d", len(results))
	}
}

func TestScanContextCancellation(t *testing.T) {
	config := &models.ScanConfig{
		ParentDomain: "pub.3gppnetwork.org",
		Subdomains:   []string{"ims", "epdg.epc"},
		QueryDelay:   100 * time.Millisecond,
		Concurrency:  2,
		Verbose:      false,
	}

	entries := []models.MCCMNCEntry{
		{
			MCC:      "310",
			MNC:      "001",
			Operator: "Verizon",
		},
		{
			MCC:      "311",
			MNC:      "005",
			Operator: "AT&T",
		},
	}

	scanner := NewScanner(config)

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results, err := scanner.Scan(ctx, entries)

	if err != nil {
		t.Logf("Scan with cancelled context returned error (expected): %v", err)
	}

	if results == nil {
		results = []models.DNSResult{}
	}

	// Should get no results or error due to context cancellation
	t.Logf("Got %d results with cancelled context", len(results))
}

func TestFormatIPCount(t *testing.T) {
	tests := []struct {
		count    int
		expected string
	}{
		{1, "1 IP"},
		{2, "2 IPs"},
		{10, "10 IPs"},
	}

	for _, tt := range tests {
		result := formatIPCount(tt.count)
		if result != tt.expected {
			t.Errorf("formatIPCount(%d) = %s, expected %s", tt.count, result, tt.expected)
		}
	}
}
