package stats

import (
	"os"
	"testing"
	"time"

	"3gpp-scanner/internal/models"
)

func TestNewAnalyzer(t *testing.T) {
	analyzer := NewAnalyzer()

	if analyzer == nil {
		t.Fatalf("NewAnalyzer returned nil")
	}

	if analyzer.mccPattern == nil {
		t.Errorf("mccPattern is nil")
	}

	if analyzer.mncPattern == nil {
		t.Errorf("mncPattern is nil")
	}

	if analyzer.subdomainPattern == nil {
		t.Errorf("subdomainPattern is nil")
	}
}

func TestAnalyzeFile(t *testing.T) {
	// Create a temporary file with test data
	tmpFile := t.TempDir() + "/test_fqdns.txt"
	testData := `ims.mnc001.mcc310.pub.3gppnetwork.org
epdg.mnc001.mcc310.pub.3gppnetwork.org
ims.mnc005.mcc311.pub.3gppnetwork.org
bsf.mnc005.mcc311.pub.3gppnetwork.org`

	err := os.WriteFile(tmpFile, []byte(testData), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	analyzer := NewAnalyzer()
	stats, err := analyzer.AnalyzeFile(tmpFile)

	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if stats.TotalFQDNs != 4 {
		t.Errorf("Expected TotalFQDNs 4, got %d", stats.TotalFQDNs)
	}

	if stats.MCCDistribution["310"] != 2 {
		t.Errorf("Expected MCC 310 count 2, got %d", stats.MCCDistribution["310"])
	}

	if stats.MCCDistribution["311"] != 2 {
		t.Errorf("Expected MCC 311 count 2, got %d", stats.MCCDistribution["311"])
	}

	if stats.SubdomainCounts["ims"] != 2 {
		t.Errorf("Expected 'ims' subdomain count 2, got %d", stats.SubdomainCounts["ims"])
	}

	if stats.SubdomainCounts["epdg"] != 1 {
		t.Errorf("Expected 'epdg' subdomain count 1, got %d", stats.SubdomainCounts["epdg"])
	}

	if stats.SubdomainCounts["bsf"] != 1 {
		t.Errorf("Expected 'bsf' subdomain count 1, got %d", stats.SubdomainCounts["bsf"])
	}
}

func TestAnalyzeResults(t *testing.T) {
	results := []models.DNSResult{
		{
			FQDN:      "ims.mnc001.mcc310.pub.3gppnetwork.org",
			IPs:       []string{"192.0.2.1"},
			Subdomain: "ims",
			MNC:       1,
			MCC:       310,
			Operator:  "Verizon",
			Timestamp: time.Now(),
		},
		{
			FQDN:      "epdg.epc.mnc001.mcc310.pub.3gppnetwork.org",
			IPs:       []string{"192.0.2.2"},
			Subdomain: "epdg.epc",
			MNC:       1,
			MCC:       310,
			Operator:  "Verizon",
			Timestamp: time.Now(),
		},
		{
			FQDN:      "ims.mnc005.mcc311.pub.3gppnetwork.org",
			IPs:       []string{"192.0.2.3", "192.0.2.4"},
			Subdomain: "ims",
			MNC:       5,
			MCC:       311,
			Operator:  "AT&T",
			Timestamp: time.Now(),
		},
	}

	analyzer := NewAnalyzer()
	stats := analyzer.AnalyzeResults(results)

	if stats.TotalFQDNs != 3 {
		t.Errorf("Expected TotalFQDNs 3, got %d", stats.TotalFQDNs)
	}

	if stats.UniqueOperators != 2 {
		t.Errorf("Expected 2 unique operators, got %d", stats.UniqueOperators)
	}

	if stats.TotalIPs != 4 {
		t.Errorf("Expected 4 total IPs, got %d", stats.TotalIPs)
	}

	if stats.MCCDistribution["310"] != 2 {
		t.Errorf("Expected MCC 310 count 2, got %d", stats.MCCDistribution["310"])
	}

	if stats.MCCDistribution["311"] != 1 {
		t.Errorf("Expected MCC 311 count 1, got %d", stats.MCCDistribution["311"])
	}

	if stats.SubdomainCounts["ims"] != 2 {
		t.Errorf("Expected 'ims' subdomain count 2, got %d", stats.SubdomainCounts["ims"])
	}
}

func TestFormatStats(t *testing.T) {
	stats := &models.Stats{
		TotalFQDNs: 100,
		MCCDistribution: map[string]int{
			"310": 45,
			"311": 35,
			"312": 20,
		},
		SubdomainCounts: map[string]int{
			"ims":       30,
			"epdg.epc":  40,
			"bsf":       20,
			"gan":       5,
			"xcap.ims":  5,
		},
		UniqueOperators: 25,
		TotalIPs:        150,
	}

	formatted := FormatStats(stats)

	if !contains(formatted, "Total FQDNs: 100") {
		t.Errorf("Formatted stats does not contain 'Total FQDNs: 100'")
	}

	if !contains(formatted, "Total IPs: 150") {
		t.Errorf("Formatted stats does not contain 'Total IPs: 150'")
	}

	if !contains(formatted, "Unique Operators: 25") {
		t.Errorf("Formatted stats does not contain 'Unique Operators: 25'")
	}

	if !contains(formatted, "MCC Distribution") {
		t.Errorf("Formatted stats does not contain 'MCC Distribution'")
	}

	if !contains(formatted, "Subdomain Distribution") {
		t.Errorf("Formatted stats does not contain 'Subdomain Distribution'")
	}
}

func TestSortMapByValue(t *testing.T) {
	m := map[string]int{
		"c": 10,
		"a": 30,
		"b": 20,
	}

	sorted := sortMapByValue(m)

	if len(sorted) != 3 {
		t.Errorf("Expected 3 sorted items, got %d", len(sorted))
	}

	// Should be sorted by value in descending order
	if sorted[0].Value != 30 {
		t.Errorf("Expected first value 30, got %d", sorted[0].Value)
	}

	if sorted[1].Value != 20 {
		t.Errorf("Expected second value 20, got %d", sorted[1].Value)
	}

	if sorted[2].Value != 10 {
		t.Errorf("Expected third value 10, got %d", sorted[2].Value)
	}
}

// Helper function
func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
