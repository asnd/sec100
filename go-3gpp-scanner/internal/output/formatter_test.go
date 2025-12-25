package output

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"3gpp-scanner/internal/models"
)

func TestExportJSON(t *testing.T) {
	tmpFile := t.TempDir() + "/test.json"

	data := []models.DNSResult{
		{
			FQDN:      "ims.mnc001.mcc310.pub.3gppnetwork.org",
			IPs:       []string{"192.0.2.1"},
			Subdomain: "ims",
			MNC:       1,
			MCC:       310,
			Operator:  "Verizon",
			Timestamp: time.Now(),
		},
	}

	err := ExportJSON(data, tmpFile)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	// Verify file was created and contains valid JSON
	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read exported file: %v", err)
	}

	var result []models.DNSResult
	err = json.Unmarshal(content, &result)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 result, got %d", len(result))
	}

	if result[0].FQDN != "ims.mnc001.mcc310.pub.3gppnetwork.org" {
		t.Errorf("Expected FQDN 'ims.mnc001.mcc310.pub.3gppnetwork.org', got %s", result[0].FQDN)
	}
}

func TestExportResultsCSV(t *testing.T) {
	tmpFile := t.TempDir() + "/test.csv"

	results := []models.DNSResult{
		{
			FQDN:      "ims.mnc001.mcc310.pub.3gppnetwork.org",
			IPs:       []string{"192.0.2.1", "192.0.2.2"},
			Subdomain: "ims",
			MNC:       1,
			MCC:       310,
			Operator:  "Verizon",
			Timestamp: time.Now(),
		},
	}

	err := ExportResultsCSV(results, tmpFile)
	if err != nil {
		t.Fatalf("ExportResultsCSV failed: %v", err)
	}

	// Verify file was created
	_, err = os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("CSV file was not created: %v", err)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	if len(content) == 0 {
		t.Fatalf("CSV file is empty")
	}

	// Check for header
	if !contains(string(content), "FQDN") {
		t.Errorf("CSV header does not contain 'FQDN'")
	}
}

func TestExportPingResultsCSV(t *testing.T) {
	tmpFile := t.TempDir() + "/ping.csv"

	results := []models.PingResult{
		{
			FQDN:      "ims.mnc001.mcc310.pub.3gppnetwork.org",
			Success:   true,
			Latency:   100 * time.Millisecond,
			IP:        "192.0.2.1",
			Method:    "icmp",
			Timestamp: time.Now(),
		},
	}

	err := ExportPingResultsCSV(results, tmpFile)
	if err != nil {
		t.Fatalf("ExportPingResultsCSV failed: %v", err)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read CSV file: %v", err)
	}

	if len(content) == 0 {
		t.Fatalf("CSV file is empty")
	}

	// Check for expected columns
	contentStr := string(content)
	if !contains(contentStr, "Success") {
		t.Errorf("CSV header does not contain 'Success'")
	}
	if !contains(contentStr, "Latency_ms") {
		t.Errorf("CSV header does not contain 'Latency_ms'")
	}
}

func TestExportFQDNList(t *testing.T) {
	tmpFile := t.TempDir() + "/fqdns.txt"

	results := []models.DNSResult{
		{FQDN: "ims.mnc001.mcc310.pub.3gppnetwork.org"},
		{FQDN: "epdg.epc.mnc001.mcc310.pub.3gppnetwork.org"},
	}

	err := ExportFQDNList(results, tmpFile)
	if err != nil {
		t.Fatalf("ExportFQDNList failed: %v", err)
	}

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	contentStr := string(content)
	if !contains(contentStr, "ims.mnc001.mcc310.pub.3gppnetwork.org") {
		t.Errorf("Expected FQDN not found in file")
	}
	if !contains(contentStr, "epdg.epc.mnc001.mcc310.pub.3gppnetwork.org") {
		t.Errorf("Second FQDN not found in file")
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
