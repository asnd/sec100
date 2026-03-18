package fetcher

import (
	"testing"
	"time"

	"3gpp-scanner/internal/models"
)

// TestFilterValidAllGood verifies that a slice of well-formed entries passes
// through FilterValid without any being dropped.
func TestFilterValidAllGood(t *testing.T) {
	entries := []models.MCCMNCEntry{
		{MCC: "310", MNC: "260", Operator: "T-Mobile US"},
		{MCC: "001", MNC: "001", Operator: "Test Operator"},
		{MCC: "999", MNC: "999", Operator: "Max Codes"},
		{MCC: "232", MNC: "001", Operator: "A1 Austria"},
		{MCC: "460", MNC: "000", Operator: "China Mobile"},
	}

	valid, dropped := FilterValid(entries)

	if dropped != 0 {
		t.Errorf("Expected 0 dropped, got %d", dropped)
	}
	if len(valid) != len(entries) {
		t.Errorf("Expected %d valid entries, got %d", len(entries), len(valid))
	}
}

// TestFilterValidDropsInvalid verifies that entries with missing or malformed
// MCC/MNC values are filtered out.
func TestFilterValidDropsInvalid(t *testing.T) {
	entries := []models.MCCMNCEntry{
		{MCC: "310",  MNC: "260", Operator: "Good entry"},
		{MCC: "",     MNC: "260", Operator: "Empty MCC"},
		{MCC: "310",  MNC: "",    Operator: "Empty MNC"},
		{MCC: "abc",  MNC: "260", Operator: "Non-numeric MCC"},
		{MCC: "310",  MNC: "xyz", Operator: "Non-numeric MNC"},
		{MCC: "1000", MNC: "260", Operator: "MCC too large"},
		{MCC: "0",    MNC: "260", Operator: "MCC zero"},
		{MCC: "-1",   MNC: "260", Operator: "MCC negative"},
		{MCC: "310",  MNC: "1000", Operator: "MNC too large"},
		{MCC: "310",  MNC: "-1",   Operator: "MNC negative"},
	}

	valid, dropped := FilterValid(entries)

	if dropped != 9 {
		t.Errorf("Expected 9 dropped, got %d", dropped)
	}
	if len(valid) != 1 {
		t.Errorf("Expected 1 valid entry, got %d", len(valid))
	}
	if len(valid) > 0 && valid[0].Operator != "Good entry" {
		t.Errorf("Expected surviving entry to be 'Good entry', got %q", valid[0].Operator)
	}
}

// TestFilterValidEmptySlice verifies that an empty input produces empty output.
func TestFilterValidEmptySlice(t *testing.T) {
	valid, dropped := FilterValid([]models.MCCMNCEntry{})
	if dropped != 0 {
		t.Errorf("Expected 0 dropped for empty slice, got %d", dropped)
	}
	if len(valid) != 0 {
		t.Errorf("Expected 0 valid entries for empty slice, got %d", len(valid))
	}
}

// TestFilterValidBoundaryMCC checks the exact boundary values for MCC (1 and 999).
func TestFilterValidBoundaryMCC(t *testing.T) {
	tests := []struct {
		mcc  string
		want bool // true = should be valid
	}{
		{"1", true},
		{"0", false},
		{"999", true},
		{"1000", false},
	}

	for _, tt := range tests {
		entry := models.MCCMNCEntry{MCC: tt.mcc, MNC: "001"}
		_, dropped := FilterValid([]models.MCCMNCEntry{entry})
		isValid := dropped == 0
		if isValid != tt.want {
			t.Errorf("MCC=%q: expected valid=%v, got valid=%v", tt.mcc, tt.want, isValid)
		}
	}
}

// TestFilterValidBoundaryMNC checks the exact boundary values for MNC (0 and 999).
func TestFilterValidBoundaryMNC(t *testing.T) {
	tests := []struct {
		mnc  string
		want bool // true = should be valid
	}{
		{"0", true},
		{"-1", false},
		{"999", true},
		{"1000", false},
	}

	for _, tt := range tests {
		entry := models.MCCMNCEntry{MCC: "310", MNC: tt.mnc}
		_, dropped := FilterValid([]models.MCCMNCEntry{entry})
		isValid := dropped == 0
		if isValid != tt.want {
			t.Errorf("MNC=%q: expected valid=%v, got valid=%v", tt.mnc, tt.want, isValid)
		}
	}
}

// TestNewFetcher validates that NewFetcher applies default values.
func TestNewFetcher(t *testing.T) {
	f := NewFetcher("", "", 24*time.Hour, false)

	if f.URL != DefaultMCCMNCURL {
		t.Errorf("Expected default URL %q, got %q", DefaultMCCMNCURL, f.URL)
	}
	if f.CacheDir != "." {
		t.Errorf("Expected default CacheDir '.', got %q", f.CacheDir)
	}
}

// TestNewFetcherCustomURL validates custom URL is preserved.
func TestNewFetcherCustomURL(t *testing.T) {
	customURL := "https://example.com/mcc.json"
	f := NewFetcher(customURL, "/tmp", time.Hour, true)

	if f.URL != customURL {
		t.Errorf("Expected custom URL %q, got %q", customURL, f.URL)
	}
	if f.CacheDir != "/tmp" {
		t.Errorf("Expected CacheDir '/tmp', got %q", f.CacheDir)
	}
	if !f.Verbose {
		t.Errorf("Expected Verbose=true")
	}
}

// TestIsCacheFreshZeroTTL ensures cache is never considered fresh when TTL is 0.
func TestIsCacheFreshZeroTTL(t *testing.T) {
	f := NewFetcher("", "", 0, false)
	if f.isCacheFresh("/any/path") {
		t.Errorf("Expected cache to not be fresh when TTL is 0")
	}
}
