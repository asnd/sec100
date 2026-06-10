package diameter

import (
	"context"
	"testing"
)

// TestBuildRealm verifies realm construction for known MNC/MCC values.
func TestBuildRealm(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		mnc      int
		mcc      int
		expected string
	}{
		{
			name:     "epc realm for T-Mobile US MNC=1 MCC=310",
			prefix:   "epc",
			mnc:      1,
			mcc:      310,
			expected: "epc.mnc001.mcc310.3gppnetwork.org",
		},
		{
			name:     "ims realm with zero-padding",
			prefix:   "ims",
			mnc:      1,
			mcc:      310,
			expected: "ims.mnc001.mcc310.3gppnetwork.org",
		},
		{
			name:     "mnc realm bare",
			prefix:   "mnc",
			mnc:      1,
			mcc:      310,
			expected: "mnc.mnc001.mcc310.3gppnetwork.org",
		},
		{
			name:     "three-digit mnc and mcc",
			prefix:   "epc",
			mnc:      260,
			mcc:      234,
			expected: "epc.mnc260.mcc234.3gppnetwork.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildRealm(tt.prefix, tt.mnc, tt.mcc)
			if got != tt.expected {
				t.Errorf("BuildRealm(%q, %d, %d) = %q; want %q",
					tt.prefix, tt.mnc, tt.mcc, got, tt.expected)
			}
		})
	}
}

// TestMapInterface verifies service-to-interface name mapping.
func TestMapInterface(t *testing.T) {
	tests := []struct {
		name     string
		services []string
		expected string
	}{
		{
			name:     "single known service aaa+ap23",
			services: []string{"aaa+ap23"},
			expected: "S6a (HSS/MME)",
		},
		{
			name:     "SWm interface via aaa+ap25",
			services: []string{"aaa+ap25"},
			expected: "SWm (ePDG)",
		},
		{
			name:     "first match wins when multiple services provided",
			services: []string{"aaa+ap16", "aaa+ap23"},
			expected: "Cx (HSS/I-CSCF)",
		},
		{
			name:     "empty slice returns Unknown",
			services: []string{},
			expected: "Unknown",
		},
		{
			name:     "unrecognised service returns Unknown",
			services: []string{"aaa+ap99"},
			expected: "Unknown",
		},
		{
			name:     "accounting interface",
			services: []string{"aaa+ap6"},
			expected: "Accounting",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapInterface(tt.services)
			if got != tt.expected {
				t.Errorf("MapInterface(%v) = %q; want %q", tt.services, got, tt.expected)
			}
		})
	}
}

// TestDiameterServicesCount verifies the DiameterServices map is fully populated.
func TestDiameterServicesCount(t *testing.T) {
	const minExpected = 7
	got := len(DiameterServices)
	if got < minExpected {
		t.Errorf("DiameterServices has %d entries; want >= %d", got, minExpected)
	}
}

// TestProbeOperatorZeroValues verifies that ProbeOperator does not panic when
// called with zero MNC/MCC values and a cancelled context (no real DNS needed).
func TestProbeOperatorZeroValues(t *testing.T) {
	cfg := DefaultDiameterConfig()
	// Point at localhost to ensure no real network calls succeed.
	cfg.DNSServer = "127.0.0.1:53"
	cfg.Workers = 1

	scanner := NewScanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled — all DNS exchanges should fail gracefully

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("ProbeOperator panicked with zero values: %v", r)
		}
	}()

	results := scanner.ProbeOperator(ctx, 0, 0, "", "")
	// With a cancelled context and unreachable DNS server we expect no results,
	// but crucially the function must not panic.
	_ = results
}

// TestDefaultDiameterConfig verifies that DefaultDiameterConfig returns
// expected defaults.
func TestDefaultDiameterConfig(t *testing.T) {
	cfg := DefaultDiameterConfig()
	if cfg == nil {
		t.Fatal("DefaultDiameterConfig returned nil")
	}
	if cfg.Timeout != 3*1e9 { // 3 seconds in nanoseconds
		t.Errorf("Timeout = %v; want 3s", cfg.Timeout)
	}
	if cfg.Workers != 10 {
		t.Errorf("Workers = %d; want 10", cfg.Workers)
	}
}
