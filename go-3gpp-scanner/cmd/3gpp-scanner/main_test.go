package main

import (
	"testing"
)

// Test Scan Flag Validations
func TestValidateScanFlags(t *testing.T) {
	tests := []struct {
		name        string
		setupFlags  func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "custom mode without subdomains",
			setupFlags: func() {
				scanMode = "custom"
				scanSubdomains = ""
				scanProfile = "public"
				scanConcurrency = 10
				scanDelay = 500
			},
			expectError: true,
			errorMsg:    "--subdomains required for custom mode",
		},
		{
			name: "invalid mode",
			setupFlags: func() {
				scanMode = "invalid"
				scanSubdomains = ""
				scanProfile = "public"
				scanConcurrency = 10
				scanDelay = 500
			},
			expectError: true,
			errorMsg:    "invalid mode",
		},
		{
			name: "zero concurrency",
			setupFlags: func() {
				scanMode = "all"
				scanSubdomains = ""
				scanProfile = "public"
				scanConcurrency = 0
				scanDelay = 500
			},
			expectError: true,
			errorMsg:    "--concurrency must be positive",
		},
		{
			name: "negative delay",
			setupFlags: func() {
				scanMode = "all"
				scanSubdomains = ""
				scanProfile = "public"
				scanConcurrency = 10
				scanDelay = -100
			},
			expectError: true,
			errorMsg:    "--delay cannot be negative",
		},
		{
			name: "invalid profile",
			setupFlags: func() {
				scanMode = "all"
				scanSubdomains = ""
				scanProfile = "invalid"
				scanConcurrency = 10
				scanDelay = 500
			},
			expectError: true,
			errorMsg:    "invalid profile",
		},
		{
			name: "valid 5g sepp mode",
			setupFlags: func() {
				scanMode = "sepp"
				scanSubdomains = ""
				scanProfile = "5g"
				scanConcurrency = 10
				scanDelay = 500
			},
			expectError: false,
		},
		{
			name: "valid epdg mode",
			setupFlags: func() {
				scanMode = "epdg"
				scanSubdomains = ""
				scanProfile = "public"
				scanConcurrency = 10
				scanDelay = 500
			},
			expectError: false,
		},
		{
			name: "valid custom mode with subdomains",
			setupFlags: func() {
				scanMode = "custom"
				scanSubdomains = "ims,bsf"
				scanProfile = "public"
				scanConcurrency = 10
				scanDelay = 500
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupFlags()
			err := validateScanFlags()

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

func TestScanTargets(t *testing.T) {
	tests := []struct {
		name             string
		profile          string
		mode             string
		customSubdomains string
		expected         []string
		expectedSuffix   map[string]string
		expectError      bool
	}{
		{
			name:    "public all profile",
			profile: "public",
			mode:    "all",
			expected: []string{
				"ims",
				"epdg.epc",
				"bsf",
				"gan",
				"xcap.ims",
			},
			expectedSuffix: map[string]string{"epdg.epc": "pub.3gppnetwork.org"},
		},
		{
			name:           "5g sepp target",
			profile:        "5g",
			mode:           "sepp",
			expected:       []string{"sepp.5gc"},
			expectedSuffix: map[string]string{"sepp.5gc": "3gppnetwork.org"},
		},
		{
			name:             "custom 5g suffix inference",
			profile:          "public",
			mode:             "custom",
			customSubdomains: "custom.5gc",
			expected:         []string{"custom.5gc"},
			expectedSuffix:   map[string]string{"custom.5gc": "3gppnetwork.org"},
		},
		{
			name:        "unsupported mode for profile",
			profile:     "public",
			mode:        "sepp",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subdomains, suffixes, err := scanTargets(tt.profile, tt.mode, tt.customSubdomains)
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(subdomains) != len(tt.expected) {
				t.Fatalf("expected %d subdomains, got %d", len(tt.expected), len(subdomains))
			}
			for i, expected := range tt.expected {
				if subdomains[i] != expected {
					t.Errorf("subdomain[%d] = %s, expected %s", i, subdomains[i], expected)
				}
			}
			for subdomain, expectedSuffix := range tt.expectedSuffix {
				if suffixes[subdomain] != expectedSuffix {
					t.Errorf("suffix for %s = %s, expected %s", subdomain, suffixes[subdomain], expectedSuffix)
				}
			}
		})
	}
}

// Test Ping Flag Validations
func TestValidatePingFlags(t *testing.T) {
	tests := []struct {
		name        string
		setupFlags  func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing file",
			setupFlags: func() {
				pingFile = ""
				pingMethod = "icmp"
				pingTimeout = 300
				pingWorkers = 10
			},
			expectError: true,
			errorMsg:    "--file required",
		},
		{
			name: "invalid method",
			setupFlags: func() {
				pingFile = "test.txt"
				pingMethod = "invalid"
				pingTimeout = 300
				pingWorkers = 10
			},
			expectError: true,
			errorMsg:    "invalid method",
		},
		{
			name: "zero timeout",
			setupFlags: func() {
				pingFile = "test.txt"
				pingMethod = "tcp"
				pingTimeout = 0
				pingWorkers = 10
			},
			expectError: true,
			errorMsg:    "--timeout must be positive",
		},
		{
			name: "negative workers",
			setupFlags: func() {
				pingFile = "test.txt"
				pingMethod = "icmp"
				pingTimeout = 300
				pingWorkers = -5
			},
			expectError: true,
			errorMsg:    "--workers must be positive",
		},
		{
			name: "valid tcp ping",
			setupFlags: func() {
				pingFile = "test.txt"
				pingMethod = "tcp"
				pingTimeout = 300
				pingWorkers = 10
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupFlags()
			err := validatePingFlags()

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// Test Query Flag Validations
func TestValidateQueryFlags(t *testing.T) {
	tests := []struct {
		name        string
		setupFlags  func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "no search criteria",
			setupFlags: func() {
				queryMNC = 0
				queryMCC = 0
				queryOperator = ""
			},
			expectError: true,
			errorMsg:    "either --mnc/--mcc or --operator required",
		},
		{
			name: "mnc without mcc",
			setupFlags: func() {
				queryMNC = 1
				queryMCC = 0
				queryOperator = ""
			},
			expectError: true,
			errorMsg:    "--mnc and --mcc must be used together",
		},
		{
			name: "mcc without mnc",
			setupFlags: func() {
				queryMNC = 0
				queryMCC = 310
				queryOperator = ""
			},
			expectError: true,
			errorMsg:    "--mnc and --mcc must be used together",
		},
		{
			name: "valid mnc and mcc",
			setupFlags: func() {
				queryMNC = 1
				queryMCC = 310
				queryOperator = ""
			},
			expectError: false,
		},
		{
			name: "valid operator",
			setupFlags: func() {
				queryMNC = 0
				queryMCC = 0
				queryOperator = "Verizon"
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupFlags()
			err := validateQueryFlags()

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// Test Stats Flag Validations
func TestValidateStatsFlags(t *testing.T) {
	tests := []struct {
		name        string
		setupFlags  func()
		expectError bool
		errorMsg    string
	}{
		{
			name: "no source specified",
			setupFlags: func() {
				statsFile = ""
				statsDB = ""
				statsFormat = "text"
			},
			expectError: true,
			errorMsg:    "either --file or --db required",
		},
		{
			name: "both file and db",
			setupFlags: func() {
				statsFile = "test.txt"
				statsDB = "database.db"
				statsFormat = "text"
			},
			expectError: true,
			errorMsg:    "cannot specify both --file and --db",
		},
		{
			name: "invalid format",
			setupFlags: func() {
				statsFile = "test.txt"
				statsDB = ""
				statsFormat = "invalid"
			},
			expectError: true,
			errorMsg:    "invalid format",
		},
		{
			name: "valid file with json",
			setupFlags: func() {
				statsFile = "test.txt"
				statsDB = ""
				statsFormat = "json"
			},
			expectError: false,
		},
		{
			name: "valid db with csv",
			setupFlags: func() {
				statsFile = ""
				statsDB = "database.db"
				statsFormat = "csv"
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupFlags()
			err := validateStatsFlags()

			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectError && err != nil && tt.errorMsg != "" {
				if !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && stringContains(s, substr))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
