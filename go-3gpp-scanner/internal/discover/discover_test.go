package discover

import (
	"testing"
)

// TestParseFQDN verifies that ParseFQDN correctly extracts components from
// well-formed 3GPP FQDNs and rejects non-matching strings.
func TestParseFQDN(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantPrefix string
		wantZone   string
		wantMNC    int
		wantMCC    int
		wantOK     bool
	}{
		{
			name:       "standard epdg.epc",
			input:      "epdg.epc.mnc001.mcc310.pub.3gppnetwork.org",
			wantPrefix: "epdg.epc",
			wantZone:   "pub",
			wantMNC:    1,
			wantMCC:    310,
			wantOK:     true,
		},
		{
			name:       "wildcard prefix stripped",
			input:      "*.ims.mnc010.mcc234.pub.3gppnetwork.org",
			wantPrefix: "ims",
			wantZone:   "pub",
			wantMNC:    10,
			wantMCC:    234,
			wantOK:     true,
		},
		{
			name:       "multi-level prefix xcap.ims",
			input:      "xcap.ims.mnc099.mcc505.pub.3gppnetwork.org",
			wantPrefix: "xcap.ims",
			wantZone:   "pub",
			wantMNC:    99,
			wantMCC:    505,
			wantOK:     true,
		},
		{
			name:       "non-pub zone",
			input:      "bsf.mnc001.mcc262.ims.3gppnetwork.org",
			wantPrefix: "bsf",
			wantZone:   "ims",
			wantMNC:    1,
			wantMCC:    262,
			wantOK:     true,
		},
		{
			name:       "deep prefix ss.epdg.epc",
			input:      "ss.epdg.epc.mnc007.mcc250.pub.3gppnetwork.org",
			wantPrefix: "ss.epdg.epc",
			wantZone:   "pub",
			wantMNC:    7,
			wantMCC:    250,
			wantOK:     true,
		},
		{
			name:   "unrelated domain does not match",
			input:  "example.com",
			wantOK: false,
		},
		{
			name:   "missing mnc segment",
			input:  "epdg.epc.mcc310.pub.3gppnetwork.org",
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefix, zone, mnc, mcc, ok := ParseFQDN(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("ParseFQDN(%q) ok=%v, want %v", tc.input, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if prefix != tc.wantPrefix {
				t.Errorf("prefix=%q, want %q", prefix, tc.wantPrefix)
			}
			if zone != tc.wantZone {
				t.Errorf("zone=%q, want %q", zone, tc.wantZone)
			}
			if mnc != tc.wantMNC {
				t.Errorf("mnc=%d, want %d", mnc, tc.wantMNC)
			}
			if mcc != tc.wantMCC {
				t.Errorf("mcc=%d, want %d", mcc, tc.wantMCC)
			}
		})
	}
}

// TestClassifyHost verifies inPredefined and isNewCandidate logic.
func TestClassifyHost(t *testing.T) {
	known := DefaultSubdomains

	tests := []struct {
		name           string
		prefix         string
		zone           string
		wantInPred     bool
		wantNewCand    bool
	}{
		{
			name:        "known subdomain in pub zone",
			prefix:      "epdg.epc",
			zone:        "pub",
			wantInPred:  true,
			wantNewCand: false,
		},
		{
			name:        "unknown subdomain in pub zone is new candidate",
			prefix:      "unknown-service",
			zone:        "pub",
			wantInPred:  false,
			wantNewCand: true,
		},
		{
			name:        "unknown subdomain in non-pub zone is not a new candidate",
			prefix:      "mystery",
			zone:        "ims",
			wantInPred:  false,
			wantNewCand: false,
		},
		{
			name:        "known subdomain in non-pub zone",
			prefix:      "bsf",
			zone:        "ims",
			wantInPred:  true,
			wantNewCand: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inPred, isNew := ClassifyHost(tc.prefix, tc.zone, known)
			if inPred != tc.wantInPred {
				t.Errorf("inPredefined=%v, want %v", inPred, tc.wantInPred)
			}
			if isNew != tc.wantNewCand {
				t.Errorf("isNewCandidate=%v, want %v", isNew, tc.wantNewCand)
			}
		})
	}
}

// TestDefaultSubdomains verifies that DefaultSubdomains contains at least 18 entries.
func TestDefaultSubdomains(t *testing.T) {
	const minExpected = 18
	if got := len(DefaultSubdomains); got < minExpected {
		t.Errorf("DefaultSubdomains has %d entries, want at least %d", got, minExpected)
	}
}
