package rsp

import (
	"fmt"
	"strings"
	"testing"
)

func TestBuildCandidates(t *testing.T) {
	mnc := 1
	mcc := 310

	candidates := BuildCandidates(mnc, mcc)

	if len(candidates) != 5 {
		t.Fatalf("expected 5 candidates, got %d", len(candidates))
	}

	expectedBase := fmt.Sprintf("mnc%03d.mcc%03d.pub.3gppnetwork.org", mnc, mcc)

	expectedFQDNs := []string{
		"smdp." + expectedBase,
		"smdp-plus." + expectedBase,
		"smds." + expectedBase,
		"rsp." + expectedBase,
		"lpa." + expectedBase,
	}

	for i, c := range candidates {
		if strings.Contains(c.FQDN, "smdp+.") || strings.Contains(c.FQDN, "+") {
			t.Errorf("invalid DNS label with '+': %s", c.FQDN)
		}
		if c.FQDN != expectedFQDNs[i] {
			t.Errorf("candidate[%d] FQDN: got %q, want %q", i, c.FQDN, expectedFQDNs[i])
		}
		if c.DiscoveryMethod != "dns_pub" {
			t.Errorf("candidate[%d] DiscoveryMethod: got %q, want %q", i, c.DiscoveryMethod, "dns_pub")
		}
	}
}

func TestFingerprintVendor(t *testing.T) {
	cases := []struct {
		subject string
		issuer  string
		want    string
	}{
		{"CN=Thales Root CA", "O=Thales Group", "Thales"},
		{"CN=IDEMIA CA", "O=IDEMIA", "IDEMIA"},
		{"CN=Valid S.A.", "", "Valid"},
		{"CN=G+D Mobile Security", "", "G+D"},
		{"CN=STMicroelectronics", "", "STMicro"},
		{"CN=Apple Root CA", "O=Apple Inc.", "Apple"},
	}

	for _, tc := range cases {
		got := FingerprintVendor(tc.subject, tc.issuer)
		if got != tc.want {
			t.Errorf("FingerprintVendor(%q, %q) = %q, want %q", tc.subject, tc.issuer, got, tc.want)
		}
	}
}

func TestKnownRSPEndpointsLen(t *testing.T) {
	if len(KnownRSPEndpoints) < 3 {
		t.Errorf("KnownRSPEndpoints has %d entries, expected >= 3", len(KnownRSPEndpoints))
	}
}
