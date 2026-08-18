package probe

import (
	"encoding/binary"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestFingerprintVendor
// ---------------------------------------------------------------------------

func TestFingerprintVendor(t *testing.T) {
	tests := []struct {
		name     string
		org      string
		cn       string
		sans     []string
		expected string
	}{
		{
			name:     "Ericsson matched via org",
			org:      "Telefonaktiebolaget LM Ericsson",
			cn:       "epdg.epc.mnc001.mcc262.pub.3gppnetwork.org",
			sans:     nil,
			expected: "Ericsson",
		},
		{
			name:     "Nokia matched via CN",
			org:      "",
			cn:       "Nokia Networks GmbH ePDG",
			sans:     nil,
			expected: "Nokia",
		},
		{
			name:     "Huawei matched via SAN",
			org:      "Carrier Tech",
			cn:       "epdg.carrier.net",
			sans:     []string{"epdg.huawei.example.com"},
			expected: "Huawei",
		},
		{
			name:     "Oracle matched via org, mixed case",
			org:      "Oracle Communications",
			cn:       "seagull.example.net",
			sans:     nil,
			expected: "Oracle",
		},
		{
			name:     "Mavenir matched via CN",
			org:      "",
			cn:       "mavenir-epdg.operator.net",
			sans:     nil,
			expected: "Mavenir",
		},
		{
			name:     "Thales matched via org",
			org:      "Thales Group",
			cn:       "bsf.mnc005.mcc234.pub.3gppnetwork.org",
			sans:     nil,
			expected: "Thales",
		},
		{
			name:     "Unknown when no keyword matches",
			org:      "Generic Telecom Ltd",
			cn:       "ims.mnc020.mcc310.pub.3gppnetwork.org",
			sans:     []string{"ims.mnc020.mcc310.pub.3gppnetwork.org"},
			expected: "Unknown",
		},
		{
			name:     "Cisco matched via SAN",
			org:      "",
			cn:       "gateway.example.com",
			sans:     []string{"cisco-epdg.example.com"},
			expected: "Cisco",
		},
		{
			name:     "IDEMIA matched via CN",
			org:      "",
			cn:       "idemia-auth.operator.net",
			sans:     nil,
			expected: "IDEMIA",
		},
		{
			name:     "Valid matched via org",
			org:      "Valid Systems",
			cn:       "xcap.ims.mnc003.mcc208.pub.3gppnetwork.org",
			sans:     nil,
			expected: "Valid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FingerprintVendor(tc.org, tc.cn, tc.sans)
			if got != tc.expected {
				t.Errorf("FingerprintVendor(%q, %q, %v) = %q, want %q",
					tc.org, tc.cn, tc.sans, got, tc.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestDefaultProbeConfig
// ---------------------------------------------------------------------------

func TestDefaultProbeConfig(t *testing.T) {
	cfg := DefaultProbeConfig()

	if cfg == nil {
		t.Fatal("DefaultProbeConfig() returned nil")
	}

	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want %v", cfg.Timeout, 5*time.Second)
	}

	if cfg.Workers != 10 {
		t.Errorf("Workers = %d, want 10", cfg.Workers)
	}

	// Verbose should default to false.
	if cfg.Verbose {
		t.Errorf("Verbose = true, want false")
	}
}

// ---------------------------------------------------------------------------
// TestNewProber
// ---------------------------------------------------------------------------

func TestNewProber(t *testing.T) {
	cfg := DefaultProbeConfig()
	p := NewProber(cfg)
	if p == nil {
		t.Fatal("NewProber returned nil")
	}
	if p.config != cfg {
		t.Error("NewProber did not store the config pointer")
	}
}

// ---------------------------------------------------------------------------
// TestIKEPacketBuild
// ---------------------------------------------------------------------------

func TestIKEPacketBuild(t *testing.T) {
	const expectedLen = 52 // 28-byte IKE header + 4-byte nonce hdr + 20-byte nonce

	pkt := buildIKESAInit()

	// Length check.
	if len(pkt) != expectedLen {
		t.Fatalf("packet length = %d, want %d", len(pkt), expectedLen)
	}

	// Version byte (index 17) must be 0x20.
	if pkt[17] != 0x20 {
		t.Errorf("version byte = 0x%02x, want 0x20", pkt[17])
	}

	// Exchange type (index 18) must be 34 (IKE_SA_INIT).
	if pkt[18] != 34 {
		t.Errorf("exchange type = %d, want 34", pkt[18])
	}

	// Flags byte (index 19) must be 0x08 (Initiator bit).
	if pkt[19] != 0x08 {
		t.Errorf("flags byte = 0x%02x, want 0x08", pkt[19])
	}

	// Next payload (index 16) must be 40 (Nonce).
	if pkt[16] != 40 {
		t.Errorf("next payload = %d, want 40", pkt[16])
	}

	// Total length field (bytes 24-27) must equal expectedLen.
	totalLen := binary.BigEndian.Uint32(pkt[24:28])
	if totalLen != uint32(expectedLen) {
		t.Errorf("total length field = %d, want %d", totalLen, expectedLen)
	}

	// Responder SPI (bytes 8-15) must be all zeros.
	for i := 8; i < 16; i++ {
		if pkt[i] != 0 {
			t.Errorf("responder SPI byte[%d] = 0x%02x, want 0x00", i, pkt[i])
		}
	}

	// Nonce payload: next-payload byte (index 28) must be 0 (no chained payload).
	if pkt[28] != 0 {
		t.Errorf("nonce payload next = %d, want 0", pkt[28])
	}

	// Nonce payload length field (bytes 30-31) must be 24 (4 hdr + 20 data).
	noncePayloadLen := binary.BigEndian.Uint16(pkt[30:32])
	if noncePayloadLen != 24 {
		t.Errorf("nonce payload length = %d, want 24", noncePayloadLen)
	}

	// Two successive calls must produce different initiator SPIs (random).
	pkt2 := buildIKESAInit()
	allSame := true
	for i := 0; i < 8; i++ {
		if pkt[i] != pkt2[i] {
			allSame = false
			break
		}
	}
	if allSame {
		// This could theoretically fail with probability 1/2^64; acceptable.
		t.Error("two successive IKE packets have identical initiator SPI (expected random)")
	}
}

// ---------------------------------------------------------------------------
// TestExtractVendorIDs
// ---------------------------------------------------------------------------

func TestExtractVendorIDs(t *testing.T) {
	t.Run("too short returns nil", func(t *testing.T) {
		got := extractVendorIDs([]byte{0x00, 0x01})
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("no vendor-id payloads returns nil", func(t *testing.T) {
		// Build a minimal 28-byte response with next payload = 0 (no payloads).
		resp := make([]byte, 28)
		resp[17] = 0x20
		resp[16] = 0 // next payload = none
		got := extractVendorIDs(resp)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("single vendor-id payload extracted", func(t *testing.T) {
		// IKE header (28 bytes) + one Vendor-ID payload.
		//   Payload type 43, next=0, length=8 (4 hdr + 4 data), data=0xdeadbeef
		vendorData := []byte{0xde, 0xad, 0xbe, 0xef}
		resp := make([]byte, 28+4+len(vendorData))
		resp[17] = 0x20
		resp[16] = 43 // next payload = Vendor-ID
		// Payload header at offset 28:
		resp[28] = 0 // next payload after this = none
		resp[29] = 0 // critical
		binary.BigEndian.PutUint16(resp[30:32], uint16(4+len(vendorData)))
		copy(resp[32:], vendorData)

		got := extractVendorIDs(resp)
		if len(got) != 1 {
			t.Fatalf("expected 1 vendor ID, got %d: %v", len(got), got)
		}
		if got[0] != "deadbeef" {
			t.Errorf("vendor ID = %q, want %q", got[0], "deadbeef")
		}
	})
}

func TestMatchIKEVendorID(t *testing.T) {
	if got := MatchIKEVendorID("4048b7d56ebce88525e7de7f00d6c2d3"); got != "OpenIKEv2" {
		t.Errorf("OpenIKEv2 match = %q", got)
	}
	if got := MatchIKEVendorID("deadbeef"); got != "" {
		t.Errorf("unknown vendor should be empty, got %q", got)
	}
}

func TestAssessIKEWeakCrypto(t *testing.T) {
	// Minimal IKEv2 header + SA payload with DES transform marker.
	resp := make([]byte, 40)
	resp[16] = 33 // next = SA
	resp[17] = 0x20
	resp[28] = 0 // next after SA
	resp[29] = 0
	binary.BigEndian.PutUint16(resp[30:32], 12) // payload len
	// body starts at 32: plant ENCR type + DES id
	resp[32] = 0x01
	resp[33] = 0x02 // DES

	weak, reasons := assessIKEWeakCrypto(resp, nil)
	if !weak {
		t.Fatalf("expected weak crypto, reasons=%v", reasons)
	}
	if len(reasons) == 0 || reasons[0] != "weak-encr-transform" {
		t.Errorf("reasons = %v", reasons)
	}

	// No SA payload → not weak solely due to unknown vendor
	clean := make([]byte, 28)
	clean[16] = 0
	clean[17] = 0x20
	weak, reasons = assessIKEWeakCrypto(clean, []string{"unknown-box"})
	if weak {
		t.Errorf("unknown vendor alone must not be weak crypto, reasons=%v", reasons)
	}
}

func TestLabelVendorIDs(t *testing.T) {
	got := labelVendorIDs([]string{"4048b7d56ebce885aabb", "abcdef"})
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
	if got[0] != "OpenIKEv2" {
		t.Errorf("first label = %q", got[0])
	}
}
