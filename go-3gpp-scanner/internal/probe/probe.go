package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// ProbeConfig holds configuration for probe operations.
type ProbeConfig struct {
	Timeout time.Duration
	Workers int
	Verbose bool
}

// DefaultProbeConfig returns a ProbeConfig with sensible defaults.
func DefaultProbeConfig() *ProbeConfig {
	return &ProbeConfig{
		Timeout: 5 * time.Second,
		Workers: 10,
	}
}

// TLSResult holds the outcome of a TLS probe against a single endpoint.
type TLSResult struct {
	FQDN         string    `json:"fqdn"`
	IP           string    `json:"ip"`
	Operator     string    `json:"operator"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SAN          []string  `json:"san"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	KeyType      string    `json:"key_type"`
	SigAlgorithm string    `json:"sig_algorithm"`
	Vendor       string    `json:"vendor"`
	IsExpired    bool      `json:"is_expired"`
	IsSelfSigned bool      `json:"is_self_signed"`
	IsWeakSig    bool      `json:"is_weak_sig"`
	Port         int       `json:"port"`
	Error        string    `json:"error,omitempty"`
}

// IKEResult holds the outcome of an IKEv2 SA_INIT probe.
type IKEResult struct {
	FQDN        string   `json:"fqdn"`
	IP          string   `json:"ip"`
	Operator    string   `json:"operator"`
	Port        int      `json:"port"`
	Responded   bool     `json:"responded"`
	VendorIDs   []string `json:"vendor_ids"`
	WeakCrypto  bool     `json:"weak_crypto"`
	WeakReasons []string `json:"weak_reasons"`
	Error       string   `json:"error,omitempty"`
}

// Prober executes TLS and IKEv2 probes against 3GPP endpoints.
type Prober struct {
	config *ProbeConfig
}

// NewProber creates a new Prober with the given configuration.
func NewProber(config *ProbeConfig) *Prober {
	return &Prober{config: config}
}

// ProbeTLS dials the target over TLS, extracts certificate metadata, and
// identifies the vendor using FingerprintVendor.
func (p *Prober) ProbeTLS(ctx context.Context, fqdn, ip string, port int, operator string) TLSResult {
	result := TLSResult{
		FQDN:     fqdn,
		IP:       ip,
		Operator: operator,
		Port:     port,
	}

	addr := fmt.Sprintf("%s:%d", ip, port)

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: p.config.Timeout},
		Config: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional for recon
			ServerName:         fqdn,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		result.Error = "unexpected connection type"
		return result
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Error = "no peer certificates received"
		return result
	}

	cert := state.PeerCertificates[0]

	result.Subject = cert.Subject.CommonName
	result.Issuer = cert.Issuer.CommonName
	result.SAN = cert.DNSNames
	result.NotBefore = cert.NotBefore
	result.NotAfter = cert.NotAfter
	result.KeyType = keyTypeString(cert)
	result.SigAlgorithm = cert.SignatureAlgorithm.String()
	result.IsExpired = time.Now().After(cert.NotAfter)
	result.IsSelfSigned = cert.Issuer.String() == cert.Subject.String()
	result.IsWeakSig = strings.Contains(result.SigAlgorithm, "SHA1") ||
		strings.Contains(result.SigAlgorithm, "MD5")

	result.Vendor = FingerprintVendor(strings.Join(cert.Subject.Organization, " "), cert.Subject.CommonName, cert.DNSNames)

	return result
}

// ProbeIKE sends a minimal IKEv2 IKE_SA_INIT packet and inspects the response
// for vendor-ID payloads and weak crypto indicators.
func (p *Prober) ProbeIKE(ctx context.Context, fqdn, ip string, port int, operator string) IKEResult {
	result := IKEResult{
		FQDN:     fqdn,
		IP:       ip,
		Operator: operator,
		Port:     port,
	}

	addr := fmt.Sprintf("%s:%d", ip, port)

	// Resolve deadline from context + per-probe timeout.
	deadline := time.Now().Add(p.config.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer conn.Close()

	pkt := buildIKESAInit()

	if err := conn.SetDeadline(deadline); err != nil {
		result.Error = err.Error()
		return result
	}

	if _, err := conn.Write(pkt); err != nil {
		result.Error = err.Error()
		return result
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	resp := buf[:n]

	// IKEv2: byte index 17 is the version field; 0x20 == major 2, minor 0.
	if len(resp) < 28 || resp[17] != 0x20 {
		result.Error = "unexpected or malformed IKE response"
		return result
	}

	result.Responded = true
	result.VendorIDs = extractVendorIDs(resp)

	return result
}

// FingerprintVendor attempts to identify the telecom vendor from certificate
// fields. org is typically cert.Subject.Organization joined, cn is the common
// name, and sans are the DNS SANs. Returns "Unknown" when no match is found.
func FingerprintVendor(org, cn string, sans []string) string {
	combined := strings.ToUpper(org + " " + cn + " " + strings.Join(sans, " "))

	vendors := []struct {
		keyword string
		name    string
	}{
		{"ERICSSON", "Ericsson"},
		{"NOKIA", "Nokia"},
		{"HUAWEI", "Huawei"},
		{"CISCO", "Cisco"},
		{"MAVENIR", "Mavenir"},
		{"ORACLE", "Oracle"},
		{"THALES", "Thales"},
		{"IDEMIA", "IDEMIA"},
		{"VALID", "Valid"},
	}

	for _, v := range vendors {
		if strings.Contains(combined, v.keyword) {
			return v.name
		}
	}

	return "Unknown"
}

// --- helpers -----------------------------------------------------------------

// keyTypeString returns a human-readable key algorithm name from a certificate.
func keyTypeString(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "EC"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

// buildIKESAInit constructs a minimal IKEv2 IKE_SA_INIT request packet.
//
// Layout:
//
//	 0-7   Initiator SPI  (8 random bytes)
//	 8-15  Responder SPI  (8 zero bytes)
//	16     Next payload   = 40 (Nonce payload type in IKEv2)
//	17     Version        = 0x20 (major 2)
//	18     Exchange type  = 34  (IKE_SA_INIT)
//	19     Flags          = 0x08 (Initiator)
//	20-23  Message ID     = 0
//	24-27  Total length   (big-endian uint32)
//	28+    Nonce payload
//
// Nonce payload generic header (4 bytes): next=0, critical=0, length=24 (4+20)
// Nonce data: 20 random bytes
func buildIKESAInit() []byte {
	const (
		ikeHeaderLen   = 28
		noncePayloadHdr = 4
		nonceDataLen   = 20
		totalLen       = ikeHeaderLen + noncePayloadHdr + nonceDataLen
	)

	pkt := make([]byte, totalLen)

	// Initiator SPI – 8 random bytes
	//nolint:gosec // weak rand is fine for nonce material in a probe
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 8; i++ {
		pkt[i] = byte(r.Intn(256))
	}

	// Responder SPI – 8 zero bytes (already zero from make)

	// IKE header fields
	pkt[16] = 40   // Next payload = Nonce
	pkt[17] = 0x20 // Version 2.0
	pkt[18] = 34   // Exchange type: IKE_SA_INIT
	pkt[19] = 0x08 // Flags: Initiator bit

	// Message ID (bytes 20-23) = 0 (already zero)

	// Total length (bytes 24-27)
	binary.BigEndian.PutUint32(pkt[24:28], uint32(totalLen))

	// Nonce payload generic header
	pkt[28] = 0 // Next payload after nonce = None
	pkt[29] = 0 // Critical bit = 0
	// Payload length = noncePayloadHdr(4) + nonceDataLen(20) = 24
	binary.BigEndian.PutUint16(pkt[30:32], uint16(noncePayloadHdr+nonceDataLen))

	// Nonce data – 20 random bytes
	for i := 0; i < nonceDataLen; i++ {
		pkt[32+i] = byte(r.Intn(256))
	}

	return pkt
}

// extractVendorIDs walks IKEv2 payloads looking for type 43 (Vendor-ID).
// It returns the hex-encoded payload data for each vendor-ID payload found.
func extractVendorIDs(resp []byte) []string {
	if len(resp) < 28 {
		return nil
	}

	var ids []string

	// Walk the payload chain starting after the fixed 28-byte IKE header.
	nextPayload := resp[16]
	offset := 28

	for offset+4 <= len(resp) && nextPayload != 0 {
		payloadType := nextPayload
		nextPayload = resp[offset]
		// critical := resp[offset+1]
		payloadLen := int(binary.BigEndian.Uint16(resp[offset+2 : offset+4]))

		if payloadLen < 4 || offset+payloadLen > len(resp) {
			break
		}

		// Payload type 43 = Vendor-ID
		if payloadType == 43 {
			data := resp[offset+4 : offset+payloadLen]
			ids = append(ids, fmt.Sprintf("%x", data))
		}

		offset += payloadLen
	}

	return ids
}

