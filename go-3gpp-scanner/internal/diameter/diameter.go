package diameter

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DiameterServices maps NAPTR AAA application tags to human-readable interface names.
var DiameterServices = map[string]string{
	"aaa+ap1":  "NASREQ",
	"aaa+ap6":  "Accounting",
	"aaa+ap16": "Cx (HSS/I-CSCF)",
	"aaa+ap23": "S6a (HSS/MME)",
	"aaa+ap24": "S6b (PDN-GW)",
	"aaa+ap25": "SWm (ePDG)",
	"aaa+ap26": "SWx (AAA-HSS)",
}

// DiameterConfig holds configuration for the Diameter scanner.
type DiameterConfig struct {
	DNSServer string        `json:"dns_server"`
	Verbose   bool          `json:"verbose"`
	Timeout   time.Duration `json:"timeout"`
	Workers   int           `json:"workers"`
}

// DiameterPeer represents a discovered Diameter peer endpoint.
type DiameterPeer struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Transport   string `json:"transport"`
	ResolvedIPs string `json:"resolved_ips"`
}

// DiameterRealm represents the Diameter realm discovered for an operator.
type DiameterRealm struct {
	MNC           int            `json:"mnc"`
	MCC           int            `json:"mcc"`
	Operator      string         `json:"operator"`
	CountryName   string         `json:"country_name"`
	Realm         string         `json:"realm"`
	NAPTRServices string         `json:"naptr_services"`
	Interface     string         `json:"interface"`
	NAPTRFound    bool           `json:"naptr_found"`
	Peers         []DiameterPeer `json:"peers"`
}

// Scanner performs Diameter realm probing via DNS NAPTR lookups.
type Scanner struct {
	config    *DiameterConfig
	dnsClient *dns.Client
}

// NewScanner creates a new Diameter Scanner with the provided configuration.
func NewScanner(config *DiameterConfig) *Scanner {
	client := &dns.Client{
		Timeout: config.Timeout,
	}
	return &Scanner{
		config:    config,
		dnsClient: client,
	}
}

// DefaultDiameterConfig returns a DiameterConfig with sensible defaults.
func DefaultDiameterConfig() *DiameterConfig {
	return &DiameterConfig{
		DNSServer: "8.8.8.8:53",
		Verbose:   false,
		Timeout:   3 * time.Second,
		Workers:   10,
	}
}

// BuildRealm constructs a 3GPP Diameter realm FQDN from a prefix, MNC, and MCC.
// Valid prefixes are "epc", "ims", or "mnc" (bare mnc+mcc realm).
func BuildRealm(prefix string, mnc, mcc int) string {
	return fmt.Sprintf("%s.mnc%03d.mcc%03d.3gppnetwork.org", prefix, mnc, mcc)
}

// MapInterface maps a slice of NAPTR service strings to a Diameter interface name.
// It returns the first match found in DiameterServices, or "Unknown" if none match.
func MapInterface(services []string) string {
	for _, svc := range services {
		lower := strings.ToLower(strings.TrimSpace(svc))
		if name, ok := DiameterServices[lower]; ok {
			return name
		}
	}
	return "Unknown"
}

// realmPrefixes lists the realm patterns to probe for each operator.
var realmPrefixes = []string{"epc", "ims", "mnc"}

// ProbeOperator queries DNS NAPTR records for all known Diameter realm patterns
// for the given MNC/MCC combination. It returns one DiameterRealm per realm
// that has at least one NAPTR record. DNS errors are handled gracefully.
func (s *Scanner) ProbeOperator(ctx context.Context, mnc, mcc int, operator, country string) []DiameterRealm {
	type probeResult struct {
		realm DiameterRealm
		found bool
	}

	results := make([]DiameterRealm, 0, len(realmPrefixes))
	resultsMu := &sync.Mutex{}

	sem := make(chan struct{}, s.config.Workers)
	var wg sync.WaitGroup

	for _, prefix := range realmPrefixes {
		select {
		case <-ctx.Done():
			break
		default:
		}

		sem <- struct{}{}
		wg.Add(1)

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			realmFQDN := BuildRealm(p, mnc, mcc)
			dr := s.probeRealm(ctx, realmFQDN, mnc, mcc, operator, country)
			if dr != nil {
				resultsMu.Lock()
				results = append(results, *dr)
				resultsMu.Unlock()
			}
		}(prefix)
	}

	wg.Wait()
	return results
}

// probeRealm performs A and NAPTR lookups for a single realm FQDN.
// Returns nil if no records are found or on error.
func (s *Scanner) probeRealm(ctx context.Context, realm string, mnc, mcc int, operator, country string) *DiameterRealm {
	server := s.config.DNSServer
	if server == "" {
		server = "8.8.8.8:53"
	}

	// Query NAPTR records.
	naptrMsg := new(dns.Msg)
	naptrMsg.SetQuestion(dns.Fqdn(realm), dns.TypeNAPTR)
	naptrMsg.RecursionDesired = true

	resp, _, err := s.dnsClient.ExchangeContext(ctx, naptrMsg, server)
	if err != nil {
		return nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil
	}

	var serviceTokens []string
	var peers []DiameterPeer

	for _, ans := range resp.Answer {
		naptr, ok := ans.(*dns.NAPTR)
		if !ok {
			continue
		}

		// Collect service strings for interface mapping.
		for _, token := range strings.Fields(naptr.Services) {
			serviceTokens = append(serviceTokens, strings.ToLower(token))
		}

		// Each NAPTR replacement is a potential Diameter peer host.
		if naptr.Replacement != "" && naptr.Replacement != "." {
			peer := s.resolvePeer(ctx, naptr.Replacement, naptr.Services, server)
			peers = append(peers, peer)
		}
	}

	if len(resp.Answer) == 0 {
		// No NAPTR records — also try A record to confirm realm existence.
		aMsg := new(dns.Msg)
		aMsg.SetQuestion(dns.Fqdn(realm), dns.TypeA)
		aMsg.RecursionDesired = true

		aResp, _, aErr := s.dnsClient.ExchangeContext(ctx, aMsg, server)
		if aErr != nil || aResp.Rcode != dns.RcodeSuccess || len(aResp.Answer) == 0 {
			return nil
		}
		// A record found but no NAPTR — record as a found realm without peer detail.
		return &DiameterRealm{
			MNC:         mnc,
			MCC:         mcc,
			Operator:    operator,
			CountryName: country,
			Realm:       realm,
			NAPTRFound:  false,
			Peers:       []DiameterPeer{},
		}
	}

	iface := MapInterface(serviceTokens)
	servicesJoined := strings.Join(serviceTokens, ",")

	return &DiameterRealm{
		MNC:           mnc,
		MCC:           mcc,
		Operator:      operator,
		CountryName:   country,
		Realm:         realm,
		NAPTRServices: servicesJoined,
		Interface:     iface,
		NAPTRFound:    true,
		Peers:         peers,
	}
}

// resolvePeer resolves A records for a Diameter peer host.
func (s *Scanner) resolvePeer(ctx context.Context, host, services, server string) DiameterPeer {
	peer := DiameterPeer{
		Host:      strings.TrimSuffix(host, "."),
		Port:      3868, // standard Diameter port
		Transport: "TCP",
	}

	// Determine transport hint from NAPTR service string.
	lower := strings.ToLower(services)
	if strings.Contains(lower, "sctp") {
		peer.Transport = "SCTP"
	} else if strings.Contains(lower, "tls") {
		peer.Transport = "TLS"
	}

	aMsg := new(dns.Msg)
	aMsg.SetQuestion(dns.Fqdn(host), dns.TypeA)
	aMsg.RecursionDesired = true

	resp, _, err := s.dnsClient.ExchangeContext(ctx, aMsg, server)
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		return peer
	}

	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	peer.ResolvedIPs = strings.Join(ips, ",")

	return peer
}
