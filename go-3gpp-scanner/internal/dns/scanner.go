package dns

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"3gpp-scanner/internal/models"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// Scanner handles DNS resolution for 3GPP FQDNs
type Scanner struct {
	config       *models.ScanConfig
	rateLimiter  *rate.Limiter
	dnsClient    *dns.Client
	progressFunc func(current, total int, found int)
}

// job represents a DNS resolution task
type job struct {
	entry     models.MCCMNCEntry
	subdomain string
}

// NewScanner creates a new DNS scanner
func NewScanner(config *models.ScanConfig) *Scanner {
	// Calculate rate limit: delay between queries
	qps := 1.0 / config.QueryDelay.Seconds()
	limiter := rate.NewLimiter(rate.Limit(qps), 1)

	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	return &Scanner{
		config:      config,
		rateLimiter: limiter,
		dnsClient:   client,
	}
}

// SetProgressCallback sets a callback function for progress updates
func (s *Scanner) SetProgressCallback(callback func(current, total int, found int)) {
	s.progressFunc = callback
}

// Scan performs DNS scanning for all MCC-MNC combinations
func (s *Scanner) Scan(ctx context.Context, entries []models.MCCMNCEntry) ([]models.DNSResult, error) {
	results := make([]models.DNSResult, 0)
	resultsMux := &sync.Mutex{}

	// Create work queue
	totalJobs := len(entries) * len(s.config.Subdomains)
	jobs := make(chan job, totalJobs)

	// Fill job queue
	for _, entry := range entries {
		for _, subdomain := range s.config.Subdomains {
			jobs <- job{entry: entry, subdomain: subdomain}
		}
	}
	close(jobs)

	// Progress tracking
	var processed, found atomic.Int64

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, &results, resultsMux, &processed, &found, totalJobs)
		}()
	}

	wg.Wait()

	return results, nil
}

// worker processes DNS resolution jobs
func (s *Scanner) worker(ctx context.Context, jobs <-chan job, results *[]models.DNSResult, mux *sync.Mutex, processed, found *atomic.Int64, totalJobs int) {
	for j := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			// Rate limiting
			if err := s.rateLimiter.Wait(ctx); err != nil {
				return
			}

			result := s.resolveFQDN(j.entry, j.subdomain)
			if result != nil {
				mux.Lock()
				*results = append(*results, *result)
				mux.Unlock()

				found.Add(1)

				if s.config.Verbose {
					fmt.Printf("Found A record for %s (%s IPs)\n", result.FQDN, formatIPCount(len(result.IPs)))
				}
			}

			// Update progress
			current := int(processed.Add(1))
			if s.progressFunc != nil {
				s.progressFunc(current, totalJobs, int(found.Load()))
			}
		}
	}
}

// resolveFQDN resolves a single FQDN
func (s *Scanner) resolveFQDN(entry models.MCCMNCEntry, subdomain string) *models.DNSResult {
	mcc, _ := strconv.Atoi(entry.MCC)
	mnc, _ := strconv.Atoi(entry.MNC)

	parentDomain := s.parentDomainFor(subdomain)
	fqdn := BuildFQDN(subdomain, mnc, mcc, parentDomain)

	ips, err := s.resolveA(fqdn)
	if err != nil || len(ips) == 0 {
		return nil
	}

	classification := ClassifyService(subdomain, parentDomain)

	return &models.DNSResult{
		FQDN:          fqdn,
		IPs:           ips,
		Subdomain:     subdomain,
		ParentDomain:  parentDomain,
		DomainProfile: classification.DomainProfile,
		ServiceClass:  classification.ServiceClass,
		Standards:     classification.Standards,
		SecurityFocus: classification.SecurityFocus,
		MNC:           mnc,
		MCC:           mcc,
		Operator:      entry.Operator,
		Timestamp:     time.Now(),
	}
}

// resolveA performs an A record DNS query
func (s *Scanner) resolveA(fqdn string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	msg.RecursionDesired = true

	// Try multiple DNS servers
	servers := []string{
		"8.8.8.8:53",        // Google DNS
		"1.1.1.1:53",        // Cloudflare DNS
		"208.67.222.222:53", // OpenDNS
	}

	for _, server := range servers {
		resp, _, err := s.dnsClient.Exchange(msg, server)
		if err != nil {
			continue
		}

		if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		var ips []string
		for _, answer := range resp.Answer {
			if a, ok := answer.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}

		if len(ips) > 0 {
			return ips, nil
		}
	}

	return nil, fmt.Errorf("no A records found")
}

// BuildFQDN constructs a 3GPP FQDN from components
func BuildFQDN(subdomain string, mnc, mcc int, parentDomain string) string {
	return fmt.Sprintf("%s.mnc%03d.mcc%03d.%s", subdomain, mnc, mcc, parentDomain)
}

func (s *Scanner) parentDomainFor(subdomain string) string {
	if s.config.DomainSuffixes != nil {
		if parentDomain, ok := s.config.DomainSuffixes[subdomain]; ok && parentDomain != "" {
			return parentDomain
		}
	}
	return s.config.ParentDomain
}

// ServiceClassification captures security context for a 3GPP service FQDN.
type ServiceClassification struct {
	DomainProfile string
	ServiceClass  string
	Standards     string
	SecurityFocus string
}

// ClassifyService maps known 3GPP/GSMA service names to defensive security context.
func ClassifyService(subdomain, parentDomain string) ServiceClassification {
	classification := ServiceClassification{
		DomainProfile: "3gpp-public",
		ServiceClass:  "Telecom DNS service",
		Standards:     "3GPP TS 23.003",
		SecurityFocus: "Public DNS exposure inventory",
	}
	if parentDomain == "3gppnetwork.org" {
		classification = ServiceClassification{
			DomainProfile: "3gpp-5g",
			ServiceClass:  "Telecom DNS service",
			Standards:     "3GPP TS 23.003; 3GPP TS 33.501",
			SecurityFocus: "5G core service exposure inventory",
		}
	}

	switch subdomain {
	case "epdg.epc":
		classification.ServiceClass = "VoWiFi ingress"
		classification.Standards = "3GPP TS 23.003; GSMA IR.51; GSMA IR.61"
		classification.SecurityFocus = "Wi-Fi calling edge and IPsec gateway exposure"
	case "ims":
		classification.ServiceClass = "IMS/VoLTE"
		classification.Standards = "3GPP TS 23.003; GSMA IR.92"
		classification.SecurityFocus = "Voice and messaging control-plane exposure"
	case "bsf":
		classification.ServiceClass = "Bootstrapping/authentication"
		classification.Standards = "3GPP TS 23.003; 3GPP TS 33.220"
		classification.SecurityFocus = "Authentication helper service exposure"
	case "gan":
		classification.ServiceClass = "Generic Access Network"
		classification.Standards = "3GPP TS 23.003; 3GPP TS 43.318"
		classification.SecurityFocus = "Legacy unlicensed mobile access exposure"
	case "xcap.ims":
		classification.ServiceClass = "IMS configuration"
		classification.Standards = "3GPP TS 23.003; 3GPP TS 24.623"
		classification.SecurityFocus = "Subscriber service configuration exposure"
	case "sepp.5gc":
		classification.ServiceClass = "5G roaming security edge"
		classification.Standards = "3GPP TS 23.003; 3GPP TS 33.501; GSMA FS.34; GSMA IR.88"
		classification.SecurityFocus = "N32 interconnect and roaming security boundary exposure"
	case "nrf.5gc":
		classification.ServiceClass = "5G service registry"
		classification.Standards = "3GPP TS 23.003; 3GPP TS 29.510"
		classification.SecurityFocus = "5G service discovery exposure"
	case "nssf.5gc":
		classification.ServiceClass = "5G slice selection"
		classification.Standards = "3GPP TS 23.003; 3GPP TS 29.531"
		classification.SecurityFocus = "Network slice selection exposure"
	case "ausf.5gc", "udm.5gc":
		classification.ServiceClass = "5G subscriber authentication/data"
		classification.Standards = "3GPP TS 23.003; 3GPP TS 33.501"
		classification.SecurityFocus = "Subscriber identity and authentication service exposure"
	case "amf.5gc", "smf.5gc":
		classification.ServiceClass = "5G mobility/session control"
		classification.Standards = "3GPP TS 23.003"
		classification.SecurityFocus = "5G control-plane function exposure"
	}

	return classification
}

// formatIPCount formats IP count for display
func formatIPCount(count int) string {
	if count == 1 {
		return "1 IP"
	}
	return fmt.Sprintf("%d IPs", count)
}
