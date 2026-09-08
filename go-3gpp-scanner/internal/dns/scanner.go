package dns

import (
	"context"
	"fmt"
	"net/netip"
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

type dnsResolution struct {
	ips       []string
	dnsStatus string
	ipClass   string
}

// NewScanner creates a new DNS scanner
func NewScanner(config *models.ScanConfig) *Scanner {
	// Calculate rate limit: delay between queries
	qps := rate.Inf
	if config.QueryDelay > 0 {
		qps = rate.Limit(1.0 / config.QueryDelay.Seconds())
	}
	limiter := rate.NewLimiter(qps, 1)

	client := &dns.Client{
		Timeout: 5 * time.Second,
	}

	// Set default DNS servers if none provided
	if len(config.DNSServers) == 0 {
		config.DNSServers = []string{
			"8.8.8.8:53",        // Google DNS
			"1.1.1.1:53",        // Cloudflare DNS
			"208.67.222.222:53", // OpenDNS
		}
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

				if result.IPClass == "PUBLIC_IP" {
					found.Add(1)
				}

				if s.config.Verbose {
					fmt.Printf("Resolved %s status=%s ip_class=%s (%s)\n", result.FQDN, result.DNSStatus, result.IPClass, formatIPCount(len(result.IPs)))
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
	mcc, err := strconv.Atoi(entry.MCC)
	if err != nil {
		return nil
	}
	mnc, err := strconv.Atoi(entry.MNC)
	if err != nil {
		return nil
	}
	country := entry.CountryName
	if country == "" {
		country = "Unknown"
	}

	var fqdn string
	if subdomain == "" {
		fqdn = fmt.Sprintf("mnc%03d.mcc%03d.%s", mnc, mcc, s.config.ParentDomain)
	} else {
		fqdn = fmt.Sprintf("%s.mnc%03d.mcc%03d.%s", subdomain, mnc, mcc, s.config.ParentDomain)
	}

	resolution := s.resolveA(fqdn)
	if resolution == nil {
		return nil
	}
	if resolution.dnsStatus != "ANSWERED" {
		return nil
	}

	return &models.DNSResult{
		FQDN:      fqdn,
		IPs:       resolution.ips,
		Subdomain: subdomain,
		MNC:       mnc,
		MCC:       mcc,
		Operator:  entry.Operator,
		Country:   country,
		DNSStatus: resolution.dnsStatus,
		IPClass:   resolution.ipClass,
		Timestamp: time.Now(),
	}
}

// resolveA performs an A record DNS query
func (s *Scanner) resolveA(fqdn string) *dnsResolution {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	msg.RecursionDesired = true

	status := "TIMEOUT"

	for _, server := range s.config.DNSServers {
		resp, _, err := s.dnsClient.Exchange(msg, server)
		if err != nil {
			continue
		}

		switch resp.Rcode {
		case dns.RcodeNameError:
			return &dnsResolution{dnsStatus: "NXDOMAIN", ipClass: "NONE"}
		case dns.RcodeServerFailure:
			status = "SERVFAIL"
			continue
		case dns.RcodeRefused:
			status = "REFUSED"
			continue
		case dns.RcodeSuccess:
			// Continue below.
		default:
			status = dns.RcodeToString[resp.Rcode]
			continue
		}

		var ips []string
		for _, answer := range resp.Answer {
			if a, ok := answer.(*dns.A); ok {
				ips = append(ips, a.A.String())
			}
		}

		if len(ips) > 0 {
			return &dnsResolution{ips: ips, dnsStatus: "ANSWERED", ipClass: classifyIPs(ips)}
		}

		return &dnsResolution{dnsStatus: "NODATA", ipClass: "NONE"}
	}

	return &dnsResolution{dnsStatus: status, ipClass: "NONE"}
}

func classifyIPs(ips []string) string {
	hasPublic := false
	hasLoopback := false

	for _, raw := range ips {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if addr.IsLoopback() {
			hasLoopback = true
			continue
		}
		if addr.IsGlobalUnicast() && !addr.IsPrivate() {
			hasPublic = true
		}
	}

	if hasPublic {
		return "PUBLIC_IP"
	}
	if hasLoopback {
		return "LOOPBACK_127"
	}
	return "NON_PUBLIC_IP"
}

// BuildFQDN constructs a 3GPP FQDN from components
func BuildFQDN(subdomain string, mnc, mcc int, parentDomain string) string {
	if subdomain == "" {
		return fmt.Sprintf("mnc%03d.mcc%03d.%s", mnc, mcc, parentDomain)
	}
	return fmt.Sprintf("%s.mnc%03d.mcc%03d.%s", subdomain, mnc, mcc, parentDomain)
}

// formatIPCount formats IP count for display
func formatIPCount(count int) string {
	if count == 1 {
		return "1 IP"
	}
	return fmt.Sprintf("%d IPs", count)
}
