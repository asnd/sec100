package dns

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"3gpp-scanner/internal/models"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

// Scanner handles DNS resolution for 3GPP FQDNs
type Scanner struct {
	config      *models.ScanConfig
	rateLimiter *rate.Limiter
	dnsClient   *dns.Client
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

// Scan performs DNS scanning for all MCC-MNC combinations
func (s *Scanner) Scan(ctx context.Context, entries []models.MCCMNCEntry) ([]models.DNSResult, error) {
	results := make([]models.DNSResult, 0)
	resultsMux := &sync.Mutex{}

	// Create work queue
	jobs := make(chan job, len(entries)*len(s.config.Subdomains))

	// Fill job queue
	for _, entry := range entries {
		for _, subdomain := range s.config.Subdomains {
			jobs <- job{entry: entry, subdomain: subdomain}
		}
	}
	close(jobs)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.worker(ctx, jobs, &results, resultsMux)
		}()
	}

	wg.Wait()

	return results, nil
}

// worker processes DNS resolution jobs
func (s *Scanner) worker(ctx context.Context, jobs <-chan job, results *[]models.DNSResult, mux *sync.Mutex) {
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

				if s.config.Verbose {
					fmt.Printf("Found A record for %s (%s IPs)\n", result.FQDN, formatIPCount(len(result.IPs)))
				}
			}
		}
	}
}

// resolveFQDN resolves a single FQDN
func (s *Scanner) resolveFQDN(entry models.MCCMNCEntry, subdomain string) *models.DNSResult {
	mcc, _ := strconv.Atoi(entry.MCC)
	mnc, _ := strconv.Atoi(entry.MNC)

	fqdn := fmt.Sprintf("%s.mnc%03d.mcc%03d.%s", subdomain, mnc, mcc, s.config.ParentDomain)

	ips, err := s.resolveA(fqdn)
	if err != nil || len(ips) == 0 {
		return nil
	}

	return &models.DNSResult{
		FQDN:      fqdn,
		IPs:       ips,
		Subdomain: subdomain,
		MNC:       mnc,
		MCC:       mcc,
		Operator:  entry.Operator,
		Timestamp: time.Now(),
	}
}

// resolveA performs an A record DNS query
func (s *Scanner) resolveA(fqdn string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	msg.RecursionDesired = true

	// Try multiple DNS servers
	servers := []string{
		"8.8.8.8:53",   // Google DNS
		"1.1.1.1:53",   // Cloudflare DNS
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

// formatIPCount formats IP count for display
func formatIPCount(count int) string {
	if count == 1 {
		return "1 IP"
	}
	return fmt.Sprintf("%d IPs", count)
}
