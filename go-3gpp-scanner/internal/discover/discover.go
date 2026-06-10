package discover

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultSubdomains contains all 18 known 3GPP service subdomains.
var DefaultSubdomains = []string{
	"ss.epdg.epc",
	"sos.epdg.epc",
	"epdg.epc",
	"vowifi",
	"n3iwf.5gc",
	"pcscf.ims",
	"mmtel.ims",
	"xcap.ims",
	"ut.ims",
	"sos.ims",
	"ims",
	"sos",
	"aes",
	"bsf",
	"gan",
	"rcs",
	"subs",
	"cota-sdk",
}

// fqdnRe matches FQDNs of the form:
// <prefix>.mnc<NNN>.mcc<MMM>.<zone>.3gppnetwork.org
var fqdnRe = regexp.MustCompile(`(?i)^(.+)\.mnc(\d{1,3})\.mcc(\d{1,3})\.([a-z0-9]+)\.3gppnetwork\.org$`)

// DiscoverConfig holds configuration for passive host discovery.
type DiscoverConfig struct {
	CRTShURL        string
	HackerTargetURL string
	Timeout         time.Duration
	Limit           int
	Verbose         bool
}

// DefaultDiscoverConfig returns a DiscoverConfig with sensible defaults.
func DefaultDiscoverConfig() *DiscoverConfig {
	return &DiscoverConfig{
		CRTShURL:        "https://crt.sh/?q=%.3gppnetwork.org&output=json",
		HackerTargetURL: "https://api.hackertarget.com/hostsearch/?q=3gppnetwork.org",
		Timeout:         30 * time.Second,
		Limit:           0,
		Verbose:         false,
	}
}

// DiscoveredHost represents a single host found through passive discovery.
type DiscoveredHost struct {
	Source        string `json:"source"`
	FQDN          string `json:"fqdn"`
	ServicePrefix string `json:"service_prefix"`
	Zone          string `json:"zone"`
	MNC           int    `json:"mnc"`
	MCC           int    `json:"mcc"`
	InPredefined  bool   `json:"in_predefined"`
	IsNewCandidate bool  `json:"is_new_candidate"`
	CertID        string `json:"cert_id,omitempty"`
}

// Discoverer performs passive DNS discovery via external certificate and DNS APIs.
type Discoverer struct {
	config *DiscoverConfig
	client http.Client
}

// NewDiscoverer constructs a Discoverer using the provided config.
func NewDiscoverer(cfg *DiscoverConfig) *Discoverer {
	if cfg == nil {
		cfg = DefaultDiscoverConfig()
	}
	return &Discoverer{
		config: cfg,
		client: http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// ParseFQDN parses a 3GPP FQDN and returns its component parts.
// It trims any leading "*." wildcard prefix before matching.
// Returns ok=false when the string does not match the expected pattern.
func ParseFQDN(fqdn string) (prefix, zone string, mnc, mcc int, ok bool) {
	fqdn = strings.TrimPrefix(fqdn, "*.")
	m := fqdnRe.FindStringSubmatch(fqdn)
	if m == nil {
		return "", "", 0, 0, false
	}

	mncVal, err := strconv.Atoi(m[2])
	if err != nil {
		return "", "", 0, 0, false
	}
	mccVal, err := strconv.Atoi(m[3])
	if err != nil {
		return "", "", 0, 0, false
	}

	return m[1], m[4], mncVal, mccVal, true
}

// ClassifyHost determines whether a host prefix is among the known subdomains
// and whether it is a new candidate worth investigating.
// A new candidate is any prefix not in knownSubdomains that resides in the
// "pub" zone (public 3GPP namespace).
func ClassifyHost(prefix, zone string, knownSubdomains []string) (inPredefined, isNewCandidate bool) {
	for _, s := range knownSubdomains {
		if strings.EqualFold(s, prefix) {
			return true, false
		}
	}
	return false, strings.EqualFold(zone, "pub")
}

// crtShEntry is the JSON structure returned by crt.sh.
type crtShEntry struct {
	ID        int64  `json:"id"`
	NameValue string `json:"name_value"`
}

// QueryCRTSh queries crt.sh for certificate transparency log entries that
// contain 3gppnetwork.org hostnames and returns the parsed host list.
func (d *Discoverer) QueryCRTSh(ctx context.Context) ([]DiscoveredHost, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.config.CRTShURL, nil)
	if err != nil {
		return nil, fmt.Errorf("discover: build crt.sh request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discover: crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover: crt.sh returned status %d", resp.StatusCode)
	}

	var entries []crtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("discover: decode crt.sh response: %w", err)
	}

	seen := make(map[string]struct{})
	var hosts []DiscoveredHost

	for _, entry := range entries {
		lines := strings.Split(entry.NameValue, "\n")
		for _, line := range lines {
			fqdn := strings.TrimSpace(line)
			if fqdn == "" {
				continue
			}
			// Normalise wildcard entries before deduplication.
			normalised := strings.TrimPrefix(fqdn, "*.")
			if _, dup := seen[normalised]; dup {
				continue
			}
			seen[normalised] = struct{}{}

			prefix, zone, mnc, mcc, ok := ParseFQDN(fqdn)
			if !ok {
				continue
			}

			inPred, isNew := ClassifyHost(prefix, zone, DefaultSubdomains)

			hosts = append(hosts, DiscoveredHost{
				Source:         "crtsh",
				FQDN:           normalised,
				ServicePrefix:  prefix,
				Zone:           zone,
				MNC:            mnc,
				MCC:            mcc,
				InPredefined:   inPred,
				IsNewCandidate: isNew,
				CertID:         strconv.FormatInt(entry.ID, 10),
			})

			if d.config.Limit > 0 && len(hosts) >= d.config.Limit {
				return hosts, nil
			}
		}
	}

	return hosts, nil
}

// QueryHackerTarget queries HackerTarget's host-search API for 3gppnetwork.org
// entries and returns the parsed host list.
// The API returns lines in the format "hostname,ip".
func (d *Discoverer) QueryHackerTarget(ctx context.Context) ([]DiscoveredHost, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.config.HackerTargetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("discover: build hackertarget request: %w", err)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discover: hackertarget request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discover: hackertarget returned status %d", resp.StatusCode)
	}

	seen := make(map[string]struct{})
	var hosts []DiscoveredHost

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ",", 2)
		fqdn := strings.TrimSpace(parts[0])
		if fqdn == "" {
			continue
		}

		if _, dup := seen[fqdn]; dup {
			continue
		}
		seen[fqdn] = struct{}{}

		prefix, zone, mnc, mcc, ok := ParseFQDN(fqdn)
		if !ok {
			continue
		}

		inPred, isNew := ClassifyHost(prefix, zone, DefaultSubdomains)

		hosts = append(hosts, DiscoveredHost{
			Source:         "hackertarget",
			FQDN:           fqdn,
			ServicePrefix:  prefix,
			Zone:           zone,
			MNC:            mnc,
			MCC:            mcc,
			InPredefined:   inPred,
			IsNewCandidate: isNew,
		})

		if d.config.Limit > 0 && len(hosts) >= d.config.Limit {
			return hosts, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("discover: reading hackertarget response: %w", err)
	}

	return hosts, nil
}
