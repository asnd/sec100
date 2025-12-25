package stats

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"3gpp-scanner/internal/models"
)

// Analyzer handles statistical analysis of FQDN data
type Analyzer struct {
	mccPattern      *regexp.Regexp
	mncPattern      *regexp.Regexp
	subdomainPattern *regexp.Regexp
}

// NewAnalyzer creates a new analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		mccPattern:      regexp.MustCompile(`mcc(\d+)\.`),
		mncPattern:      regexp.MustCompile(`mnc(\d+)\.`),
		subdomainPattern: regexp.MustCompile(`^([^.]+)\.`),
	}
}

// AnalyzeFile analyzes a file containing FQDNs
func (a *Analyzer) AnalyzeFile(filePath string) (*models.Stats, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	stats := &models.Stats{
		MCCDistribution: make(map[string]int),
		SubdomainCounts: make(map[string]int),
		CountryCounts:   make(map[string]int),
	}

	scanner := bufio.NewScanner(file)
	ipSet := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		stats.TotalFQDNs++

		// Extract MCC
		if matches := a.mccPattern.FindStringSubmatch(line); len(matches) > 1 {
			mcc := matches[1]
			stats.MCCDistribution[mcc]++
		}

		// Extract subdomain type
		if matches := a.subdomainPattern.FindStringSubmatch(line); len(matches) > 1 {
			subdomain := matches[1]
			stats.SubdomainCounts[subdomain]++
		}

		// Track IPs if the line contains them
		if strings.Contains(line, " ") {
			parts := strings.Fields(line)
			for _, part := range parts[1:] {
				ipSet[part] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	stats.TotalIPs = len(ipSet)
	return stats, nil
}

// AnalyzeResults analyzes DNS results directly
func (a *Analyzer) AnalyzeResults(results []models.DNSResult) *models.Stats {
	stats := &models.Stats{
		MCCDistribution: make(map[string]int),
		SubdomainCounts: make(map[string]int),
		CountryCounts:   make(map[string]int),
	}

	operatorSet := make(map[string]bool)
	ipSet := make(map[string]bool)

	for _, result := range results {
		stats.TotalFQDNs++

		// MCC distribution
		mcc := fmt.Sprintf("%d", result.MCC)
		stats.MCCDistribution[mcc]++

		// Subdomain counts
		stats.SubdomainCounts[result.Subdomain]++

		// Unique operators
		operatorSet[result.Operator] = true

		// Track IPs
		for _, ip := range result.IPs {
			ipSet[ip] = true
		}
	}

	stats.UniqueOperators = len(operatorSet)
	stats.TotalIPs = len(ipSet)

	return stats
}

// FormatStats formats statistics for display
func FormatStats(stats *models.Stats) string {
	var sb strings.Builder

	sb.WriteString("=== 3GPP Scanner Statistics ===\n\n")
	sb.WriteString(fmt.Sprintf("Total FQDNs: %d\n", stats.TotalFQDNs))
	sb.WriteString(fmt.Sprintf("Total IPs: %d\n", stats.TotalIPs))
	sb.WriteString(fmt.Sprintf("Unique Operators: %d\n\n", stats.UniqueOperators))

	// MCC Distribution
	if len(stats.MCCDistribution) > 0 {
		sb.WriteString("MCC Distribution (Top 10):\n")
		mccPairs := sortMapByValue(stats.MCCDistribution)
		for i, pair := range mccPairs {
			if i >= 10 {
				break
			}
			sb.WriteString(fmt.Sprintf("  MCC %s: %d\n", pair.Key, pair.Value))
		}
		sb.WriteString("\n")
	}

	// Subdomain Distribution
	if len(stats.SubdomainCounts) > 0 {
		sb.WriteString("Subdomain Distribution:\n")
		subPairs := sortMapByValue(stats.SubdomainCounts)
		for _, pair := range subPairs {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", pair.Key, pair.Value))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// KeyValue is a helper struct for sorting maps
type KeyValue struct {
	Key   string
	Value int
}

// sortMapByValue sorts a map by value in descending order
func sortMapByValue(m map[string]int) []KeyValue {
	var pairs []KeyValue
	for k, v := range m {
		pairs = append(pairs, KeyValue{k, v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Value > pairs[j].Value
	})
	return pairs
}
