package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ReportConfig holds configuration for report generation.
type ReportConfig struct {
	DBPath          string
	Format          string
	OperatorFilter  string
	SeverityMin     string
	TopN            int
	Verbose         bool
}

// DefaultReportConfig returns a ReportConfig with sensible defaults.
func DefaultReportConfig() *ReportConfig {
	return &ReportConfig{
		Format:      "text",
		SeverityMin: "INFO",
		TopN:        20,
	}
}

// RiskFinding represents a single security risk finding.
type RiskFinding struct {
	Operator    string `json:"operator"`
	CountryName string `json:"country_name"`
	MCC         int    `json:"mcc"`
	MNC         int    `json:"mnc"`
	ControlRef  string `json:"control_ref"`
	FindingType string `json:"finding_type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Evidence    string `json:"evidence"`
	DetectedAt  string `json:"detected_at"`
}

// ReportSummary holds aggregate statistics for a report.
type ReportSummary struct {
	GeneratedAt   string            `json:"generated_at"`
	TotalFindings int               `json:"total_findings"`
	BySeverity    map[string]int    `json:"by_severity"`
	TopOperators  []string          `json:"top_operators"`
	FindingTypes  map[string]int    `json:"finding_types"`
}

// Report is the top-level structure returned by BuildReport.
type Report struct {
	Summary  ReportSummary `json:"summary"`
	Findings []RiskFinding `json:"findings"`
}

// ControlMap maps finding_type to [control_ref, severity, title].
var ControlMap = map[string][3]string{
	"expired_cert":     {"GSMA FS.31 4.3", "CRITICAL", "Expired TLS Certificate"},
	"weak_ike_crypto":  {"3GPP TS 33.402 7.3", "HIGH", "Weak IKEv2 Cipher Suite"},
	"5gc_pub_leak":     {"3GPP TS 29.573 4.4", "HIGH", "5GC NF in Public DNS"},
	"sepp_pub_leak":    {"3GPP TS 29.573 4.4", "CRITICAL", "SEPP in Public DNS"},
	"missing_epdg":     {"3GPP TS 24.302", "MEDIUM", "No VoWiFi Published"},
	"diameter_public":  {"GSMA IR.88 4.2", "HIGH", "Diameter Realm on Public DNS"},
	"rsp_smdp_exposed": {"GSMA SGP.22 4.1", "INFO", "SM-DP+ Discovered"},
	"self_signed_cert": {"GSMA FS.31 4.3", "HIGH", "Self-Signed Certificate"},
	"weak_sig_cert":    {"GSMA NESAS/TS 33.310", "HIGH", "SHA-1/MD5 Cert"},
	"missing_ims":      {"3GPP TS 24.229", "MEDIUM", "No IMS Published"},
}

// SeverityOrder defines the display ordering from highest to lowest severity.
var SeverityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

// SeverityWeight returns a numeric weight for severity comparison.
// Higher weight means higher severity.
func SeverityWeight(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}

// Generator produces security reports from a slice of RiskFindings.
type Generator struct {
	Config *ReportConfig
}

// NewGenerator constructs a Generator with the provided config.
// If config is nil, DefaultReportConfig is used.
func NewGenerator(config *ReportConfig) *Generator {
	if config == nil {
		config = DefaultReportConfig()
	}
	return &Generator{Config: config}
}

// BuildReport aggregates findings into a Report with summary statistics.
func (g *Generator) BuildReport(findings []RiskFinding) Report {
	bySeverity := make(map[string]int)
	findingTypes := make(map[string]int)
	operatorCount := make(map[string]int)

	for _, f := range findings {
		bySeverity[f.Severity]++
		findingTypes[f.FindingType]++
		operatorCount[f.Operator]++
	}

	// Build top operators sorted by finding count descending, then name ascending.
	type opCount struct {
		name  string
		count int
	}
	ops := make([]opCount, 0, len(operatorCount))
	for name, count := range operatorCount {
		ops = append(ops, opCount{name, count})
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].count != ops[j].count {
			return ops[i].count > ops[j].count
		}
		return ops[i].name < ops[j].name
	})

	topN := g.Config.TopN
	if topN <= 0 || topN > len(ops) {
		topN = len(ops)
	}
	topOperators := make([]string, topN)
	for i := 0; i < topN; i++ {
		topOperators[i] = ops[i].name
	}

	summary := ReportSummary{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		TotalFindings: len(findings),
		BySeverity:    bySeverity,
		TopOperators:  topOperators,
		FindingTypes:  findingTypes,
	}

	return Report{
		Summary:  summary,
		Findings: findings,
	}
}

// FormatText renders the report as plain-text with a banner and summary.
func (g *Generator) FormatText(r Report) string {
	var sb strings.Builder

	sb.WriteString("================================================================================\n")
	sb.WriteString("  3GPP SECURITY RISK REPORT\n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("  Generated : %s\n", r.Summary.GeneratedAt))
	sb.WriteString(fmt.Sprintf("  Findings  : %d total\n", r.Summary.TotalFindings))
	sb.WriteString("================================================================================\n\n")

	sb.WriteString("SUMMARY BY SEVERITY\n")
	sb.WriteString("-------------------\n")
	for _, sev := range SeverityOrder {
		if count, ok := r.Summary.BySeverity[sev]; ok && count > 0 {
			sb.WriteString(fmt.Sprintf("  %-10s %d\n", sev, count))
		}
	}
	sb.WriteString("\n")

	if len(r.Summary.TopOperators) > 0 {
		sb.WriteString("TOP OPERATORS BY FINDING COUNT\n")
		sb.WriteString("------------------------------\n")
		for i, op := range r.Summary.TopOperators {
			sb.WriteString(fmt.Sprintf("  %2d. %s\n", i+1, op))
		}
		sb.WriteString("\n")
	}

	limit := g.Config.TopN
	findings := r.Findings
	if limit > 0 && limit < len(findings) {
		findings = findings[:limit]
	}

	sb.WriteString(fmt.Sprintf("FINDINGS (showing %d of %d)\n", len(findings), r.Summary.TotalFindings))
	sb.WriteString("----------------------------------------------------------\n")
	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("[%d] %s | %s | %s\n", i+1, f.Severity, f.Title, f.Operator))
		sb.WriteString(fmt.Sprintf("    Control  : %s\n", f.ControlRef))
		sb.WriteString(fmt.Sprintf("    Type     : %s\n", f.FindingType))
		if f.Evidence != "" {
			sb.WriteString(fmt.Sprintf("    Evidence : %s\n", f.Evidence))
		}
		if f.DetectedAt != "" {
			sb.WriteString(fmt.Sprintf("    Detected : %s\n", f.DetectedAt))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatMarkdown renders the report as a Markdown document.
func (g *Generator) FormatMarkdown(r Report) string {
	var sb strings.Builder

	sb.WriteString("# 3GPP Security Risk Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", r.Summary.GeneratedAt))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d\n\n", r.Summary.TotalFindings))

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString("### Findings by Severity\n\n")
	sb.WriteString("| Severity | Count |\n")
	sb.WriteString("|----------|-------|\n")
	for _, sev := range SeverityOrder {
		if count, ok := r.Summary.BySeverity[sev]; ok && count > 0 {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", sev, count))
		}
	}
	sb.WriteString("\n")

	if len(r.Summary.TopOperators) > 0 {
		sb.WriteString("### Top Operators by Finding Count\n\n")
		for i, op := range r.Summary.TopOperators {
			sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, op))
		}
		sb.WriteString("\n")
	}

	if len(r.Summary.FindingTypes) > 0 {
		sb.WriteString("### Finding Types\n\n")
		sb.WriteString("| Type | Count |\n")
		sb.WriteString("|------|-------|\n")
		// Stable iteration: sort keys.
		types := make([]string, 0, len(r.Summary.FindingTypes))
		for t := range r.Summary.FindingTypes {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", t, r.Summary.FindingTypes[t]))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Findings\n\n")
	sb.WriteString("| # | Severity | Title | Operator | Country | MCC | MNC | Control | Detected |\n")
	sb.WriteString("|---|----------|-------|----------|---------|-----|-----|---------|----------|\n")

	limit := g.Config.TopN
	findings := r.Findings
	if limit > 0 && limit < len(findings) {
		findings = findings[:limit]
	}

	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | %d | %d | %s | %s |\n",
			i+1, f.Severity, f.Title, f.Operator, f.CountryName,
			f.MCC, f.MNC, f.ControlRef, f.DetectedAt))
	}
	sb.WriteString("\n")

	if g.Config.Verbose {
		sb.WriteString("## Detailed Evidence\n\n")
		for i, f := range findings {
			if f.Evidence != "" {
				sb.WriteString(fmt.Sprintf("### %d. %s — %s\n\n", i+1, f.Title, f.Operator))
				sb.WriteString(fmt.Sprintf("```\n%s\n```\n\n", f.Evidence))
			}
		}
	}

	return sb.String()
}

// FormatJSON serialises the report to indented JSON.
func (g *Generator) FormatJSON(r Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// FilterFindings filters a slice of RiskFinding by operator substring,
// minimum severity weight, and a topN limit.
func FilterFindings(findings []RiskFinding, operatorFilter, severityMin string, topN int) []RiskFinding {
	minWeight := SeverityWeight(severityMin)

	filtered := make([]RiskFinding, 0, len(findings))
	for _, f := range findings {
		if operatorFilter != "" && !strings.Contains(
			strings.ToLower(f.Operator), strings.ToLower(operatorFilter)) {
			continue
		}
		if SeverityWeight(f.Severity) < minWeight {
			continue
		}
		filtered = append(filtered, f)
	}

	if topN > 0 && topN < len(filtered) {
		filtered = filtered[:topN]
	}

	return filtered
}
