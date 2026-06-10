package report

import (
	"strings"
	"testing"
)

// TestSeverityWeight verifies numeric weights for all severity levels.
func TestSeverityWeight(t *testing.T) {
	cases := []struct {
		severity string
		want     int
	}{
		{"CRITICAL", 5},
		{"HIGH", 4},
		{"MEDIUM", 3},
		{"LOW", 2},
		{"INFO", 1},
		{"UNKNOWN", 0},
	}

	for _, tc := range cases {
		got := SeverityWeight(tc.severity)
		if got != tc.want {
			t.Errorf("SeverityWeight(%q) = %d, want %d", tc.severity, got, tc.want)
		}
	}
}

// TestBuildReport verifies that summary counts are correctly derived from findings.
func TestBuildReport(t *testing.T) {
	findings := []RiskFinding{
		{Operator: "Alpha Mobile", FindingType: "expired_cert", Severity: "CRITICAL"},
		{Operator: "Alpha Mobile", FindingType: "weak_ike_crypto", Severity: "HIGH"},
		{Operator: "Beta Telecom", FindingType: "missing_epdg", Severity: "MEDIUM"},
		{Operator: "Gamma Net", FindingType: "rsp_smdp_exposed", Severity: "INFO"},
		{Operator: "Alpha Mobile", FindingType: "self_signed_cert", Severity: "HIGH"},
	}

	g := NewGenerator(DefaultReportConfig())
	r := g.BuildReport(findings)

	if r.Summary.TotalFindings != 5 {
		t.Errorf("TotalFindings = %d, want 5", r.Summary.TotalFindings)
	}

	if r.Summary.BySeverity["CRITICAL"] != 1 {
		t.Errorf("BySeverity[CRITICAL] = %d, want 1", r.Summary.BySeverity["CRITICAL"])
	}
	if r.Summary.BySeverity["HIGH"] != 2 {
		t.Errorf("BySeverity[HIGH] = %d, want 2", r.Summary.BySeverity["HIGH"])
	}
	if r.Summary.BySeverity["MEDIUM"] != 1 {
		t.Errorf("BySeverity[MEDIUM] = %d, want 1", r.Summary.BySeverity["MEDIUM"])
	}
	if r.Summary.BySeverity["INFO"] != 1 {
		t.Errorf("BySeverity[INFO] = %d, want 1", r.Summary.BySeverity["INFO"])
	}

	// Alpha Mobile has 3 findings, should be first in top operators.
	if len(r.Summary.TopOperators) == 0 {
		t.Fatal("TopOperators is empty")
	}
	if r.Summary.TopOperators[0] != "Alpha Mobile" {
		t.Errorf("TopOperators[0] = %q, want %q", r.Summary.TopOperators[0], "Alpha Mobile")
	}

	if r.Summary.FindingTypes["expired_cert"] != 1 {
		t.Errorf("FindingTypes[expired_cert] = %d, want 1", r.Summary.FindingTypes["expired_cert"])
	}
}

// TestFilterFindings verifies operator substring filter and topN limit.
func TestFilterFindings(t *testing.T) {
	findings := []RiskFinding{
		{Operator: "Alpha Mobile", Severity: "CRITICAL"},
		{Operator: "Alpha Mobile", Severity: "HIGH"},
		{Operator: "Beta Telecom", Severity: "MEDIUM"},
		{Operator: "Beta Telecom", Severity: "LOW"},
		{Operator: "Gamma Net", Severity: "INFO"},
	}

	// Operator filter: only "alpha" (case-insensitive).
	filtered := FilterFindings(findings, "alpha", "INFO", 0)
	if len(filtered) != 2 {
		t.Errorf("operator filter: got %d findings, want 2", len(filtered))
	}

	// Severity filter: only HIGH and above.
	filtered = FilterFindings(findings, "", "HIGH", 0)
	if len(filtered) != 2 {
		t.Errorf("severity filter HIGH+: got %d findings, want 2", len(filtered))
	}

	// topN limit.
	filtered = FilterFindings(findings, "", "INFO", 3)
	if len(filtered) != 3 {
		t.Errorf("topN limit: got %d findings, want 3", len(filtered))
	}

	// No filter — all 5 findings returned.
	filtered = FilterFindings(findings, "", "INFO", 0)
	if len(filtered) != 5 {
		t.Errorf("no filter: got %d findings, want 5", len(filtered))
	}
}

// TestFormatMarkdown verifies that Markdown output contains the required heading marker.
func TestFormatMarkdown(t *testing.T) {
	findings := []RiskFinding{
		{Operator: "Test Operator", FindingType: "expired_cert", Severity: "CRITICAL",
			Title: "Expired TLS Certificate", ControlRef: "GSMA FS.31 4.3"},
	}

	g := NewGenerator(DefaultReportConfig())
	r := g.BuildReport(findings)
	md := g.FormatMarkdown(r)

	if !strings.Contains(md, "#") {
		t.Error("FormatMarkdown output does not contain '#' heading marker")
	}
	if !strings.Contains(md, "Executive Summary") {
		t.Error("FormatMarkdown output missing '## Executive Summary' section")
	}
	if !strings.Contains(md, "Findings") {
		t.Error("FormatMarkdown output missing 'Findings' section")
	}
}

// TestControlMapSize verifies that ControlMap has at least 8 entries.
func TestControlMapSize(t *testing.T) {
	if len(ControlMap) < 8 {
		t.Errorf("ControlMap has %d entries, want >= 8", len(ControlMap))
	}
}
