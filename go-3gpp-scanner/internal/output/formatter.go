package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"3gpp-scanner/internal/models"
)

// ExportJSON exports data to JSON format
func ExportJSON(data interface{}, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

// ExportResultsCSV exports DNS results to CSV format
func ExportResultsCSV(results []models.DNSResult, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"FQDN", "IPs", "Subdomain", "MNC", "MCC", "Operator", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write data
	for _, result := range results {
		ips := ""
		for i, ip := range result.IPs {
			if i > 0 {
				ips += ";"
			}
			ips += ip
		}

		row := []string{
			result.FQDN,
			ips,
			result.Subdomain,
			fmt.Sprintf("%d", result.MNC),
			fmt.Sprintf("%d", result.MCC),
			result.Operator,
			result.Timestamp.Format("2006-01-02 15:04:05"),
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	return nil
}

// ExportPingResultsCSV exports ping results to CSV format
func ExportPingResultsCSV(results []models.PingResult, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"FQDN", "Success", "Latency_ms", "IP", "Method", "Error", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write data
	for _, result := range results {
		latencyMs := ""
		if result.Latency > 0 {
			latencyMs = fmt.Sprintf("%.2f", float64(result.Latency.Microseconds())/1000.0)
		}

		row := []string{
			result.FQDN,
			fmt.Sprintf("%t", result.Success),
			latencyMs,
			result.IP,
			result.Method,
			result.Error,
			result.Timestamp.Format("2006-01-02 15:04:05"),
		}

		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	return nil
}

// ExportFQDNList exports a simple list of FQDNs to a text file
func ExportFQDNList(results []models.DNSResult, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	for _, result := range results {
		if _, err := fmt.Fprintln(file, result.FQDN); err != nil {
			return fmt.Errorf("failed to write FQDN: %w", err)
		}
	}

	return nil
}

// PrintResults prints DNS results to stdout
func PrintResults(results []models.DNSResult) {
	for _, result := range results {
		fmt.Printf("Found A record for %s\n", result.FQDN)
		if len(result.IPs) > 0 {
			for _, ip := range result.IPs {
				fmt.Printf("  IP: %s\n", ip)
			}
		}
	}
}

// PrintPingResults prints ping results to stdout
func PrintPingResults(results []models.PingResult) {
	for _, result := range results {
		if result.Success {
			latencyMs := float64(result.Latency.Microseconds()) / 1000.0
			fmt.Printf("Pinging %s ... %s (%.2f ms)\n", result.FQDN, result.IP, latencyMs)
		} else if result.Error != "" {
			fmt.Printf("Pinging %s ... FAILED: %s\n", result.FQDN, result.Error)
		}
	}
}
