package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"3gpp-scanner/internal/database"
	"3gpp-scanner/internal/dns"
	"3gpp-scanner/internal/fetcher"
	"3gpp-scanner/internal/models"
	"3gpp-scanner/internal/output"
	"3gpp-scanner/internal/ping"
	"3gpp-scanner/internal/stats"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var (
	version = "1.0.0"

	// Global flags
	verbose bool
	quiet   bool

	// Scan command flags
	scanMode        string
	scanSubdomains  string
	scanDB          string
	scanOutput      string
	scanConcurrency int
	scanDelay       int
	scanMCCMNCFile  string

	// Ping command flags
	pingFile    string
	pingMethod  string
	pingTimeout int
	pingWorkers int
	pingOutput  string

	// Query command flags
	queryMNC      int
	queryMCC      int
	queryOperator string
	queryDB       string
	queryExport   string

	// Stats command flags
	statsFile   string
	statsDB     string
	statsFormat string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "3gpp-scanner",
		Short: "3GPP network discovery and analysis tool",
		Long: `A unified toolkit for discovering and analyzing ePDG and 3GPP mobile
network infrastructure through DNS reconnaissance.`,
		Version: version,
	}

	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress output except errors")

	// Add subcommands
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(pingCmd())
	rootCmd.AddCommand(queryCmd())
	rootCmd.AddCommand(statsCmd())
	rootCmd.AddCommand(fetchMCCMNCCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan 3GPP network infrastructure via DNS",
		Long: `Enumerate 3GPP network subdomains (ePDG, IMS, BSF, GAN, XCAP) across
global MCC-MNC combinations to identify exposed telecom infrastructure.`,
		RunE: runScan,
	}

	cmd.Flags().StringVarP(&scanMode, "mode", "m", "all", "Scan mode: all, epdg, ims, bsf, gan, xcap, custom")
	cmd.Flags().StringVar(&scanSubdomains, "subdomains", "", "Custom subdomain list (comma-separated, for mode=custom)")
	cmd.Flags().StringVar(&scanDB, "db", "", "Database file path (if set, results will be saved to SQLite)")
	cmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output file (json, csv, or txt)")
	cmd.Flags().IntVarP(&scanConcurrency, "concurrency", "c", 10, "Number of concurrent DNS queries")
	cmd.Flags().IntVar(&scanDelay, "delay", 500, "Delay between queries in milliseconds")
	cmd.Flags().StringVar(&scanMCCMNCFile, "mccmnc-file", "", "Use local MCC-MNC JSON file instead of fetching")

	return cmd
}

func pingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Test connectivity to discovered FQDNs",
		Long:  `Ping FQDNs using ICMP (requires root) or TCP connectivity checks.`,
		RunE:  runPing,
	}

	cmd.Flags().StringVarP(&pingFile, "file", "f", "", "File containing FQDNs (one per line)")
	cmd.Flags().StringVar(&pingMethod, "method", "icmp", "Ping method: icmp or tcp")
	cmd.Flags().IntVar(&pingTimeout, "timeout", 300, "Timeout in milliseconds")
	cmd.Flags().IntVarP(&pingWorkers, "workers", "w", 10, "Number of concurrent ping workers")
	cmd.Flags().StringVarP(&pingOutput, "output", "o", "", "Output file (json or csv)")

	return cmd
}

func queryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "query",
		Short: "Query the database for operator information",
		Long:  `Query FQDNs by MNC/MCC or operator name from the SQLite database.`,
		RunE:  runQuery,
	}

	cmd.Flags().IntVar(&queryMNC, "mnc", 0, "Mobile Network Code")
	cmd.Flags().IntVar(&queryMCC, "mcc", 0, "Mobile Country Code")
	cmd.Flags().StringVar(&queryOperator, "operator", "", "Operator name")
	cmd.Flags().StringVar(&queryDB, "db", "database.db", "Database file path")
	cmd.Flags().StringVar(&queryExport, "export", "", "Export format: json or csv")

	return cmd
}

func statsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Generate statistics from scan results",
		Long:  `Analyze FQDN files or database and generate statistics.`,
		RunE:  runStats,
	}

	cmd.Flags().StringVarP(&statsFile, "file", "f", "", "FQDN file to analyze")
	cmd.Flags().StringVar(&statsDB, "db", "", "Database to analyze")
	cmd.Flags().StringVar(&statsFormat, "format", "text", "Output format: text, json, or csv")

	return cmd
}

func fetchMCCMNCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch-mccmnc",
		Short: "Download MCC-MNC list",
		Long:  `Download the latest MCC-MNC list from GitHub and save locally.`,
		RunE:  runFetchMCCMNC,
	}

	return cmd
}

// Scan command implementation
func runScan(cmd *cobra.Command, args []string) error {
	// Determine subdomains based on mode
	var subdomains []string
	switch scanMode {
	case "all":
		subdomains = []string{"ims", "epdg.epc", "bsf", "gan", "xcap.ims"}
	case "epdg":
		subdomains = []string{"epdg.epc"}
	case "ims":
		subdomains = []string{"ims"}
	case "bsf":
		subdomains = []string{"bsf"}
	case "gan":
		subdomains = []string{"gan"}
	case "xcap":
		subdomains = []string{"xcap.ims"}
	case "custom":
		if scanSubdomains == "" {
			return fmt.Errorf("--subdomains required for custom mode")
		}
		subdomains = strings.Split(scanSubdomains, ",")
	default:
		return fmt.Errorf("invalid mode: %s", scanMode)
	}

	if !quiet {
		fmt.Printf("Starting scan with mode=%s, subdomains=%v\n", scanMode, subdomains)
	}

	// Fetch MCC-MNC list
	f := fetcher.NewFetcher("", ".", 24*time.Hour, verbose)
	var entries []models.MCCMNCEntry
	var err error

	if scanMCCMNCFile != "" {
		entries, err = f.FetchFromFile(scanMCCMNCFile)
	} else {
		entries, err = f.Fetch()
	}

	if err != nil {
		return fmt.Errorf("failed to fetch MCC-MNC list: %w", err)
	}

	if !quiet {
		fmt.Printf("Loaded %d MCC-MNC entries\n", len(entries))
	}

	// Configure scanner
	config := &models.ScanConfig{
		ParentDomain: "pub.3gppnetwork.org",
		Subdomains:   subdomains,
		QueryDelay:   time.Duration(scanDelay) * time.Millisecond,
		Concurrency:  scanConcurrency,
		Verbose:      verbose,
	}

	scanner := dns.NewScanner(config)

	// Setup progress bar if not quiet/verbose
	totalQueries := len(entries) * len(subdomains)
	var bar *progressbar.ProgressBar
	if !quiet && !verbose {
		bar = progressbar.NewOptions(totalQueries,
			progressbar.OptionSetDescription("Scanning DNS"),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetPredictTime(true),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]=[reset]",
				SaucerHead:    "[green]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprintf(os.Stderr, "\n")
			}),
		)

		scanner.SetProgressCallback(func(current, total int, found int) {
			bar.Set(current)
		})
	}

	// Run scan
	ctx := context.Background()
	results, err := scanner.Scan(ctx, entries)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if !quiet {
		fmt.Printf("Scan complete! Found %d FQDNs\n", len(results))
	}

	// Print to stdout if not quiet
	if !quiet && scanOutput == "" && scanDB == "" {
		output.PrintResults(results)
	}

	// Save to database if requested
	if scanDB != "" {
		if !quiet {
			fmt.Printf("Saving results to database: %s\n", scanDB)
		}
		db, err := database.NewDB(scanDB)
		if err != nil {
			return fmt.Errorf("database error: %w", err)
		}
		defer db.Close()

		if err := db.InsertResults(results); err != nil {
			return fmt.Errorf("failed to save results: %w", err)
		}
		if !quiet {
			fmt.Printf("Saved %d results to database\n", len(results))
		}
	}

	// Export to file if requested
	if scanOutput != "" {
		if err := exportScanResults(results, scanOutput); err != nil {
			return fmt.Errorf("export failed: %w", err)
		}
		if !quiet {
			fmt.Printf("Exported results to: %s\n", scanOutput)
		}
	}

	return nil
}

// Ping command implementation
func runPing(cmd *cobra.Command, args []string) error {
	if pingFile == "" {
		return fmt.Errorf("--file required")
	}

	// Read FQDNs from file
	fqdns, err := readFQDNsFromFile(pingFile)
	if err != nil {
		return fmt.Errorf("failed to read FQDNs: %w", err)
	}

	if !quiet {
		fmt.Printf("Pinging %d FQDNs using %s method\n", len(fqdns), pingMethod)
	}

	// Configure pinger
	config := &models.PingConfig{
		Method:   pingMethod,
		Timeout:  time.Duration(pingTimeout) * time.Millisecond,
		Workers:  pingWorkers,
		TCPPorts: []int{443, 4500},
		Verbose:  verbose,
	}

	pinger := ping.NewPinger(config)

	// Setup progress bar if not quiet/verbose
	var bar *progressbar.ProgressBar
	if !quiet && !verbose {
		bar = progressbar.NewOptions(len(fqdns),
			progressbar.OptionSetDescription(fmt.Sprintf("Pinging (%s)", pingMethod)),
			progressbar.OptionSetWriter(os.Stderr),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetPredictTime(true),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[cyan]=[reset]",
				SaucerHead:    "[cyan]>[reset]",
				SaucerPadding: " ",
				BarStart:      "[",
				BarEnd:        "]",
			}),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprintf(os.Stderr, "\n")
			}),
		)

		pinger.SetProgressCallback(func(current, total int, successful int) {
			bar.Set(current)
		})
	}

	// Run ping
	ctx := context.Background()
	results, err := pinger.Ping(ctx, fqdns)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Print results
	if !quiet {
		output.PrintPingResults(results)
		successCount := 0
		for _, r := range results {
			if r.Success {
				successCount++
			}
		}
		fmt.Printf("\nTotal: %d, Success: %d, Failed: %d\n",
			len(results), successCount, len(results)-successCount)
	}

	// Export if requested
	if pingOutput != "" {
		if err := exportPingResults(results, pingOutput); err != nil {
			return fmt.Errorf("export failed: %w", err)
		}
		if !quiet {
			fmt.Printf("Exported results to: %s\n", pingOutput)
		}
	}

	return nil
}

// Query command implementation
func runQuery(cmd *cobra.Command, args []string) error {
	db, err := database.NewDB(queryDB)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	var fqdns []string

	if queryMNC > 0 && queryMCC > 0 {
		fqdns, err = db.QueryByMNCMCC(queryMNC, queryMCC)
		if err != nil {
			return fmt.Errorf("query failed: %w", err)
		}
		if !quiet {
			fmt.Printf("Results for MNC=%d, MCC=%d:\n", queryMNC, queryMCC)
		}
	} else if queryOperator != "" {
		fqdns, err = db.QueryByOperator(queryOperator)
		if err != nil {
			return fmt.Errorf("query failed: %w", err)
		}
		if !quiet {
			fmt.Printf("Results for operator=%s:\n", queryOperator)
		}
	} else {
		return fmt.Errorf("either --mnc/--mcc or --operator required")
	}

	// Print results
	for _, fqdn := range fqdns {
		fmt.Println(fqdn)
	}

	if !quiet {
		fmt.Printf("\nFound %d FQDNs\n", len(fqdns))
	}

	return nil
}

// Stats command implementation
func runStats(cmd *cobra.Command, args []string) error {
	analyzer := stats.NewAnalyzer()
	var st *models.Stats
	var err error

	if statsFile != "" {
		st, err = analyzer.AnalyzeFile(statsFile)
		if err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}
	} else if statsDB != "" {
		db, err := database.NewDB(statsDB)
		if err != nil {
			return fmt.Errorf("database error: %w", err)
		}
		defer db.Close()

		st, err = db.GetStats()
		if err != nil {
			return fmt.Errorf("stats query failed: %w", err)
		}
	} else {
		return fmt.Errorf("either --file or --db required")
	}

	// Output stats
	if statsFormat == "json" {
		if err := output.ExportJSON(st, "/dev/stdout"); err != nil {
			return fmt.Errorf("JSON export failed: %w", err)
		}
	} else {
		fmt.Print(stats.FormatStats(st))
	}

	return nil
}

// Fetch MCC-MNC command implementation
func runFetchMCCMNC(cmd *cobra.Command, args []string) error {
	if !quiet {
		fmt.Println("Fetching MCC-MNC list from GitHub...")
	}

	f := fetcher.NewFetcher("", ".", 0, verbose) // No cache TTL for forced fetch
	entries, err := f.Fetch()
	if err != nil {
		return fmt.Errorf("fetch failed: %w", err)
	}

	if !quiet {
		fmt.Printf("Successfully fetched %d entries\n", len(entries))
		fmt.Println("Saved to: mcc-mnc-list.json")
	}

	return nil
}

// Helper functions

func exportScanResults(results []models.DNSResult, filePath string) error {
	ext := strings.ToLower(filePath[len(filePath)-4:])

	switch ext {
	case ".json":
		return output.ExportJSON(results, filePath)
	case ".csv":
		return output.ExportResultsCSV(results, filePath)
	case ".txt":
		return output.ExportFQDNList(results, filePath)
	default:
		return fmt.Errorf("unsupported format (use .json, .csv, or .txt)")
	}
}

func exportPingResults(results []models.PingResult, filePath string) error {
	ext := strings.ToLower(filePath[len(filePath)-4:])

	switch ext {
	case ".json":
		return output.ExportJSON(results, filePath)
	case ".csv":
		return output.ExportPingResultsCSV(results, filePath)
	default:
		return fmt.Errorf("unsupported format (use .json or .csv)")
	}
}

func readFQDNsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var fqdns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			fqdns = append(fqdns, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return fqdns, nil
}
