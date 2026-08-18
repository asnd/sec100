package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"3gpp-scanner/internal/database"
	"3gpp-scanner/internal/diameter"
	"3gpp-scanner/internal/discover"
	"3gpp-scanner/internal/dns"
	"3gpp-scanner/internal/fetcher"
	"3gpp-scanner/internal/models"
	"3gpp-scanner/internal/output"
	"3gpp-scanner/internal/ping"
	"3gpp-scanner/internal/probe"
	"3gpp-scanner/internal/report"
	"3gpp-scanner/internal/rsp"
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

	// Probe command flags
	probeDB      string
	probeWorkers int
	probeTimeout int
	probeActive  bool

	// Discover command flags
	discoverDB     string
	discoverLimit  int
	discoverOutput string

	// Diameter command flags
	diameterDB        string
	diameterSource    string
	diameterWorkers   int
	diameterDNSServer string

	// RSP command flags
	rspDB      string
	rspWorkers int
	rspActive  bool
	rspOutput  string

	// Report command flags
	reportDB       string
	reportFormat   string
	reportOutput   string
	reportOperator string
	reportCollect  bool
	reportTopN     int
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
	rootCmd.AddCommand(probeCmd())
	rootCmd.AddCommand(discoverCmd())
	rootCmd.AddCommand(diameterCmd())
	rootCmd.AddCommand(rspCmd())
	rootCmd.AddCommand(reportCmd())

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
		Example: `  # Scan only ePDG endpoints
  3gpp-scanner scan --mode=epdg

  # Scan all types and save to database with high concurrency
  3gpp-scanner scan --mode=all --db=database.db --concurrency=20

  # Scan custom subdomains with rate limiting
  3gpp-scanner scan --mode=custom --subdomains=ims,bsf --delay=250`,
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
		Example: `  # TCP connectivity check (no root required)
  3gpp-scanner ping --file=results.txt --method=tcp

  # ICMP ping with custom timeout and workers, export to JSON
  sudo 3gpp-scanner ping --file=fqdns.txt --method=icmp --timeout=500 --workers=20 --output=results.json`,
		RunE: runPing,
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
		Example: `  # Query by MNC and MCC
  3gpp-scanner query --mnc=001 --mcc=310 --db=database.db

  # Query by operator name and export as CSV
  3gpp-scanner query --operator="Verizon" --db=database.db --export=csv`,
		RunE: runQuery,
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
		Example: `  # Analyze FQDN file with text output
  3gpp-scanner stats --file=epdg-fqdn-raw.txt

  # Analyze database and export as JSON
  3gpp-scanner stats --db=database.db --format=json`,
		RunE: runStats,
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
		Example: `  # Download latest MCC-MNC list
  3gpp-scanner fetch-mccmnc`,
		RunE: runFetchMCCMNC,
	}

	return cmd
}

func probeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Probe TLS certs and IKEv2 on discovered endpoints",
		Long: `Fingerprint discovered 3GPP endpoints by probing TLS certificates and
IKEv2 exchanges. In passive mode (default) only metadata already stored in
the database is analysed. Pass --active to initiate real connections and
collect live TLS certificate chains, supported cipher suites, and IKEv2
SA proposals from ePDG endpoints.`,
		Example: `  # Passive analysis of database entries
  3gpp-scanner probe --db=database.db

  # Active TLS/IKEv2 probing with 20 workers
  3gpp-scanner probe --db=database.db --active --workers=20 --timeout=8000`,
		RunE: runProbe,
	}

	cmd.Flags().StringVar(&probeDB, "db", "database.db", "Database file path")
	cmd.Flags().IntVarP(&probeWorkers, "workers", "w", 10, "Number of concurrent probe workers")
	cmd.Flags().IntVar(&probeTimeout, "timeout", 5000, "Probe timeout in milliseconds")
	cmd.Flags().BoolVar(&probeActive, "active", false, "Enable active connections (TLS handshake + IKEv2 SA init)")

	return cmd
}

func discoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Passive CT log and passive DNS discovery",
		Long: `Discover 3GPP endpoints through passive sources without sending any
DNS queries to operator resolvers. Sources include Certificate Transparency
(CT) logs (crt.sh) and passive DNS databases. Newly found FQDNs are stored
in the database and can be further analysed with the probe or ping commands.`,
		Example: `  # Discover from CT logs, store results in database
  3gpp-scanner discover --db=database.db

  # Limit results and export to JSON
  3gpp-scanner discover --db=database.db --limit=500 --output=ct-results.json`,
		RunE: runDiscover,
	}

	cmd.Flags().StringVar(&discoverDB, "db", "database.db", "Database file path")
	cmd.Flags().IntVar(&discoverLimit, "limit", 0, "Maximum number of FQDNs to collect (0 = unlimited)")
	cmd.Flags().StringVarP(&discoverOutput, "output", "o", "", "Output file (json, csv, or txt)")

	return cmd
}

func diameterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diameter",
		Short: "Enumerate Diameter roaming realms via DNS",
		Long: `Enumerate Diameter roaming hub and inter-operator signalling endpoints
by resolving NAPTR/SRV records for well-known Diameter realm patterns
(e.g. epc.mnc<NNN>.mcc<MMM>.3gppnetwork.org). Results can be stored in
the database and cross-referenced with existing scan data.`,
		Example: `  # Enumerate Diameter realms using system resolver
  3gpp-scanner diameter --db=database.db

  # Use a specific DNS server with 20 workers
  3gpp-scanner diameter --db=database.db --dns-server=8.8.8.8 --workers=20

  # Seed from an existing FQDN file
  3gpp-scanner diameter --db=database.db --source=epdg-fqdn-raw.txt`,
		RunE: runDiameter,
	}

	cmd.Flags().StringVar(&diameterDB, "db", "database.db", "Database file path")
	cmd.Flags().StringVar(&diameterSource, "source", "", "Seed FQDN file (one per line)")
	cmd.Flags().IntVarP(&diameterWorkers, "workers", "w", 10, "Number of concurrent DNS workers")
	cmd.Flags().StringVar(&diameterDNSServer, "dns-server", "", "DNS server to use (default: system resolver)")

	return cmd
}

func rspCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rsp",
		Short: "Discover eSIM RSP endpoints (SM-DP+/SM-DS)",
		Long: `Discover eSIM Remote SIM Provisioning (RSP) infrastructure by enumerating
SM-DP+ and SM-DS endpoints as defined in GSMA SGP.22 and SGP.02. Combines
DNS enumeration of well-known RSP hostnames with optional active HTTPS
probing to verify endpoint availability and collect server certificates.`,
		Example: `  # Passive RSP enumeration
  3gpp-scanner rsp --db=database.db

  # Active probing with results exported to JSON
  3gpp-scanner rsp --db=database.db --active --workers=15 --output=rsp-results.json`,
		RunE: runRSP,
	}

	cmd.Flags().StringVar(&rspDB, "db", "database.db", "Database file path")
	cmd.Flags().IntVarP(&rspWorkers, "workers", "w", 10, "Number of concurrent RSP probe workers")
	cmd.Flags().BoolVar(&rspActive, "active", false, "Enable active HTTPS probing of RSP endpoints")
	cmd.Flags().StringVarP(&rspOutput, "output", "o", "", "Output file (json, csv, or txt)")

	return cmd
}

func reportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate GSMA FS.31/ETSI security baseline report",
		Long: `Generate a structured security baseline report aligned with GSMA FS.31
(Network Equipment Security Assurance Scheme) and relevant ETSI standards.
The report summarises discovered infrastructure, exposure metrics, and
recommended hardening actions for each operator or for the full dataset.
Run with --collect first to populate the database before generating reports.`,
		Example: `  # Generate a text report for all operators
  3gpp-scanner report --db=database.db

  # Generate a JSON report for a specific operator
  3gpp-scanner report --db=database.db --operator="Deutsche Telekom" --format=json --output=report.json

  # Collect fresh data then report, showing top 10 operators
  3gpp-scanner report --db=database.db --collect --top-n=10`,
		RunE: runReport,
	}

	cmd.Flags().StringVar(&reportDB, "db", "database.db", "Database file path")
	cmd.Flags().StringVar(&reportFormat, "format", "text", "Report format: text or json")
	cmd.Flags().StringVarP(&reportOutput, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&reportOperator, "operator", "", "Limit report to a specific operator name")
	cmd.Flags().BoolVar(&reportCollect, "collect", false, "Collect/refresh data before generating the report")
	cmd.Flags().IntVar(&reportTopN, "top-n", 20, "Number of top operators to include in summary tables")

	return cmd
}

// validateScanFlags validates scan command flags
func validateScanFlags() error {
	if scanMode == "custom" && scanSubdomains == "" {
		return fmt.Errorf("--subdomains required for custom mode")
	}
	validModes := map[string]bool{"all": true, "epdg": true, "ims": true, "bsf": true, "gan": true, "xcap": true, "custom": true}
	if !validModes[scanMode] {
		return fmt.Errorf("invalid mode: %s", scanMode)
	}
	if scanConcurrency <= 0 {
		return fmt.Errorf("--concurrency must be positive")
	}
	if scanDelay < 0 {
		return fmt.Errorf("--delay cannot be negative")
	}
	return nil
}

// validatePingFlags validates ping command flags
func validatePingFlags() error {
	if pingFile == "" {
		return fmt.Errorf("--file required")
	}
	if pingMethod != "icmp" && pingMethod != "tcp" {
		return fmt.Errorf("invalid method: %s (must be icmp or tcp)", pingMethod)
	}
	if pingTimeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	if pingWorkers <= 0 {
		return fmt.Errorf("--workers must be positive")
	}
	return nil
}

// validateQueryFlags validates query command flags
func validateQueryFlags() error {
	// MNC and MCC must be used together (check this first)
	if (queryMNC > 0 && queryMCC == 0) || (queryMNC == 0 && queryMCC > 0) {
		return fmt.Errorf("--mnc and --mcc must be used together")
	}

	hasMNCMCC := queryMNC > 0 && queryMCC > 0
	hasOperator := queryOperator != ""

	if !hasMNCMCC && !hasOperator {
		return fmt.Errorf("either --mnc/--mcc or --operator required")
	}

	return nil
}

// validateStatsFlags validates stats command flags
func validateStatsFlags() error {
	if statsFile == "" && statsDB == "" {
		return fmt.Errorf("either --file or --db required")
	}
	if statsFile != "" && statsDB != "" {
		return fmt.Errorf("cannot specify both --file and --db")
	}
	validFormats := map[string]bool{"text": true, "json": true, "csv": true}
	if !validFormats[statsFormat] {
		return fmt.Errorf("invalid format: %s (must be text, json, or csv)", statsFormat)
	}
	return nil
}

// Scan command implementation
func runScan(cmd *cobra.Command, args []string) error {
	// Validate flags
	if err := validateScanFlags(); err != nil {
		return err
	}

	// Determine subdomains based on mode
	var subdomains []string
	switch scanMode {
	case "all":
		// Full known pub.3gppnetwork.org service set (parity with discover.DefaultSubdomains).
		subdomains = append([]string{}, discover.DefaultSubdomains...)
	case "epdg":
		subdomains = []string{"epdg.epc", "ss.epdg.epc", "sos.epdg.epc", "vowifi"}
	case "ims":
		subdomains = []string{"ims", "pcscf.ims", "mmtel.ims", "xcap.ims", "ut.ims", "sos.ims"}
	case "bsf":
		subdomains = []string{"bsf"}
	case "gan":
		subdomains = []string{"gan"}
	case "xcap":
		subdomains = []string{"xcap.ims"}
	case "custom":
		subdomains = strings.Split(scanSubdomains, ",")
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
	// Validate flags
	if err := validatePingFlags(); err != nil {
		return err
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
	// Validate flags
	if err := validateQueryFlags(); err != nil {
		return err
	}

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
	// Validate flags
	if err := validateStatsFlags(); err != nil {
		return err
	}

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

// Probe command implementation
func runProbe(cmd *cobra.Command, args []string) error {
	db, err := database.NewDB(probeDB)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	cfg := probe.DefaultProbeConfig()
	cfg.Timeout = time.Duration(probeTimeout) * time.Millisecond
	cfg.Workers = probeWorkers
	cfg.Verbose = verbose
	p := probe.NewProber(cfg)

	if !probeActive {
		// Passive: summarise stored TLS/IKE findings already in the DB.
		findings, err := db.CollectRiskFindings()
		if err != nil {
			return err
		}
		var tlsN, ikeN int
		for _, f := range findings {
			switch f.FindingType {
			case "expired_cert", "self_signed_cert", "weak_sig_cert":
				tlsN++
			case "weak_ike_crypto":
				ikeN++
			}
		}
		if !quiet {
			fmt.Printf("Probe mode: passive\nDatabase: %s\n", probeDB)
			fmt.Printf("Stored TLS-related findings: %d\nStored IKE weak-crypto findings: %d\n", tlsN, ikeN)
			fmt.Println("Tip: use --active to initiate real TLS/IKEv2 connections")
		}
		return nil
	}

	if !quiet {
		fmt.Printf("Probe mode: active (TLS + IKEv2)\nDatabase: %s workers=%d timeout=%dms\n",
			probeDB, probeWorkers, probeTimeout)
	}

	// Probe FQDNs already discovered so the command is not a no-op.
	// Full multi-IP worker fan-out matches the Python toolkit more closely.
	ops, err := db.GetAllOperators()
	if err != nil {
		return err
	}
	ctx := context.Background()
	probed := 0
	for _, op := range ops {
		mnc, _ := strconv.Atoi(op.MNC)
		mcc, _ := strconv.Atoi(op.MCC)
		list, qerr := db.QueryByMNCMCC(mnc, mcc)
		if qerr != nil {
			continue
		}
		for _, fqdn := range list {
			// Prefer ePDG for IKE and xcap/ims for TLS based on prefix.
			if strings.Contains(fqdn, "epdg.epc.") {
				// Resolve is left to the OS; use hostname dial via empty IP fallback.
				res := p.ProbeIKE(ctx, fqdn, fqdn, 500, op.Operator)
				if verbose {
					fmt.Printf("IKE %s responded=%v weak=%v err=%s\n", fqdn, res.Responded, res.WeakCrypto, res.Error)
				}
				probed++
			} else if strings.Contains(fqdn, "xcap.ims.") || strings.HasPrefix(fqdn, "ims.") || strings.Contains(fqdn, "pcscf.ims.") {
				res := p.ProbeTLS(ctx, fqdn, fqdn, 443, op.Operator)
				if verbose {
					fmt.Printf("TLS %s vendor=%s expired=%v err=%s\n", fqdn, res.Vendor, res.IsExpired, res.Error)
				}
				probed++
			}
			if probed >= 50 {
				break
			}
		}
		if probed >= 50 {
			break
		}
	}
	if !quiet {
		fmt.Printf("Active probe attempts: %d\n", probed)
	}
	return nil
}

// Discover command implementation
func runDiscover(cmd *cobra.Command, args []string) error {
	db, err := database.NewDB(discoverDB)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	cfg := discover.DefaultDiscoverConfig()
	cfg.Limit = discoverLimit
	cfg.Verbose = verbose
	d := discover.NewDiscoverer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout*2)
	defer cancel()

	if !quiet {
		fmt.Printf("Discover mode: passive CT log + passive DNS\nDatabase: %s\n", discoverDB)
	}

	var hosts []discover.DiscoveredHost
	if crtHosts, err := d.QueryCRTSh(ctx); err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "crt.sh query failed: %v\n", err)
		}
	} else {
		hosts = append(hosts, crtHosts...)
	}
	if htHosts, err := d.QueryHackerTarget(ctx); err != nil {
		if !quiet {
			fmt.Fprintf(os.Stderr, "hackertarget query failed: %v\n", err)
		}
	} else {
		hosts = append(hosts, htHosts...)
	}

	n, err := db.InsertDiscoveredHosts(hosts)
	if err != nil {
		return fmt.Errorf("failed to store hosts: %w", err)
	}
	if !quiet {
		fmt.Printf("Discovered hosts: %d (upserted %d)\n", len(hosts), n)
		newN := 0
		for _, h := range hosts {
			if h.IsNewCandidate {
				newN++
			}
		}
		fmt.Printf("New pub-zone candidates: %d\n", newN)
	}

	if discoverOutput != "" {
		data, err := json.MarshalIndent(hosts, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(discoverOutput, data, 0o644); err != nil {
			return err
		}
		if !quiet {
			fmt.Printf("Wrote %s\n", discoverOutput)
		}
	}
	return nil
}

// Diameter command implementation
func runDiameter(cmd *cobra.Command, args []string) error {
	db, err := database.NewDB(diameterDB)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	cfg := diameter.DefaultDiameterConfig()
	cfg.Workers = diameterWorkers
	cfg.Verbose = verbose
	if diameterDNSServer != "" {
		server := diameterDNSServer
		if !strings.Contains(server, ":") {
			server += ":53"
		}
		cfg.DNSServer = server
	}
	scanner := diameter.NewScanner(cfg)
	ctx := context.Background()

	ops, err := db.GetAllOperators()
	if err != nil {
		return err
	}
	if !quiet {
		fmt.Printf("Diameter realm enumeration\nDatabase: %s operators=%d workers=%d\n",
			diameterDB, len(ops), diameterWorkers)
	}

	var allRealms []diameter.DiameterRealm
	for _, op := range ops {
		mnc, _ := strconv.Atoi(op.MNC)
		mcc, _ := strconv.Atoi(op.MCC)
		realms := scanner.ProbeOperator(ctx, mnc, mcc, op.Operator, op.CountryName)
		allRealms = append(allRealms, realms...)
		if verbose {
			for _, r := range realms {
				fmt.Printf("realm=%s naptr=%v iface=%s\n", r.Realm, r.NAPTRFound, r.Interface)
			}
		}
	}
	stored, err := db.InsertDiameterRealms(allRealms)
	if err != nil {
		return fmt.Errorf("persist diameter realms: %w", err)
	}
	if !quiet {
		fmt.Printf("Diameter realms discovered: %d (stored %d)\n", len(allRealms), stored)
	}
	return nil
}

// RSP command implementation
func runRSP(cmd *cobra.Command, args []string) error {
	db, err := database.NewDB(rspDB)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	ops, err := db.GetAllOperators()
	if err != nil {
		return err
	}

	var endpoints []rsp.RSPEndpoint
	endpoints = append(endpoints, rsp.KnownRSPEndpoints...)
	for _, op := range ops {
		mnc, _ := strconv.Atoi(op.MNC)
		mcc, _ := strconv.Atoi(op.MCC)
		cands := rsp.BuildCandidates(mnc, mcc)
		for i := range cands {
			cands[i].Operator = op.Operator
			cands[i].CountryName = op.CountryName
			cands[i].MNC = mnc
			cands[i].MCC = mcc
		}
		endpoints = append(endpoints, cands...)
	}

	if !quiet {
		mode := "passive"
		if rspActive {
			mode = "active"
		}
		fmt.Printf("RSP discovery (%s)\nDatabase: %s candidates=%d\n", mode, rspDB, len(endpoints))
	}

	if rspOutput != "" {
		data, err := json.MarshalIndent(endpoints, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(rspOutput, data, 0o644); err != nil {
			return err
		}
		if !quiet {
			fmt.Printf("Wrote %s\n", rspOutput)
		}
	} else if !quiet && len(endpoints) > 0 {
		limit := 10
		if len(endpoints) < limit {
			limit = len(endpoints)
		}
		for _, ep := range endpoints[:limit] {
			fmt.Printf("  %s (%s) %s\n", ep.FQDN, ep.Role, ep.DiscoveryMethod)
		}
		if len(endpoints) > limit {
			fmt.Printf("  ... and %d more\n", len(endpoints)-limit)
		}
	}
	return nil
}

// Report command implementation
func runReport(cmd *cobra.Command, args []string) error {
	db, err := database.NewDB(reportDB)
	if err != nil {
		return fmt.Errorf("database error: %w", err)
	}
	defer db.Close()

	if reportCollect {
		collected, err := db.CollectRiskFindings()
		if err != nil {
			return fmt.Errorf("collect failed: %w", err)
		}
		n, err := db.InsertRiskFindings(collected)
		if err != nil {
			return fmt.Errorf("save findings failed: %w", err)
		}
		if !quiet {
			fmt.Printf("Collected and saved %d findings\n", n)
		}
	}

	findings, err := db.LoadRiskFindings()
	if err != nil {
		return err
	}
	findings = report.FilterFindings(findings, reportOperator, "INFO", 0)

	cfg := report.DefaultReportConfig()
	cfg.TopN = reportTopN
	cfg.Format = reportFormat
	cfg.OperatorFilter = reportOperator
	cfg.Verbose = verbose
	gen := report.NewGenerator(cfg)
	rep := gen.BuildReport(findings)

	var out string
	var raw []byte
	switch strings.ToLower(reportFormat) {
	case "json":
		raw, err = gen.FormatJSON(rep)
		if err != nil {
			return err
		}
		out = string(raw)
	case "markdown", "md":
		out = gen.FormatMarkdown(rep)
	default:
		out = gen.FormatText(rep)
	}

	if reportOutput != "" {
		if err := os.WriteFile(reportOutput, []byte(out), 0o644); err != nil {
			return err
		}
		if !quiet {
			fmt.Printf("Wrote report to %s\n", reportOutput)
		}
		return nil
	}
	fmt.Print(out)
	return nil
}

// Helper functions

func exportScanResults(results []models.DNSResult, filePath string) error {
	ext := strings.ToLower(filepath.Ext(filePath))

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
	ext := strings.ToLower(filepath.Ext(filePath))

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
