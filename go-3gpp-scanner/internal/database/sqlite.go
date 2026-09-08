package database

import (
	"database/sql"
	"fmt"
	"strings"

	"3gpp-scanner/internal/models"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQLite database connection
type DB struct {
	conn *sql.DB
	path string
}

// NewDB creates a new database connection
func NewDB(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &DB{
		conn: conn,
		path: dbPath,
	}

	// Initialize schema
	if err := db.InitSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return db, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// InitSchema creates the database tables if they don't exist
func (db *DB) InitSchema() error {
	_, err := db.conn.Exec(schemaSQL)
	if err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}

	// Best-effort migrations for databases created with older schema versions.
	migrations := []string{
		"ALTER TABLE operators ADD COLUMN country_name TEXT",
		"ALTER TABLE operators ADD COLUMN country_code TEXT",
		"ALTER TABLE operators ADD COLUMN last_scanned TIMESTAMP",
		"ALTER TABLE available_fqdns ADD COLUMN mnc INTEGER",
		"ALTER TABLE available_fqdns ADD COLUMN mcc INTEGER",
		"ALTER TABLE available_fqdns ADD COLUMN country_name TEXT",
		"ALTER TABLE available_fqdns ADD COLUMN record_type TEXT NOT NULL DEFAULT 'A'",
		"ALTER TABLE available_fqdns ADD COLUMN service TEXT",
		"ALTER TABLE available_fqdns ADD COLUMN dns_status TEXT",
		"ALTER TABLE available_fqdns ADD COLUMN last_query_status TEXT",
		"ALTER TABLE available_fqdns ADD COLUMN ip_class TEXT",
		"ALTER TABLE available_fqdns ADD COLUMN resolved_ips TEXT",
		"ALTER TABLE available_fqdns ADD COLUMN first_seen TIMESTAMP",
		"ALTER TABLE available_fqdns ADD COLUMN last_seen TIMESTAMP",
		"ALTER TABLE available_fqdns ADD COLUMN last_checked TIMESTAMP",
		"ALTER TABLE fiveg_fqdns ADD COLUMN dns_source TEXT NOT NULL DEFAULT 'public'",
		"CREATE INDEX IF NOT EXISTS idx_fqdns_mnc_mcc ON available_fqdns(mnc, mcc)",
	}

	for _, stmt := range migrations {
		if _, err := db.conn.Exec(stmt); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "duplicate column name") {
				continue
			}
			if strings.Contains(msg, "already exists") {
				continue
			}
			return fmt.Errorf("failed to run migration %q: %w", stmt, err)
		}
	}
	return nil
}

// InsertResults inserts DNS scan results into the database
func (db *DB) InsertResults(results []models.DNSResult) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	operatorStmt, err := tx.Prepare(`
		INSERT INTO operators (mnc, mcc, operator, country_name, last_scanned)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT DO UPDATE SET
			operator = excluded.operator, country_name = excluded.country_name,
			last_scanned = excluded.last_scanned`)
	if err != nil {
		return fmt.Errorf("failed to prepare operator statement: %w", err)
	}
	defer operatorStmt.Close()

	fqdnStmt, err := tx.Prepare(`
		INSERT INTO available_fqdns
			(mnc, mcc, operator, country_name, fqdn, record_type, service, dns_status, ip_class, resolved_ips, first_seen, last_seen, last_checked)
		VALUES (?, ?, ?, ?, ?, 'A', ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT DO UPDATE SET
			operator = excluded.operator, country_name = excluded.country_name,
			service = excluded.service, dns_status = excluded.dns_status,
			ip_class = excluded.ip_class, resolved_ips = excluded.resolved_ips,
			last_seen = excluded.last_seen, last_checked = excluded.last_checked`)
	if err != nil {
		return fmt.Errorf("failed to prepare fqdn statement: %w", err)
	}
	defer fqdnStmt.Close()

	for _, result := range results {
		// Insert operator
		_, err = operatorStmt.Exec(result.MNC, result.MCC, result.Operator, result.Country)
		if err != nil {
			return fmt.Errorf("failed to insert operator: %w", err)
		}

		// Insert FQDN
		_, err = fqdnStmt.Exec(
			result.MNC, result.MCC, result.Operator, result.Country, result.FQDN,
			result.Subdomain, result.DNSStatus, result.IPClass, strings.Join(result.IPs, ","),
		)
		if err != nil {
			return fmt.Errorf("failed to insert fqdn: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// QueryByMNCMCC queries FQDNs for a specific MNC and MCC
func (db *DB) QueryByMNCMCC(mnc, mcc int) ([]string, error) {
	query := `
		SELECT fqdn
		FROM available_fqdns
		WHERE mnc = ? AND mcc = ?
	`

	rows, err := db.conn.Query(query, mnc, mcc)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var fqdns []string
	for rows.Next() {
		var fqdn string
		if err := rows.Scan(&fqdn); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		fqdns = append(fqdns, fqdn)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return fqdns, nil
}

// QueryByOperator queries FQDNs for a specific operator name
func (db *DB) QueryByOperator(operator string) ([]string, error) {
	query := "SELECT fqdn FROM available_fqdns WHERE operator LIKE ?"

	rows, err := db.conn.Query(query, "%"+operator+"%")
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var fqdns []string
	for rows.Next() {
		var fqdn string
		if err := rows.Scan(&fqdn); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		fqdns = append(fqdns, fqdn)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return fqdns, nil
}

// GetAllOperators retrieves all unique operators from the database
func (db *DB) GetAllOperators() ([]models.MCCMNCEntry, error) {
	query := "SELECT DISTINCT mnc, mcc, operator FROM operators ORDER BY mcc, mnc"

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var operators []models.MCCMNCEntry
	for rows.Next() {
		var mnc, mcc int
		var operator string
		if err := rows.Scan(&mnc, &mcc, &operator); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		operators = append(operators, models.MCCMNCEntry{
			MNC:      fmt.Sprintf("%03d", mnc),
			MCC:      fmt.Sprintf("%03d", mcc),
			Operator: operator,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return operators, nil
}

// GetStats retrieves statistics from the database
func (db *DB) GetStats() (*models.Stats, error) {
	stats := &models.Stats{
		MCCDistribution: make(map[string]int),
		SubdomainCounts: make(map[string]int),
		CountryCounts:   make(map[string]int),
	}

	// Count total FQDNs
	var totalFQDNs int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM available_fqdns").Scan(&totalFQDNs)
	if err != nil {
		return nil, fmt.Errorf("failed to count FQDNs: %w", err)
	}
	stats.TotalFQDNs = totalFQDNs

	// Count unique operators
	var uniqueOperators int
	err = db.conn.QueryRow("SELECT COUNT(DISTINCT operator) FROM operators").Scan(&uniqueOperators)
	if err != nil {
		return nil, fmt.Errorf("failed to count operators: %w", err)
	}
	stats.UniqueOperators = uniqueOperators

	// Get MCC distribution
	rows, err := db.conn.Query("SELECT mcc, COUNT(*) FROM operators GROUP BY mcc")
	if err != nil {
		return nil, fmt.Errorf("failed to query MCC distribution: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var mcc, count int
		if err := rows.Scan(&mcc, &count); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		stats.MCCDistribution[fmt.Sprintf("%d", mcc)] = count
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	// Get country domain distribution
	countryDist, err := db.GetCountryDomainDistribution()
	if err != nil {
		return nil, fmt.Errorf("failed to get country domain distribution: %w", err)
	}
	for country, count := range countryDist {
		stats.CountryCounts[country] = count
	}

	return stats, nil
}

// GetCountryDomainDistribution returns domain counts per country.
func (db *DB) GetCountryDomainDistribution() (map[string]int, error) {
	query := `
		SELECT COALESCE(o.country_name, 'Unknown') AS country, COUNT(*) AS domains
		FROM available_fqdns f
		JOIN operators o ON o.mnc = f.mnc AND o.mcc = f.mcc AND o.operator = f.operator
		GROUP BY country
		ORDER BY domains DESC, country ASC
	`

	rows, err := db.conn.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	distribution := make(map[string]int)
	for rows.Next() {
		var country string
		var domains int
		if err := rows.Scan(&country, &domains); err != nil {
			return nil, fmt.Errorf("scan failed: %w", err)
		}
		distribution[country] = domains
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration failed: %w", err)
	}

	return distribution, nil
}
