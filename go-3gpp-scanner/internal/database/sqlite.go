package database

import (
	"database/sql"
	"fmt"

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
	return nil
}

// InsertResults inserts DNS scan results into the database
func (db *DB) InsertResults(results []models.DNSResult) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Prepare statements
	operatorStmt, err := tx.Prepare("INSERT INTO operators (mnc, mcc, operator) VALUES (?, ?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare operator statement: %w", err)
	}
	defer operatorStmt.Close()

	fqdnStmt, err := tx.Prepare("INSERT INTO available_fqdns (operator, fqdn) VALUES (?, ?)")
	if err != nil {
		return fmt.Errorf("failed to prepare fqdn statement: %w", err)
	}
	defer fqdnStmt.Close()

	// Track inserted operators to avoid duplicates
	operatorSeen := make(map[string]bool)

	for _, result := range results {
		operatorKey := fmt.Sprintf("%d:%d:%s", result.MNC, result.MCC, result.Operator)

		// Insert operator if not seen before
		if !operatorSeen[operatorKey] {
			_, err = operatorStmt.Exec(result.MNC, result.MCC, result.Operator)
			if err != nil {
				return fmt.Errorf("failed to insert operator: %w", err)
			}
			operatorSeen[operatorKey] = true
		}

		// Insert FQDN
		_, err = fqdnStmt.Exec(result.Operator, result.FQDN)
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
		WHERE operator IN (
			SELECT operator
			FROM operators
			WHERE mnc = ? AND mcc = ?
		)
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
	query := "SELECT fqdn FROM available_fqdns WHERE operator = ?"

	rows, err := db.conn.Query(query, operator)
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
			MNC:      fmt.Sprintf("%d", mnc),
			MCC:      fmt.Sprintf("%d", mcc),
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

	return stats, nil
}
