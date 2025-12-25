package database

const (
	// Schema SQL for creating tables (compatible with Python version)
	schemaSQL = `
CREATE TABLE IF NOT EXISTS operators (
    mnc INTEGER,
    mcc INTEGER,
    operator TEXT
);

CREATE TABLE IF NOT EXISTS available_fqdns (
    operator TEXT,
    fqdn TEXT
);

CREATE INDEX IF NOT EXISTS idx_operators_mnc_mcc ON operators(mnc, mcc);
CREATE INDEX IF NOT EXISTS idx_fqdns_operator ON available_fqdns(operator);
`
)
