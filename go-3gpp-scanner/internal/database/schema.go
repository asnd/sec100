package database

const (
	// Schema SQL for creating tables (compatible with Python version)
	schemaSQL = `
CREATE TABLE IF NOT EXISTS operators (
    mnc INTEGER,
    mcc INTEGER,
    operator TEXT,
    country_name TEXT,
    UNIQUE(mnc, mcc, operator)
);

CREATE TABLE IF NOT EXISTS available_fqdns (
    mnc INTEGER,
    mcc INTEGER,
    operator TEXT,
    fqdn TEXT,
    UNIQUE(mnc, mcc, operator, fqdn)
);

CREATE INDEX IF NOT EXISTS idx_operators_mnc_mcc ON operators(mnc, mcc);
CREATE INDEX IF NOT EXISTS idx_fqdns_operator ON available_fqdns(operator);
`
)
