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

CREATE TABLE IF NOT EXISTS fqdn_security_metadata (
    fqdn TEXT PRIMARY KEY,
    parent_domain TEXT,
    domain_profile TEXT,
    service_class TEXT,
    standards TEXT,
    security_focus TEXT,
    last_classification TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_operators_mnc_mcc ON operators(mnc, mcc);
CREATE INDEX IF NOT EXISTS idx_fqdns_operator ON available_fqdns(operator);
CREATE INDEX IF NOT EXISTS idx_fqdn_security_profile ON fqdn_security_metadata(domain_profile);
`
)
