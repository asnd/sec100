package database

const (
	// Schema SQL for creating tables (compatible with Python version)
	schemaSQL = `
CREATE TABLE IF NOT EXISTS operators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc INTEGER,
    mcc INTEGER,
    operator TEXT,
    country_name TEXT,
    country_code TEXT,
    last_scanned TIMESTAMP,
    UNIQUE(mnc, mcc)
);

CREATE TABLE IF NOT EXISTS available_fqdns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc INTEGER,
    mcc INTEGER,
    operator TEXT,
    country_name TEXT,
    fqdn TEXT,
    record_type TEXT NOT NULL DEFAULT 'A',
    service TEXT,
    dns_status TEXT,
    last_query_status TEXT,
    ip_class TEXT,
    resolved_ips TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn, record_type)
);

CREATE INDEX IF NOT EXISTS idx_operators_mnc_mcc ON operators(mnc, mcc);
CREATE INDEX IF NOT EXISTS idx_fqdns_operator ON available_fqdns(operator);
CREATE INDEX IF NOT EXISTS idx_fqdns_mcc ON available_fqdns(mcc);
CREATE INDEX IF NOT EXISTS idx_fqdns_country ON available_fqdns(country_name);

CREATE TABLE IF NOT EXISTS fiveg_fqdns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc          INTEGER NOT NULL,
    mcc          INTEGER NOT NULL,
    operator     TEXT,
    country_name TEXT,
    nf_type      TEXT    NOT NULL,
    fqdn         TEXT    NOT NULL,
    record_type  TEXT    NOT NULL DEFAULT 'A',
    resolved_ips TEXT,
    dns_zone     TEXT,
    dns_source   TEXT NOT NULL DEFAULT 'public',
    dns_server   TEXT,
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMP,
    UNIQUE(fqdn, record_type)
);

CREATE TABLE IF NOT EXISTS naptr_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    base_fqdn    TEXT NOT NULL,
    order_val    INTEGER,
    preference   INTEGER,
    flags        TEXT,
    service      TEXT,
    regexp       TEXT,
    replacement  TEXT,
    operator     TEXT,
    country_name TEXT,
    mnc          INTEGER,
    mcc          INTEGER,
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS srv_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    query_name   TEXT NOT NULL,
    priority     INTEGER,
    weight       INTEGER,
    port         INTEGER,
    target       TEXT,
    operator     TEXT,
    country_name TEXT,
    mnc          INTEGER,
    mcc          INTEGER,
    source_fqdn  TEXT,
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS esim_servers (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc          INTEGER NOT NULL,
    mcc          INTEGER NOT NULL,
    operator     TEXT,
    fqdn         TEXT    NOT NULL,
    status       TEXT,
    tls_cert_org TEXT,
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn)
);
`
)
