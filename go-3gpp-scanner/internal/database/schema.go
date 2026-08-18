package database

const (
	// schemaSQL creates tables compatible with the Python toolkit schemas.
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

CREATE TABLE IF NOT EXISTS tls_certs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn           TEXT    NOT NULL,
    ip             TEXT    NOT NULL,
    port           INTEGER NOT NULL,
    operator       TEXT,
    country_name   TEXT,
    mnc            INTEGER,
    mcc            INTEGER,
    subject        TEXT,
    issuer         TEXT,
    san            TEXT,
    not_before     INTEGER,
    not_after      INTEGER,
    key_type       TEXT,
    key_bits       INTEGER,
    sig_algorithm  TEXT,
    vendor         TEXT,
    is_expired     INTEGER DEFAULT 0,
    is_self_signed INTEGER DEFAULT 0,
    is_weak_sig    INTEGER DEFAULT 0,
    first_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn, ip, port)
);

CREATE TABLE IF NOT EXISTS ike_probes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn           TEXT    NOT NULL,
    ip             TEXT    NOT NULL,
    port           INTEGER NOT NULL,
    operator       TEXT,
    country_name   TEXT,
    mnc            INTEGER,
    mcc            INTEGER,
    responded      INTEGER DEFAULT 0,
    vendor_ids     TEXT,
    weak_crypto    INTEGER DEFAULT 0,
    weak_reasons   TEXT,
    first_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn, ip, port)
);

CREATE INDEX IF NOT EXISTS idx_tls_fqdn   ON tls_certs(fqdn);
CREATE INDEX IF NOT EXISTS idx_tls_vendor ON tls_certs(vendor);
CREATE INDEX IF NOT EXISTS idx_ike_fqdn   ON ike_probes(fqdn);

CREATE TABLE IF NOT EXISTS discovered_hosts (
    id                INTEGER  PRIMARY KEY AUTOINCREMENT,
    source            TEXT     NOT NULL,
    fqdn              TEXT     NOT NULL,
    service_prefix    TEXT,
    zone              TEXT,
    in_predefined     INTEGER  DEFAULT 0,
    is_new_candidate  INTEGER  DEFAULT 0,
    mnc               INTEGER,
    mcc               INTEGER,
    operator          TEXT,
    country_name      TEXT,
    cert_id           TEXT,
    first_seen        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source, fqdn)
);
CREATE INDEX IF NOT EXISTS idx_ph_source    ON discovered_hosts(source);
CREATE INDEX IF NOT EXISTS idx_ph_zone      ON discovered_hosts(zone);
CREATE INDEX IF NOT EXISTS idx_ph_prefix    ON discovered_hosts(service_prefix);
CREATE INDEX IF NOT EXISTS idx_ph_candidate ON discovered_hosts(is_new_candidate);

CREATE TABLE IF NOT EXISTS diameter_realms (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    mnc             INTEGER NOT NULL,
    mcc             INTEGER NOT NULL,
    operator        TEXT,
    country_name    TEXT,
    realm           TEXT    NOT NULL,
    naptr_found     INTEGER NOT NULL DEFAULT 0,
    naptr_services  TEXT,
    srv_hosts       TEXT,
    interface       TEXT,
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(realm)
);

CREATE TABLE IF NOT EXISTS diameter_peers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    realm           TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    transport       TEXT    NOT NULL,
    resolved_ips    TEXT,
    operator        TEXT,
    country_name    TEXT,
    mnc             INTEGER,
    mcc             INTEGER,
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(host, port)
);

CREATE INDEX IF NOT EXISTS idx_diameter_realm_country  ON diameter_realms(country_name);
CREATE INDEX IF NOT EXISTS idx_diameter_realm_iface    ON diameter_realms(interface);
CREATE INDEX IF NOT EXISTS idx_diameter_realm_mcc      ON diameter_realms(mcc);
CREATE INDEX IF NOT EXISTS idx_diameter_peers_realm    ON diameter_peers(realm);

CREATE TABLE IF NOT EXISTS rsp_endpoints (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    operator         TEXT,
    country_name     TEXT,
    mnc              INTEGER,
    mcc              INTEGER,
    fqdn             TEXT    NOT NULL,
    role             TEXT,
    resolved_ips     TEXT,
    https_reachable  INTEGER DEFAULT 0,
    http_status      INTEGER,
    vendor           TEXT,
    tls_subject      TEXT,
    tls_issuer       TEXT,
    tls_san          TEXT,
    sgp22_version    TEXT,
    discovery_method TEXT,
    first_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(fqdn)
);
CREATE INDEX IF NOT EXISTS idx_rsp_country  ON rsp_endpoints(country_name);
CREATE INDEX IF NOT EXISTS idx_rsp_role     ON rsp_endpoints(role);
CREATE INDEX IF NOT EXISTS idx_rsp_vendor   ON rsp_endpoints(vendor);
CREATE INDEX IF NOT EXISTS idx_rsp_operator ON rsp_endpoints(operator);

CREATE TABLE IF NOT EXISTS risk_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    operator     TEXT NOT NULL,
    country_name TEXT,
    mcc          INTEGER,
    mnc          INTEGER,
    control_ref  TEXT,
    finding_type TEXT,
    severity     TEXT,
    title        TEXT,
    evidence     TEXT,
    detected_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(operator, finding_type, control_ref, evidence)
);
`
)
