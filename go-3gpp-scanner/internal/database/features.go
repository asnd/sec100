package database

import (
	"fmt"
	"strings"

	"3gpp-scanner/internal/discover"
	"3gpp-scanner/internal/report"
)

// InsertDiscoveredHosts upserts passive discovery hosts into discovered_hosts.
func (db *DB) InsertDiscoveredHosts(hosts []discover.DiscoveredHost) (int, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO discovered_hosts
			(source, fqdn, service_prefix, zone, in_predefined, is_new_candidate,
			 mnc, mcc, operator, country_name, cert_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source, fqdn) DO UPDATE SET
			service_prefix=excluded.service_prefix,
			zone=excluded.zone,
			in_predefined=excluded.in_predefined,
			is_new_candidate=excluded.is_new_candidate,
			mnc=excluded.mnc,
			mcc=excluded.mcc,
			cert_id=excluded.cert_id
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for _, h := range hosts {
		inPred, isNew := 0, 0
		if h.InPredefined {
			inPred = 1
		}
		if h.IsNewCandidate {
			isNew = 1
		}
		if _, err := stmt.Exec(
			h.Source, h.FQDN, h.ServicePrefix, h.Zone, inPred, isNew,
			h.MNC, h.MCC, "", "", h.CertID,
		); err != nil {
			return n, err
		}
		n++
	}
	return n, tx.Commit()
}

// InsertRiskFindings upserts baseline findings.
func (db *DB) InsertRiskFindings(findings []report.RiskFinding) (int, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO risk_findings
			(operator, country_name, mcc, mnc, control_ref, finding_type, severity, title, evidence)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(operator, finding_type, control_ref, evidence) DO UPDATE SET
			country_name=excluded.country_name,
			mcc=excluded.mcc,
			mnc=excluded.mnc,
			severity=excluded.severity,
			title=excluded.title,
			detected_at=CURRENT_TIMESTAMP
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	n := 0
	for _, f := range findings {
		if _, err := stmt.Exec(
			f.Operator, f.CountryName, f.MCC, f.MNC,
			f.ControlRef, f.FindingType, f.Severity, f.Title, f.Evidence,
		); err != nil {
			return n, err
		}
		n++
	}
	return n, tx.Commit()
}

// LoadRiskFindings returns all risk findings from the database.
func (db *DB) LoadRiskFindings() ([]report.RiskFinding, error) {
	rows, err := db.conn.Query(`
		SELECT operator, COALESCE(country_name,''), COALESCE(mcc,0), COALESCE(mnc,0),
		       COALESCE(control_ref,''), COALESCE(finding_type,''), COALESCE(severity,''),
		       COALESCE(title,''), COALESCE(evidence,''), COALESCE(detected_at,'')
		FROM risk_findings
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []report.RiskFinding
	for rows.Next() {
		var f report.RiskFinding
		if err := rows.Scan(
			&f.Operator, &f.CountryName, &f.MCC, &f.MNC,
			&f.ControlRef, &f.FindingType, &f.Severity, &f.Title, &f.Evidence, &f.DetectedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CollectRiskFindings synthesises risk findings from available feature tables.
// Missing tables are skipped gracefully.
func (db *DB) CollectRiskFindings() ([]report.RiskFinding, error) {
	var findings []report.RiskFinding

	add := func(operator, country string, mcc, mnc int, ftype, evidence string) {
		meta, ok := report.ControlMap[ftype]
		if !ok {
			meta = [3]string{"Unknown", "INFO", ftype}
		}
		findings = append(findings, report.RiskFinding{
			Operator:    operator,
			CountryName: country,
			MCC:         mcc,
			MNC:         mnc,
			ControlRef:  meta[0],
			FindingType: ftype,
			Severity:    meta[1],
			Title:       meta[2],
			Evidence:    evidence,
		})
	}

	// TLS cert findings
	if rows, err := db.conn.Query(`
		SELECT COALESCE(operator,''), COALESCE(country_name,''), COALESCE(mcc,0), COALESCE(mnc,0),
		       fqdn, is_expired, is_self_signed, is_weak_sig, COALESCE(subject,''), COALESCE(sig_algorithm,'')
		FROM tls_certs
		WHERE is_expired=1 OR is_self_signed=1 OR is_weak_sig=1
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var op, country, fqdn, subject, sig string
			var mcc, mnc, exp, self, weak int
			if err := rows.Scan(&op, &country, &mcc, &mnc, &fqdn, &exp, &self, &weak, &subject, &sig); err != nil {
				return findings, err
			}
			if exp == 1 {
				add(op, country, mcc, mnc, "expired_cert", fmt.Sprintf("fqdn=%s subject=%s", fqdn, subject))
			}
			if self == 1 {
				add(op, country, mcc, mnc, "self_signed_cert", fmt.Sprintf("fqdn=%s subject=%s", fqdn, subject))
			}
			if weak == 1 {
				add(op, country, mcc, mnc, "weak_sig_cert", fmt.Sprintf("fqdn=%s sig=%s", fqdn, sig))
			}
		}
	}

	// IKE weak crypto
	if rows, err := db.conn.Query(`
		SELECT COALESCE(operator,''), COALESCE(country_name,''), COALESCE(mcc,0), COALESCE(mnc,0),
		       fqdn, COALESCE(vendor_ids,''), COALESCE(weak_reasons,'')
		FROM ike_probes WHERE weak_crypto=1
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var op, country, fqdn, vids, reasons string
			var mcc, mnc int
			if err := rows.Scan(&op, &country, &mcc, &mnc, &fqdn, &vids, &reasons); err != nil {
				return findings, err
			}
			add(op, country, mcc, mnc, "weak_ike_crypto",
				fmt.Sprintf("fqdn=%s vendor_ids=%s reasons=%s", fqdn, vids, reasons))
		}
	}

	// Diameter public realms
	if rows, err := db.conn.Query(`
		SELECT COALESCE(operator,''), COALESCE(country_name,''), COALESCE(mcc,0), COALESCE(mnc,0),
		       realm, COALESCE(naptr_services,'')
		FROM diameter_realms WHERE naptr_found=1
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var op, country, realm, services string
			var mcc, mnc int
			if err := rows.Scan(&op, &country, &mcc, &mnc, &realm, &services); err != nil {
				return findings, err
			}
			add(op, country, mcc, mnc, "diameter_public",
				fmt.Sprintf("realm=%s naptr_services=%s", realm, services))
		}
	}

	// RSP endpoints
	if rows, err := db.conn.Query(`
		SELECT COALESCE(operator,''), COALESCE(country_name,''), COALESCE(mcc,0), COALESCE(mnc,0),
		       fqdn, COALESCE(role,''), COALESCE(resolved_ips,'')
		FROM rsp_endpoints
	`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var op, country, fqdn, role, ips string
			var mcc, mnc int
			if err := rows.Scan(&op, &country, &mcc, &mnc, &fqdn, &role, &ips); err != nil {
				return findings, err
			}
			ftype := "rsp_smds_exposed"
			ru := strings.ToUpper(role)
			if strings.Contains(ru, "SM-DP") || strings.Contains(ru, "SMDP") {
				ftype = "rsp_smdp_exposed"
			}
			add(op, country, mcc, mnc, ftype,
				fmt.Sprintf("endpoint=%s role=%s ip=%s", fqdn, role, ips))
		}
	}

	// CT / passive new candidates
	if rows, err := db.conn.Query(`
		SELECT COALESCE(operator,''), COALESCE(country_name,''), COALESCE(mcc,0), COALESCE(mnc,0),
		       fqdn, COALESCE(service_prefix,'')
		FROM discovered_hosts WHERE is_new_candidate=1
	`); err == nil {
		defer rows.Close()
		seen := map[string]struct{}{}
		for rows.Next() {
			var op, country, fqdn, prefix string
			var mcc, mnc int
			if err := rows.Scan(&op, &country, &mcc, &mnc, &fqdn, &prefix); err != nil {
				return findings, err
			}
			key := op + "|" + prefix
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			add(op, country, mcc, mnc, "ct_new_prefix",
				fmt.Sprintf("service_prefix=%s example_hostname=%s", prefix, fqdn))
		}
	}

	// Missing service findings from available_fqdns
	if rows, err := db.conn.Query(`
		SELECT COALESCE(operator,''), fqdn FROM available_fqdns
		WHERE fqdn IS NOT NULL AND fqdn != ''
	`); err == nil {
		defer rows.Close()
		type flags struct{ epdg, ims, sos, bsf bool }
		presence := map[string]*flags{}
		for rows.Next() {
			var op, fqdn string
			if err := rows.Scan(&op, &fqdn); err != nil {
				return findings, err
			}
			if op == "" {
				continue
			}
			f := presence[op]
			if f == nil {
				f = &flags{}
				presence[op] = f
			}
			fl := strings.ToLower(fqdn)
			if strings.Contains(fl, "epdg.epc.") {
				f.epdg = true
			}
			if strings.HasPrefix(fl, "ims.") || strings.Contains(fl, ".ims.") || strings.Contains(fl, "ims.mnc") {
				f.ims = true
			}
			if strings.Contains(fl, "sos.") {
				f.sos = true
			}
			if strings.Contains(fl, "bsf.") {
				f.bsf = true
			}
		}
		for op, f := range presence {
			if !f.epdg {
				add(op, "", 0, 0, "missing_epdg", "operator="+op+" has no epdg.epc.* FQDN")
			}
			if !f.ims {
				add(op, "", 0, 0, "missing_ims", "operator="+op+" has no ims.* FQDN")
			}
		}
	}

	return findings, nil
}
