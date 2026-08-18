package database

import (
	"path/filepath"
	"testing"

	"3gpp-scanner/internal/discover"
	"3gpp-scanner/internal/report"
)

func TestSchemaAndCollect(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "t.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	// Seed available_fqdns / operators via InsertResults path is limited;
	// write directly for collector coverage.
	if _, err := db.conn.Exec(`INSERT INTO operators(mnc,mcc,operator) VALUES (1,310,'TestOp')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.Exec(`INSERT INTO available_fqdns(operator,fqdn) VALUES ('TestOp','bsf.mnc001.mcc310.pub.3gppnetwork.org')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.Exec(`
		INSERT INTO tls_certs(fqdn,ip,port,operator,is_expired,is_self_signed,is_weak_sig,subject)
		VALUES ('x.example','1.2.3.4',443,'TestOp',1,0,0,'CN=x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.conn.Exec(`
		INSERT INTO diameter_realms(mnc,mcc,operator,realm,naptr_found,naptr_services)
		VALUES (1,310,'TestOp','epc.mnc001.mcc310.3gppnetwork.org',1,'aaa+ap23')`); err != nil {
		t.Fatal(err)
	}

	hosts := []discover.DiscoveredHost{{
		Source: "crtsh", FQDN: "foo.mnc001.mcc310.pub.3gppnetwork.org",
		ServicePrefix: "foo", Zone: "pub", MNC: 1, MCC: 310, IsNewCandidate: true,
	}}
	if _, err := db.InsertDiscoveredHosts(hosts); err != nil {
		t.Fatalf("InsertDiscoveredHosts: %v", err)
	}

	findings, err := db.CollectRiskFindings()
	if err != nil {
		t.Fatalf("CollectRiskFindings: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected some findings")
	}

	// Must include expired cert + diameter + missing epdg/ims + ct candidate
	types := map[string]bool{}
	for _, f := range findings {
		types[f.FindingType] = true
	}
	for _, want := range []string{"expired_cert", "diameter_public", "missing_epdg", "ct_new_prefix"} {
		if !types[want] {
			t.Errorf("missing finding type %s in %#v", want, types)
		}
	}

	n, err := db.InsertRiskFindings(findings)
	if err != nil {
		t.Fatalf("InsertRiskFindings: %v", err)
	}
	if n == 0 {
		t.Fatal("expected upserts")
	}
	loaded, err := db.LoadRiskFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) == 0 {
		t.Fatal("expected loaded findings")
	}

	// Control map covers collected types
	for _, f := range findings {
		if _, ok := report.ControlMap[f.FindingType]; !ok && f.FindingType != "" {
			// Collect may emit only mapped types; tolerate unknown only if Severity set
			if f.ControlRef == "" {
				t.Errorf("unmapped type %s", f.FindingType)
			}
		}
	}
}
