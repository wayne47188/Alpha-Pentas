package operator

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPostgresOperatorCertificateIdentity(t *testing.T) {
	dsn := os.Getenv("ALPHA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	tenant := "98111111-1111-4111-8111-111111111111"
	if _, err = db.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'operator-identity') ON CONFLICT(id) DO NOTHING", tenant); err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{Raw: []byte("verified-client-certificate-fixture")}
	fingerprint := sha256.Sum256(cert.Raw)
	if _, err = db.ExecContext(ctx, `INSERT INTO operator_identities(certificate_sha256,operator_id,tenant_id)
 VALUES($1,'fixture-operator',$2)`, fingerprint[:], tenant); err != nil {
		t.Fatal(err)
	}

	resolver := PostgresPrincipalResolver{DB: db}
	principal, err := resolver.ResolveOperator(ctx, cert)
	if err != nil {
		t.Fatal(err)
	}
	if !principal.Authenticated || principal.ID != "fixture-operator" || principal.TenantID != tenant {
		t.Fatalf("unexpected principal: %+v", principal)
	}

	unknown := &x509.Certificate{Raw: []byte("unregistered-client-certificate")}
	if _, err = resolver.ResolveOperator(ctx, unknown); !errors.Is(err, ErrOperatorIdentity) {
		t.Fatalf("unknown certificate returned %v", err)
	}

	if _, err = db.ExecContext(ctx, `UPDATE operator_identities
 SET state='revoked',revoked_at=now() WHERE certificate_sha256=$1`, fingerprint[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.ResolveOperator(ctx, cert); !errors.Is(err, ErrOperatorIdentity) {
		t.Fatalf("revoked certificate returned %v", err)
	}
}
