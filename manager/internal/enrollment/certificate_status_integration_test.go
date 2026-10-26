package enrollment

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
	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

func TestPostgresCertificateRevocationEnforced(t *testing.T) {
	dsn := os.Getenv("ALPHA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tenant, project, agent, claim := randomUUID(t), randomUUID(t), randomUUID(t), randomUUID(t)
	if _, err = db.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'revocation-test')", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'revocation-test')", project, tenant); err != nil {
		t.Fatal(err)
	}
	store := SQLStore{DB: db}
	issuer, csr := testIssuer(t)
	token, err := store.IssueToken(ctx, randomUUID(t), project, "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Claim(ctx, token, project, agent, claim, csr); err != nil {
		t.Fatal(err)
	}
	result, err := store.IssueClaim(ctx, claim, project, randomUUID(t), "CA-test", token, csr, issuer)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer.CA)
	peer, err := identity.VerifyAgentPeer(ctx, result.CertificateDER, roots, project, time.Now(), store.CertificateStatus)
	if err != nil || peer != agent {
		t.Fatalf("issued cert rejected: peer=%q err=%v", peer, err)
	}
	digest := sha256.Sum256(result.CertificateDER)
	if _, err = db.ExecContext(ctx, "UPDATE agent_certificates SET revoked_at=now() WHERE sha256_fingerprint=$1", digest[:]); err != nil {
		t.Fatal(err)
	}
	if _, err = identity.VerifyAgentPeer(ctx, result.CertificateDER, roots, project, time.Now(), store.CertificateStatus); !errors.Is(err, identity.ErrPeerIdentity) {
		t.Fatalf("revoked certificate accepted: %v", err)
	}
}
