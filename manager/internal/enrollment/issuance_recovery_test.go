package enrollment

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Exercises expired-lease takeover and fencing of an obsolete signer.
// The blocked signer is released only after the successor commits.
func TestPostgresExpiredLeaseFencesStaleSigner(t *testing.T) {
	dsn := os.Getenv("ALPHA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(6)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	tenant, project, agent, claim := randomUUID(t), randomUUID(t), randomUUID(t), randomUUID(t)
	if _, err = db.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'fence-test')", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'fence-test')", project, tenant); err != nil {
		t.Fatal(err)
	}
	issuer, csr := testIssuer(t)
	store := SQLStore{DB: db}
	token, err := store.IssueToken(ctx, randomUUID(t), project, "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Claim(ctx, token, project, agent, claim, csr); err != nil {
		t.Fatal(err)
	}
	blocker := &blockingSigner{Signer: issuer.Signer, entered: make(chan struct{}), release: make(chan struct{})}
	stalledIssuer := issuer
	stalledIssuer.Signer = blocker
	stale := make(chan error, 1)
	go func() {
		_, issueErr := store.IssueClaim(ctx, claim, project, randomUUID(t), "CA-test", csr, stalledIssuer)
		stale <- issueErr
	}()
	select {
	case <-blocker.entered:
	case <-time.After(3 * time.Second):
		close(blocker.release)
		t.Fatal("first signer was not reached")
	}
	// Simulate a lease that expired while a remote CA was still signing.
	_, err = db.ExecContext(ctx, "UPDATE enrollment_claims SET lease_expires_at=now()-interval '1 second' WHERE id=$1 AND state='issuing'", claim)
	if err != nil {
		close(blocker.release)
		t.Fatal(err)
	}
	replacement, err := store.IssueClaim(ctx, claim, project, randomUUID(t), "CA-test", csr, issuer)
	close(blocker.release)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case issueErr := <-stale:
		if !errors.Is(issueErr, ErrLeaseLost) {
			t.Fatalf("obsolete signer returned %v, want ErrLeaseLost", issueErr)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("obsolete signer did not terminate")
	}
	if _, err = x509.ParseCertificate(replacement.CertificateDER); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM agent_certificates WHERE agent_id=$1", agent).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("durable certificates = %d, want exactly one", count)
	}
}

func TestPostgresSigningFailureReleasesLease(t *testing.T) {
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
	if _, err = db.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'failure-test')", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'failure-test')", project, tenant); err != nil {
		t.Fatal(err)
	}
	issuer, csr := testIssuer(t)
	store := SQLStore{DB: db}
	token, err := store.IssueToken(ctx, randomUUID(t), project, "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Claim(ctx, token, project, agent, claim, csr); err != nil {
		t.Fatal(err)
	}
	invalidIssuer := issuer
	invalidIssuer.Signer = nil
	if _, err = store.IssueClaim(ctx, claim, project, randomUUID(t), "CA-test", csr, invalidIssuer); err == nil {
		t.Fatal("signing failure unexpectedly succeeded")
	}
	var state string
	var owner sql.NullString
	if err = db.QueryRowContext(ctx, "SELECT state,lease_owner FROM enrollment_claims WHERE id=$1", claim).Scan(&state, &owner); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || owner.Valid {
		t.Fatalf("lease not released on signing failure: state=%s owner=%v", state, owner)
	}
	if _, err = store.IssueClaim(ctx, claim, project, randomUUID(t), "CA-test", csr, issuer); err != nil {
		t.Fatalf("retry after signer recovery failed: %v", err)
	}
}
