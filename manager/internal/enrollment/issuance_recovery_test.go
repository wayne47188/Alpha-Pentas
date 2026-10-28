package enrollment

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	// Register lib/pq with database/sql for PostgreSQL integration tests.
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
	store := testSQLStore(t, db)
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
		_, issueErr := store.IssueClaim(ctx, IssueRequest{ClaimID: claim, ProjectID: project, CertificateID: randomUUID(t), IssuerKeyID: "CA-test", EnrollmentToken: token, CSRDER: csr}, stalledIssuer)
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
	replacement, err := store.IssueClaim(ctx, IssueRequest{ClaimID: claim, ProjectID: project, CertificateID: randomUUID(t), IssuerKeyID: "CA-test", EnrollmentToken: token, CSRDER: csr}, issuer)
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
	store := testSQLStore(t, db)
	token, err := store.IssueToken(ctx, randomUUID(t), project, "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Claim(ctx, token, project, agent, claim, csr); err != nil {
		t.Fatal(err)
	}
	invalidIssuer := issuer
	invalidIssuer.Signer = nil
	if _, err = store.IssueClaim(ctx, IssueRequest{ClaimID: claim, ProjectID: project, CertificateID: randomUUID(t), IssuerKeyID: "CA-test", EnrollmentToken: token, CSRDER: csr}, invalidIssuer); err == nil {
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
	if _, err = store.IssueClaim(ctx, IssueRequest{ClaimID: claim, ProjectID: project, CertificateID: randomUUID(t), IssuerKeyID: "CA-test", EnrollmentToken: token, CSRDER: csr}, issuer); err != nil {
		t.Fatalf("retry after signer recovery failed: %v", err)
	}
}


func TestPostgresConnectionLossDuringSigningRecoversAfterLease(t *testing.T) {
	dsn := os.Getenv("ALPHA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	workerDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	controlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer controlDB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tenant, project, agent, claim := randomUUID(t), randomUUID(t), randomUUID(t), randomUUID(t)
	if _, err = controlDB.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'db-loss-test')", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = controlDB.ExecContext(ctx, "INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'db-loss-test')", project, tenant); err != nil {
		t.Fatal(err)
	}

	issuer, csr := testIssuer(t)
	workerStore := testSQLStore(t, workerDB)
	token, err := workerStore.IssueToken(ctx, randomUUID(t), project, "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = workerStore.Claim(ctx, token, project, agent, claim, csr); err != nil {
		t.Fatal(err)
	}

	blocker := &blockingSigner{Signer: issuer.Signer, entered: make(chan struct{}), release: make(chan struct{})}
	stalledIssuer := issuer
	stalledIssuer.Signer = blocker
	result := make(chan error, 1)
	go func() {
		_, issueErr := workerStore.IssueClaim(ctx, IssueRequest{
			ClaimID: claim, ProjectID: project, CertificateID: randomUUID(t),
			IssuerKeyID: "CA-test", EnrollmentToken: token, CSRDER: csr,
		}, stalledIssuer)
		result <- issueErr
	}()
	select {
	case <-blocker.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("signer was not reached")
	}

	// Signing holds no DB transaction/row lock, so closing the Manager pool
	// must complete while the external signer remains blocked.
	closeStart := time.Now()
	if err = workerDB.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(closeStart) > time.Second {
		t.Fatal("closing DB pool waited on signing; a DB operation may still span the CA call")
	}
	close(blocker.release)
	select {
	case issueErr := <-result:
		if issueErr == nil {
			t.Fatal("issuance committed after its DB pool was closed")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("issuer did not return after DB loss")
	}

	var state string
	if err = controlDB.QueryRowContext(ctx, "SELECT state FROM enrollment_claims WHERE id=$1", claim).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "issuing" {
		t.Fatalf("claim state=%q, want recoverable issuing lease", state)
	}
	var count int
	if err = controlDB.QueryRowContext(ctx, "SELECT count(*) FROM agent_certificates WHERE agent_id=$1", agent).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("certificate committed through lost DB pool: %d", count)
	}

	// Simulate lease expiry after the failed Manager instance disappears.
	if _, err = controlDB.ExecContext(ctx, "UPDATE enrollment_claims SET lease_expires_at=now()-interval '1 second' WHERE id=$1", claim); err != nil {
		t.Fatal(err)
	}
	replacementStore := testSQLStore(t, controlDB)
	if _, err = replacementStore.IssueClaim(ctx, IssueRequest{
		ClaimID: claim, ProjectID: project, CertificateID: randomUUID(t),
		IssuerKeyID: "CA-test", EnrollmentToken: token, CSRDER: csr,
	}, issuer); err != nil {
		t.Fatalf("replacement Manager failed to recover expired lease: %v", err)
	}
	if err = controlDB.QueryRowContext(ctx, "SELECT count(*) FROM agent_certificates WHERE agent_id=$1", agent).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("durable certificates=%d, want exactly one after recovery", count)
	}
}
