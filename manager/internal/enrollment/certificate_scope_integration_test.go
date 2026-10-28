package enrollment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"os"
	"testing"
	"time"

	// Register lib/pq with database/sql for PostgreSQL integration tests.
	_ "github.com/lib/pq"
)

// Validate that trust is rejected for the wrong project or any inactive
// project/agent, even when the certificate was legitimately signed.
func TestPostgresCertificateScopeAndSuspension(t *testing.T) {
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
	if _, err = db.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'scope-test')", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'scope-test')", project, tenant); err != nil {
		t.Fatal(err)
	}
	store := testSQLStore(t, db)
	issuer, csr := testIssuer(t)
	token, err := store.IssueToken(ctx, randomUUID(t), project, "test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Claim(ctx, token, project, agent, claim, csr); err != nil {
		t.Fatal(err)
	}
	result, err := store.IssueClaim(ctx, claim, project, randomUUID(t), "test-CA", token, csr, issuer)
	if err != nil {
		t.Fatal(err)
	}
	fp := sha256.Sum256(result.CertificateDER)
	if err = store.CertificateStatus(ctx, project, agent, fp); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}
	if err = store.CertificateStatus(ctx, randomUUID(t), agent, fp); err == nil {
		t.Fatal("cross-project certificate accepted")
	}
	if err = store.CertificateStatus(ctx, project, agent, sha256.Sum256([]byte("uncommitted"))); err == nil {
		t.Fatal("unknown certificate fingerprint accepted")
	}
	if _, err = db.ExecContext(ctx, "UPDATE projects SET status='suspended' WHERE id=$1", project); err != nil {
		t.Fatal(err)
	}
	if err = store.CertificateStatus(ctx, project, agent, fp); err == nil {
		t.Fatal("suspended project certificate accepted")
	}
	if _, err = db.ExecContext(ctx, "UPDATE projects SET status='active' WHERE id=$1", project); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "UPDATE agents SET state='suspended' WHERE id=$1", agent); err != nil {
		t.Fatal(err)
	}
	if err = store.CertificateStatus(ctx, project, agent, fp); err == nil {
		t.Fatal("suspended agent certificate accepted")
	}
}
