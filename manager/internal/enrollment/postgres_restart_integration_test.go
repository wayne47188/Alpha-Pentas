package enrollment

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// TestDockerPostgresServerRestartDuringSigningRecovers is CI-only because it
// restarts the disposable PostgreSQL service container. It proves that no DB
// transaction spans the CA call and that an expired lease can be reclaimed
// after the database process itself disappears and returns.
func TestDockerPostgresServerRestartDuringSigningRecovers(t *testing.T) {
	dsn := os.Getenv("ALPHA_TEST_DATABASE_URL")
	containerID := os.Getenv("ALPHA_TEST_POSTGRES_CONTAINER")
	if dsn == "" || containerID == "" {
		t.Skip("requires disposable PostgreSQL and ALPHA_TEST_POSTGRES_CONTAINER")
	}

	workerDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer workerDB.Close()
	controlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer controlDB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	tenant, project, agent, claim := randomUUID(t), randomUUID(t), randomUUID(t), randomUUID(t)
	if _, err = controlDB.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'db-restart-test')", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = controlDB.ExecContext(ctx, "INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'db-restart-test')", project, tenant); err != nil {
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
	stale := make(chan error, 1)
	go func() {
		_, issueErr := workerStore.IssueClaim(ctx, IssueRequest{
			ClaimID: claim, ProjectID: project, CertificateID: randomUUID(t),
			IssuerKeyID: "CA-test", EnrollmentToken: token, CSRDER: csr,
		}, stalledIssuer)
		stale <- issueErr
	}()
	select {
	case <-blocker.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("signer was not reached")
	}

	restartCtx, restartCancel := context.WithTimeout(ctx, 15*time.Second)
	defer restartCancel()
	cmd := exec.CommandContext(restartCtx, "docker", "restart", containerID)
	if output, restartErr := cmd.CombinedOutput(); restartErr != nil {
		close(blocker.release)
		t.Fatalf("restart PostgreSQL container: %v: %s", restartErr, output)
	}

	deadline := time.Now().Add(15 * time.Second)
	for {
		pingCtx, stop := context.WithTimeout(ctx, time.Second)
		err = controlDB.PingContext(pingCtx)
		stop()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			close(blocker.release)
			t.Fatalf("PostgreSQL did not recover after restart: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The old signer is still blocked. Expire its lease after the DB process
	// returns, then let another Manager instance reclaim and commit first.
	if _, err = controlDB.ExecContext(ctx, "UPDATE enrollment_claims SET lease_expires_at=now()-interval '1 second' WHERE id=$1 AND state='issuing'", claim); err != nil {
		close(blocker.release)
		t.Fatal(err)
	}
	replacementStore := testSQLStore(t, controlDB)
	if _, err = replacementStore.IssueClaim(ctx, IssueRequest{
		ClaimID: claim, ProjectID: project, CertificateID: randomUUID(t),
		IssuerKeyID: "CA-test", EnrollmentToken: token, CSRDER: csr,
	}, issuer); err != nil {
		close(blocker.release)
		t.Fatalf("replacement Manager failed after DB restart: %v", err)
	}

	close(blocker.release)
	select {
	case issueErr := <-stale:
		if !errors.Is(issueErr, ErrLeaseLost) {
			t.Fatalf("stale signer returned %v, want ErrLeaseLost", issueErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale signer did not terminate")
	}

	var count int
	if err = controlDB.QueryRowContext(ctx, "SELECT count(*) FROM agent_certificates WHERE agent_id=$1", agent).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("durable certificates=%d, want exactly one", count)
	}
}
