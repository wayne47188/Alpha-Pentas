package enrollment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

func randomUUID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

func testIssuer(t *testing.T) (identity.Issuer, []byte) {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CI Only CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return identity.Issuer{CA: ca, Signer: caKey}, csr
}

func TestPostgresEnrollmentLifecycle(t *testing.T) {
	dsn := os.Getenv("ALPHA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("integration requires disposable ALPHA_TEST_DATABASE_URL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	tenant, project := randomUUID(t), randomUUID(t)
	for _, stmt := range []struct {
		query string
		args  []any
	}{
		{"INSERT INTO tenants(id,name) VALUES($1,'integration')", []any{tenant}},
		{"INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'integration')", []any{project, tenant}},
	} {
		if _, err = db.ExecContext(ctx, stmt.query, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	store := SQLStore{DB: db}
	token, err := store.IssueToken(ctx, randomUUID(t), project, "integration", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer, csr := testIssuer(t)
	var won atomic.Int32
	var claimedID, claimedAgent string
	var lock sync.Mutex
	var wg sync.WaitGroup
	for n := 0; n < 32; n++ {
		claimID, agentID := randomUUID(t), randomUUID(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.Claim(ctx, token, project, agentID, claimID, csr)
			if err == nil {
				won.Add(1)
				lock.Lock()
				claimedID, claimedAgent = claimID, agentID
				lock.Unlock()
			} else if !errors.Is(err, ErrInvalid) {
				t.Errorf("unexpected claim error: %v", err)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("claims succeeded: %d, want 1", won.Load())
	}
	issued, err := store.IssueClaim(ctx, claimedID, project, randomUUID(t), "test-CA", csr, issuer)
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.IssueClaim(ctx, claimedID, project, randomUUID(t), "test-CA", csr, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(issued.CertificateDER) != hex.EncodeToString(again.CertificateDER) {
		t.Fatal("idempotent retry changed certificate")
	}
	var state string
	if err = db.QueryRowContext(ctx, "SELECT state FROM agents WHERE id=$1", claimedAgent).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Fatalf("agent state %q, want active", state)
	}
	var certificateCount int
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM agent_certificates WHERE agent_id=$1", claimedAgent).Scan(&certificateCount); err != nil {
		t.Fatal(err)
	}
	if certificateCount != 1 {
		t.Fatalf("certificates %d, want 1", certificateCount)
	}
}
