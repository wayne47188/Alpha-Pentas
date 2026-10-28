package operator

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

func TestPostgresOperatorDenialAudit(t *testing.T) {
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

	tenant := "99111111-1111-4111-8111-111111111111"
	if _, err = db.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'operator-audit') ON CONFLICT(id) DO NOTHING", tenant); err != nil {
		t.Fatal(err)
	}
	audit := PostgresDenialAudit{DB: db}
	principal := authz.Principal{ID: "audit-operator", TenantID: tenant, Authenticated: true}
	if err = audit.RecordDenied(ctx, principal, "project-does-not-exist", "forbidden"); err != nil {
		t.Fatal(err)
	}
	if err = audit.RecordDenied(ctx, authz.Principal{}, "", "unauthenticated"); err != nil {
		t.Fatal(err)
	}

	var count int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM operator_audit
 WHERE reason IN ('forbidden','unauthenticated')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("audit rows=%d, want 2", count)
	}
	if err = audit.RecordDenied(ctx, principal, "", "arbitrary_reason"); err == nil {
		t.Fatal("unknown audit reason accepted")
	}
}
