package authz

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPostgresOperatorGrantRevocationAndIsolation(t *testing.T) {
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
	tenant := "97111111-1111-4111-8111-111111111111"
	otherTenant := "97222222-2222-4222-8222-222222222222"
	project := "97333333-3333-4333-8333-333333333333"
	if _, err = db.ExecContext(ctx, `INSERT INTO tenants(id,name) VALUES ($1,'grant-fixture'),($2,'other-fixture') ON CONFLICT (id) DO NOTHING`, tenant, otherTenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO projects(id,tenant_id,name) VALUES ($1,$2,'grant-fixture') ON CONFLICT (id) DO NOTHING`, project, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO operator_grants(operator_id,tenant_id,project_id,action)
	VALUES ('fixture-operator',$1,$2,$3) ON CONFLICT(operator_id,tenant_id,project_id,action)
	DO UPDATE SET revoked_at=NULL`, tenant, project, string(IssueEnrollmentToken)); err != nil {
		t.Fatal(err)
	}
	auth := Authorizer{Grants: PostgresGrants{DB: db}}
	principal := Principal{ID: "fixture-operator", TenantID: tenant, Authenticated: true}
	scope := Scope{TenantID: tenant, ProjectID: project, Action: IssueEnrollmentToken}
	if err := auth.Check(ctx, principal, scope); err != nil {
		t.Fatal(err)
	}
	wrong := scope
	wrong.TenantID = otherTenant
	if err := auth.Check(ctx, principal, wrong); err == nil {
		t.Fatal("cross tenant grant accepted")
	}
	wrong = scope
	wrong.Action = ManageAgent
	if err := auth.Check(ctx, principal, wrong); err == nil {
		t.Fatal("wrong action grant accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE operator_grants SET revoked_at=now() WHERE operator_id='fixture-operator' AND project_id=$1`, project); err != nil {
		t.Fatal(err)
	}
	if err := auth.Check(ctx, principal, scope); err == nil {
		t.Fatal("revoked grant accepted")
	}
	if _, err = db.ExecContext(ctx, `UPDATE operator_grants SET revoked_at=NULL WHERE operator_id='fixture-operator' AND project_id=$1`, project); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE projects SET status='suspended' WHERE id=$1`, project); err != nil {
		t.Fatal(err)
	}
	if err := auth.Check(ctx, principal, scope); err == nil {
		t.Fatal("suspended project grant accepted")
	}
}
