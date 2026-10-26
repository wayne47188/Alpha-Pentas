package operator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

type grants struct {
	allowed bool
}

func (g grants) HasGrant(context.Context, string, string, string, authz.Action) (bool, error) {
	return g.allowed, nil
}

type tokenIssuer struct {
	calls  int
	issuer string
}

func (t *tokenIssuer) IssueToken(_ context.Context, _, _, issuer string, _ time.Duration) (string, error) {
	t.calls++
	t.issuer = issuer
	return "secret", nil
}

func TestIssueTokenRequiresAuthorization(t *testing.T) {
	principal := authz.Principal{ID: "operator-1", TenantID: "tenant-A", Authenticated: true}
	scope := authz.Scope{TenantID: "tenant-A", ProjectID: "project-A", Action: authz.IssueEnrollmentToken}
	for _, tc := range []struct {
		name      string
		principal authz.Principal
		scope     authz.Scope
		grant     bool
		success   bool
	}{
		{"allowed", principal, scope, true, true},
		{"denied grant", principal, scope, false, false},
		{"unauthenticated", authz.Principal{ID: "operator-1", TenantID: "tenant-A"}, scope, true, false},
		{"cross tenant", principal, authz.Scope{TenantID: "tenant-B", ProjectID: "project-A", Action: authz.IssueEnrollmentToken}, true, false},
		{"wrong action", principal, authz.Scope{TenantID: "tenant-A", ProjectID: "project-A", Action: authz.ManageAgent}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokens := &tokenIssuer{}
			service := EnrollmentService{Authorization: authz.Authorizer{Grants: grants{allowed: tc.grant}}, Tokens: tokens}
			_, err := service.IssueToken(context.Background(), tc.principal, tc.scope, "id", time.Minute)
			if (err == nil) != tc.success {
				t.Fatalf("issue token error=%v want success=%v", err, tc.success)
			}
			if tc.success && (tokens.calls != 1 || tokens.issuer != principal.ID) {
				t.Fatalf("incorrect issuer binding: calls=%d issuer=%q", tokens.calls, tokens.issuer)
			}
			if !tc.success && tokens.calls != 0 {
				t.Fatal("unauthorized issuance invoked token store")
			}
		})
	}
	service := EnrollmentService{Authorization: authz.Authorizer{Grants: grants{allowed: true}}}
	if _, err := service.IssueToken(context.Background(), principal, scope, "id", time.Minute); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("missing token service should fail closed: %v", err)
	}
}
