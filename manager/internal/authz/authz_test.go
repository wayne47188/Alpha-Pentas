package authz

import (
	"context"
	"errors"
	"testing"
)

type stubGrants struct {
	allow bool
	err   error
	calls int
}

func (s *stubGrants) CheckGrant(_ context.Context, _, _, _ string, _ Action) (bool, error) {
	s.calls++
	return s.allow, s.err
}

func TestCheckFailsClosed(t *testing.T) {
	tests := []struct {
		name      string
		principal Principal
		scope     Scope
		store     *stubGrants
		allow     bool
		calls     int
	}{
		{"allowed", Principal{ID: "op", TenantID: "tenantA", Authenticated: true}, Scope{"tenantA", "projectA", IssueEnrollmentToken}, &stubGrants{allow: true}, true, 1},
		{"unauthenticated", Principal{ID: "op", TenantID: "tenantA"}, Scope{"tenantA", "projectA", IssueEnrollmentToken}, &stubGrants{allow: true}, false, 0},
		{"cross tenant", Principal{ID: "op", TenantID: "tenantA", Authenticated: true}, Scope{"tenantB", "projectA", IssueEnrollmentToken}, &stubGrants{allow: true}, false, 0},
		{"missing project", Principal{ID: "op", TenantID: "tenantA", Authenticated: true}, Scope{"tenantA", "", IssueEnrollmentToken}, &stubGrants{allow: true}, false, 0},
		{"unknown action", Principal{ID: "op", TenantID: "tenantA", Authenticated: true}, Scope{"tenantA", "projectA", "arbitrary.execute"}, &stubGrants{allow: true}, false, 0},
		{"no grant", Principal{ID: "op", TenantID: "tenantA", Authenticated: true}, Scope{"tenantA", "projectA", ManageAgent}, &stubGrants{}, false, 1},
		{"grant DB failure", Principal{ID: "op", TenantID: "tenantA", Authenticated: true}, Scope{"tenantA", "projectA", ManageAgent}, &stubGrants{err: errors.New("database down")}, false, 1},
		{"missing store", Principal{ID: "op", TenantID: "tenantA", Authenticated: true}, Scope{"tenantA", "projectA", ManageAgent}, nil, false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := (Authorizer{Grants: tc.store}).Check(context.Background(), tc.principal, tc.scope)
			if (err == nil) != tc.allow {
				t.Fatalf("got error %v, allow=%v", err, tc.allow)
			}
			if tc.store != nil && tc.store.calls != tc.calls {
				t.Fatalf("grant calls=%d, want %d", tc.store.calls, tc.calls)
			}
		})
	}
}
