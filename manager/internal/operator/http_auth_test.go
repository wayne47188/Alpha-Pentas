package operator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

type fakeResolver struct {
	principal authz.Principal
	err       error
}

func (r fakeResolver) ResolveOperator(context.Context, *x509.Certificate) (authz.Principal, error) {
	return r.principal, r.err
}

func verifiedTLS(cert *x509.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains:   [][]*x509.Certificate{{cert}},
	}
}

func runOperatorAuthCase(t *testing.T, tlsState *tls.ConnectionState, resolver PrincipalResolver, allowed bool) {
	t.Helper()
	valid := authz.Principal{ID: "operator", TenantID: "tenant", Authenticated: true}
	called := false
	handler := RequireVerifiedOperator(resolver, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principal, ok := PrincipalFromContext(r.Context())
		if !ok || principal.ID != valid.ID {
			t.Error("verified principal not propagated")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "https://manager.example/internal", nil)
	req.Header.Set("X-Operator-ID", "attacker-controlled-value")
	req.TLS = tlsState
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if called != allowed {
		t.Fatalf("handler called=%v, want %v", called, allowed)
	}
	expectedStatus := http.StatusUnauthorized
	if allowed {
		expectedStatus = http.StatusNoContent
	}
	if rec.Code != expectedStatus {
		t.Fatalf("status=%d, want %d", rec.Code, expectedStatus)
	}
}

func TestRequireVerifiedOperatorFailsClosed(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{1, 2, 3}}
	other := &x509.Certificate{Raw: []byte{4, 5, 6}}
	valid := authz.Principal{ID: "operator", TenantID: "tenant", Authenticated: true}
	cases := []struct {
		name     string
		tlsState *tls.ConnectionState
		resolver PrincipalResolver
		allowed  bool
	}{
		{"missing TLS", nil, fakeResolver{principal: valid}, false},
		{"no verified chain", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, fakeResolver{principal: valid}, false},
		{"mismatched leaf", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{other}}}, fakeResolver{principal: valid}, false},
		{"resolver failure", verifiedTLS(cert), fakeResolver{err: errors.New("unavailable")}, false},
		{"no authenticated operator", verifiedTLS(cert), fakeResolver{principal: authz.Principal{ID: "operator"}}, false},
		{"nil resolver", verifiedTLS(cert), nil, false},
		{"authenticated", verifiedTLS(cert), fakeResolver{principal: valid}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runOperatorAuthCase(t, tc.tlsState, tc.resolver, tc.allowed)
		})
	}
}
