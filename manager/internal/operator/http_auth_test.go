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

func TestRequireVerifiedOperatorFailsClosed(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{1, 2, 3}}
	other := &x509.Certificate{Raw: []byte{4, 5, 6}}
	valid := authz.Principal{ID: "operator", TenantID: "tenant", Authenticated: true}
	tests := []struct {
		name     string
		tlsState *tls.ConnectionState
		resolver PrincipalResolver
		allowed  bool
	}{
		{"missing TLS", nil, fakeResolver{principal: valid}, false},
		{"no verified chain", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, fakeResolver{principal: valid}, false},
		{"mismatched leaf", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{other}}}, fakeResolver{principal: valid}, false},
		{"resolver failure", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}, fakeResolver{err: errors.New("unavailable")}, false},
		{"no authenticated operator", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}, fakeResolver{principal: authz.Principal{ID: "operator"}}, false},
		{"nil resolver", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}, nil, false},
		{"authenticated", &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}, fakeResolver{principal: valid}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			handler := RequireVerifiedOperator(tc.resolver, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				p, ok := PrincipalFromContext(r.Context())
				if !ok || p.ID != valid.ID {
					t.Error("verified principal not propagated")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(http.MethodPost, "https://manager.example/internal", nil)
			req.Header.Set("X-Operator-ID", "operator")
			req.TLS = tc.tlsState
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if called != tc.allowed {
				t.Fatalf("handler called=%v, want %v", called, tc.allowed)
			}
			if tc.allowed && rec.Code != http.StatusNoContent {
				t.Fatalf("code=%d", rec.Code)
			}
			if !tc.allowed && rec.Code != http.StatusUnauthorized {
				t.Fatalf("code=%d, want 401", rec.Code)
			}
		})
	}
}
