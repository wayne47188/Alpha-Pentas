package operator

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

// PrincipalResolver binds a verified client certificate to a server-side
// operator record. Never derive privileges from request-controlled headers.
type PrincipalResolver interface {
	ResolveOperator(context.Context, *x509.Certificate) (authz.Principal, error)
}

type principalContextKey struct{}

func PrincipalFromContext(ctx context.Context) (authz.Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(authz.Principal)
	return principal, ok && principal.Authenticated && principal.ID != "" && principal.TenantID != ""
}

// RequireVerifiedOperator requires a TLS-verified client certificate and
// server-side operator identity resolution before dispatching to a handler.
// This middleware must only run behind a TLS server configured with
// tls.RequireAndVerifyClientCert; never trust forwarded identity headers.
func RequireVerifiedOperator(resolver PrincipalResolver, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if resolver == nil || next == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 ||
			len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		if leaf == nil || !leaf.Equal(r.TLS.VerifiedChains[0][0]) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		principal, err := resolver.ResolveOperator(r.Context(), leaf)
		if err != nil || !principal.Authenticated || principal.ID == "" || principal.TenantID == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalContextKey{}, principal)))
	})
}
