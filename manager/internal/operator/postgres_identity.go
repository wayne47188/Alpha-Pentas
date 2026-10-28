package operator

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"errors"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

var ErrOperatorIdentity = errors.New("operator identity not authorized")

// PostgresPrincipalResolver maps a TLS-verified client certificate to an
// authoritative operator identity. Request headers and JSON are never used.
type PostgresPrincipalResolver struct {
	DB *sql.DB
}

func (r PostgresPrincipalResolver) ResolveOperator(ctx context.Context, cert *x509.Certificate) (authz.Principal, error) {
	var principal authz.Principal
	if r.DB == nil || cert == nil || len(cert.Raw) == 0 {
		return principal, ErrOperatorIdentity
	}
	fingerprint := sha256.Sum256(cert.Raw)
	err := r.DB.QueryRowContext(ctx, `SELECT operator_id, tenant_id::text
 FROM operator_identities
 WHERE certificate_sha256=$1 AND state='active' AND revoked_at IS NULL`,
		fingerprint[:]).Scan(&principal.ID, &principal.TenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return authz.Principal{}, ErrOperatorIdentity
	}
	if err != nil {
		return authz.Principal{}, err
	}
	principal.Authenticated = true
	return principal, nil
}
