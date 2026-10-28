package authz

import (
	"context"
	"database/sql"
	"errors"
)

// PostgresGrants is the authoritative grant lookup used by Authorizer.
// Database failures are propagated and then denied by Authorizer.Check.
type PostgresGrants struct {
	DB *sql.DB
}

func (g PostgresGrants) CheckGrant(ctx context.Context, operatorID, tenantID, projectID string, action Action) (bool, error) {
	if g.DB == nil {
		return false, errors.New("grant database unavailable")
	}
	if operatorID == "" || tenantID == "" || projectID == "" {
		return false, ErrForbidden
	}
	var allowed bool
	err := g.DB.QueryRowContext(ctx, `SELECT EXISTS(
	SELECT 1 FROM operator_grants g
	JOIN projects p ON p.id=g.project_id AND p.tenant_id=g.tenant_id
	WHERE g.operator_id=$1 AND g.tenant_id=$2 AND g.project_id=$3
	AND g.action=$4 AND g.revoked_at IS NULL AND p.status='active'
	)`, operatorID, tenantID, projectID, string(action)).Scan(&allowed)
	return allowed, err
}
