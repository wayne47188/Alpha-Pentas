package operator

import (
	"context"
	"database/sql"
	"errors"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

var ErrOperatorAudit = errors.New("operator audit unavailable")

// PostgresDenialAudit persists deny decisions separately from application logs.
// Denial paths remain denied even if this store is temporarily unavailable.
type PostgresDenialAudit struct {
	DB *sql.DB
}

func (a PostgresDenialAudit) RecordDenied(ctx context.Context, principal authz.Principal, projectID, reason string) error {
	if a.DB == nil {
		return ErrOperatorAudit
	}
	if len(projectID) > 200 {
		projectID = projectID[:200]
	}
	switch reason {
	case "unauthenticated", "missing_project", "rate_limited", "forbidden":
	default:
		return ErrOperatorAudit
	}

	var operatorID any
	var tenantID any
	if principal.ID != "" {
		operatorID = principal.ID
	}
	if principal.TenantID != "" {
		tenantID = principal.TenantID
	}
	_, err := a.DB.ExecContext(ctx, `INSERT INTO operator_audit
 (operator_id,tenant_id,project_ref,event_type,reason)
 VALUES ($1,$2,$3,'authorization_denied',$4)`,
		operatorID, tenantID, projectID, reason)
	return err
}
