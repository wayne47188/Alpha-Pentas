package operator

import (
	"context"
	"errors"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

var ErrNotConfigured = errors.New("operator enrollment service is not configured")

type TokenIssuer interface {
	IssueToken(context.Context, string, string, string, time.Duration) (string, error)
}

type EnrollmentService struct {
	Authorization authz.Authorizer
	Tokens        TokenIssuer
}

// IssueToken has no direct HTTP route. A future authenticated endpoint must
// construct Principal from trusted server-side identity, never request JSON.
// The operator ID is authoritative; caller cannot choose issued_by.
func (s EnrollmentService) IssueToken(ctx context.Context, principal authz.Principal, scope authz.Scope, tokenID string, ttl time.Duration) (string, error) {
	if s.Tokens == nil {
		return "", ErrNotConfigured
	}
	if scope.Action != authz.IssueEnrollmentToken {
		return "", authz.ErrForbidden
	}
	if err := s.Authorization.Check(ctx, principal, scope); err != nil {
		return "", err
	}
	return s.Tokens.IssueToken(ctx, tokenID, scope.ProjectID, principal.ID, ttl)
}
