package authz

import (
	"context"
	"errors"
	"reflect"
)

var ErrForbidden = errors.New("operation not authorized")

type Action string

const (
	IssueEnrollmentToken Action = "enrollment.token.issue"
	ReadEnrollmentStatus Action = "enrollment.status.read"
	ManageAgent          Action = "agent.manage"
)

type Principal struct {
	ID            string
	TenantID      string
	Authenticated bool
}

type Scope struct {
	TenantID  string
	ProjectID string
	Action    Action
}

// GrantChecker checks scoped grants from the authoritative authorization source.
// It must fail closed when the source is unavailable.
type GrantChecker interface {
	CheckGrant(context.Context, string, string, string, Action) (bool, error)
}

type Authorizer struct {
	Grants GrantChecker
}

// Check always binds principal, tenant, project and operation together.
// Do not trust tenant/project from client-controlled headers or JWT role text
// without independently verifying an authenticated principal.
func (a Authorizer) Check(ctx context.Context, principal Principal, scope Scope) error {
	if !grantCheckerAvailable(a.Grants) || !principal.Authenticated || principal.ID == "" ||
		principal.TenantID == "" || scope.TenantID == "" ||
		scope.ProjectID == "" || principal.TenantID != scope.TenantID {
		return ErrForbidden
	}
	switch scope.Action {
	case IssueEnrollmentToken, ReadEnrollmentStatus, ManageAgent:
	default:
		return ErrForbidden
	}
	ok, err := a.Grants.CheckGrant(ctx, principal.ID, scope.TenantID, scope.ProjectID, scope.Action)
	if err != nil || !ok {
		return ErrForbidden
	}
	return nil
}

func grantCheckerAvailable(checker GrantChecker) bool {
	if checker == nil {
		return false
	}
	value := reflect.ValueOf(checker)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return !value.IsNil()
	default:
		return true
	}
}
