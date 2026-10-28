package operator

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

type apiGrant struct {
	tenant  string
	project string
}

func (g apiGrant) CheckGrant(_ context.Context, _ string, tenantID, projectID string, action authz.Action) (bool, error) {
	return tenantID == g.tenant && projectID == g.project && action == authz.IssueEnrollmentToken, nil
}

type denialRecord struct {
	principal authz.Principal
	project   string
	reason    string
}

type auditRecorder struct {
	records []denialRecord
}

func (a *auditRecorder) RecordDenied(_ context.Context, principal authz.Principal, projectID, reason string) error {
	a.records = append(a.records, denialRecord{principal: principal, project: projectID, reason: reason})
	return nil
}

type staticLimiter bool

func (l staticLimiter) Allow(string) bool { return bool(l) }

func tokenAPI(t *testing.T, service EnrollmentService, resolver PrincipalResolver, limiter RequestLimiter, audit DenialAudit) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/projects/{projectID}/enrollment-tokens",
		RequireVerifiedOperator(resolver, NewEnrollmentTokenHandler(service, limiter, audit)))
	return mux
}

func TestEnrollmentTokenHTTPBoundary(t *testing.T) {
	tenant := "tenant-A"
	project := "project-A"
	principal := authz.Principal{ID: "operator-A", TenantID: tenant, Authenticated: true}
	tokens := &tokenIssuer{}
	service := EnrollmentService{
		Authorization: authz.Authorizer{Grants: apiGrant{tenant: tenant, project: project}},
		Tokens:        tokens,
	}
	cert := &x509.Certificate{Raw: []byte{1, 2, 3}}
	audit := &auditRecorder{}
	handler := tokenAPI(t, service, fakeResolver{principal: principal}, staticLimiter(true), audit)

	body, _ := json.Marshal(tokenRequest{TTLSeconds: 60})
	req := httptest.NewRequest(http.MethodPost, "https://manager.example/api/v1/projects/project-A/enrollment-tokens", bytes.NewReader(body))
	req.TLS = verifiedTLS(cert)
	req.Header.Set("X-Operator-ID", "attacker")
	req.Header.Set("X-Tenant-ID", "tenant-B")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if tokens.calls != 1 || tokens.issuer != principal.ID {
		t.Fatalf("untrusted header affected issuer binding: calls=%d issuer=%q", tokens.calls, tokens.issuer)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response is cacheable")
	}
}

func TestEnrollmentTokenHTTPRejectsCrossProjectAndAudits(t *testing.T) {
	principal := authz.Principal{ID: "operator-A", TenantID: "tenant-A", Authenticated: true}
	tokens := &tokenIssuer{}
	audit := &auditRecorder{}
	service := EnrollmentService{
		Authorization: authz.Authorizer{Grants: apiGrant{tenant: "tenant-A", project: "project-A"}},
		Tokens:        tokens,
	}
	cert := &x509.Certificate{Raw: []byte{4, 5, 6}}
	handler := tokenAPI(t, service, fakeResolver{principal: principal}, staticLimiter(true), audit)
	req := httptest.NewRequest(http.MethodPost, "https://manager.example/api/v1/projects/project-B/enrollment-tokens", bytes.NewBufferString(`{"ttl_seconds":60}`))
	req.TLS = verifiedTLS(cert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || tokens.calls != 0 {
		t.Fatalf("cross-project request status=%d tokenCalls=%d", rec.Code, tokens.calls)
	}
	if len(audit.records) != 1 || audit.records[0].reason != "forbidden" || audit.records[0].project != "project-B" {
		t.Fatalf("denial not audited: %+v", audit.records)
	}
}

func TestEnrollmentTokenHTTPRateLimitAndAuthentication(t *testing.T) {
	principal := authz.Principal{ID: "operator-A", TenantID: "tenant-A", Authenticated: true}
	service := EnrollmentService{Authorization: authz.Authorizer{Grants: apiGrant{tenant: "tenant-A", project: "project-A"}}, Tokens: &tokenIssuer{}}
	cert := &x509.Certificate{Raw: []byte{7, 8, 9}}

	audit := &auditRecorder{}
	handler := tokenAPI(t, service, fakeResolver{principal: principal}, staticLimiter(false), audit)
	req := httptest.NewRequest(http.MethodPost, "https://manager.example/api/v1/projects/project-A/enrollment-tokens", bytes.NewBufferString(`{"ttl_seconds":60}`))
	req.TLS = verifiedTLS(cert)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests || len(audit.records) != 1 || audit.records[0].reason != "rate_limited" {
		t.Fatalf("rate limit not enforced/audited: status=%d records=%+v", rec.Code, audit.records)
	}

	audit = &auditRecorder{}
	handler = tokenAPI(t, service, fakeResolver{principal: principal}, staticLimiter(true), audit)
	req = httptest.NewRequest(http.MethodPost, "https://manager.example/api/v1/projects/project-A/enrollment-tokens", bytes.NewBufferString(`{"ttl_seconds":60}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing verified TLS status=%d", rec.Code)
	}
}

func TestFixedWindowLimiter(t *testing.T) {
	limiter, err := NewFixedWindowLimiter(2, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1000, 0)
	limiter.now = func() time.Time { return now }
	if !limiter.Allow("operator") || !limiter.Allow("operator") || limiter.Allow("operator") {
		t.Fatal("fixed window limit not enforced")
	}
	now = now.Add(time.Minute)
	if !limiter.Allow("operator") {
		t.Fatal("new window did not reset")
	}
}
