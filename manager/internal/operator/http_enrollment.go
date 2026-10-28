package operator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
)

type DenialAudit interface {
	RecordDenied(context.Context, authz.Principal, string, string) error
}

type RequestLimiter interface {
	Allow(string) bool
}

type fixedWindowEntry struct {
	start time.Time
	count int
}

// FixedWindowLimiter provides per-authenticated-operator admission control.
// It is intentionally local to one Manager process; a distributed limiter can
// replace the RequestLimiter interface when Manager replicas are introduced.
type FixedWindowLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	now     func() time.Time
	entries map[string]fixedWindowEntry
}

func NewFixedWindowLimiter(limit int, window time.Duration) (*FixedWindowLimiter, error) {
	if limit < 1 || limit > 10000 || window <= 0 {
		return nil, errors.New("invalid rate limit")
	}
	return &FixedWindowLimiter{
		limit:   limit,
		window:  window,
		now:     time.Now,
		entries: make(map[string]fixedWindowEntry),
	}, nil
}

func (l *FixedWindowLimiter) Allow(key string) bool {
	if l == nil || key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	entry := l.entries[key]
	if entry.start.IsZero() || now.Sub(entry.start) >= l.window {
		entry = fixedWindowEntry{start: now}
	}
	if entry.count >= l.limit {
		l.entries[key] = entry
		return false
	}
	entry.count++
	l.entries[key] = entry
	return true
}

type tokenRequest struct {
	TTLSeconds int64 `json:"ttl_seconds"`
}

type tokenResponse struct {
	Token            string `json:"token"`
	ExpiresInSeconds int64  `json:"expires_in_seconds"`
}

// NewEnrollmentTokenHandler returns the authenticated API boundary for token
// issuance. It must be wrapped in RequireVerifiedOperator; the handler still
// fails closed if the verified principal is absent from context.
func NewEnrollmentTokenHandler(service EnrollmentService, limiter RequestLimiter, audit DenialAudit) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := PrincipalFromContext(r.Context())
		projectID := r.PathValue("projectID")
		if !ok {
			recordDenied(r.Context(), audit, authz.Principal{}, projectID, "unauthenticated")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if limiter == nil || audit == nil {
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		if projectID == "" {
			recordDenied(r.Context(), audit, principal, projectID, "missing_project")
			http.Error(w, "invalid project", http.StatusBadRequest)
			return
		}
		if !limiter.Allow(principal.ID) {
			recordDenied(r.Context(), audit, principal, projectID, "rate_limited")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		var input tokenRequest
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil || input.TTLSeconds < 1 || input.TTLSeconds > 3600 {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}

		tokenID, err := randomTokenID()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		scope := authz.Scope{
			TenantID:  principal.TenantID,
			ProjectID: projectID,
			Action:    authz.IssueEnrollmentToken,
		}
		token, err := service.IssueToken(r.Context(), principal, scope, tokenID, time.Duration(input.TTLSeconds)*time.Second)
		if err != nil {
			if errors.Is(err, authz.ErrForbidden) {
				recordDenied(r.Context(), audit, principal, projectID, "forbidden")
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(tokenResponse{Token: token, ExpiresInSeconds: input.TTLSeconds})
	})
}

func recordDenied(ctx context.Context, audit DenialAudit, principal authz.Principal, projectID, reason string) {
	if audit != nil {
		_ = audit.RecordDenied(ctx, principal, projectID, reason)
	}
}

func randomTokenID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
