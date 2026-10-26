// Package enrollment implements a P1 in-memory one-time token ledger.
// Production requires durable transactions, RBAC, PKI and audit.
package enrollment

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalid = errors.New("invalid or expired enrollment token")
	ErrProject = errors.New("project mismatch")
)

type tokenRecord struct {
	digest  [32]byte
	project string
	expires time.Time
	used    bool
}

type Store struct {
	mu      sync.Mutex
	records map[[32]byte]*tokenRecord
	now     func() time.Time
}

func NewStore() *Store {
	return &Store{records: make(map[[32]byte]*tokenRecord), now: time.Now}
}

// Issue returns a 256-bit random token and stores only its SHA-256 digest.
func (s *Store) Issue(project string, lifetime time.Duration) (string, error) {
	if project == "" || lifetime <= 0 || lifetime > time.Hour {
		return "", errors.New("invalid project or lifetime")
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(raw))
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[hash] = &tokenRecord{digest: hash, project: project, expires: s.now().Add(lifetime)}
	return raw, nil
}

// Consume atomically grants exactly one claim per token within this process.
func (s *Store) Consume(raw, project string) error {
	if raw == "" || project == "" {
		return ErrInvalid
	}
	hash := sha256.Sum256([]byte(raw))
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[hash]
	if !ok || subtle.ConstantTimeCompare(hash[:], record.digest[:]) != 1 || record.used || !s.now().Before(record.expires) {
		return ErrInvalid
	}
	if record.project != project {
		return ErrProject
	}
	record.used = true
	return nil
}
