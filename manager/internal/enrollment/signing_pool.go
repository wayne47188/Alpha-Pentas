package enrollment

import (
	"context"
	"errors"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

var ErrSigningPool = errors.New("certificate signing worker pool is unavailable")

// SigningPool bounds concurrent CA operations and the caller's wait time.
// A non-cooperative hardware signer cannot be forcibly killed. A hung call
// keeps its slot occupied, deliberately preventing unbounded goroutine growth.
type SigningPool struct {
	slots   chan struct{}
	timeout time.Duration
}

func NewSigningPool(maxConcurrent int, timeout time.Duration) (*SigningPool, error) {
	if maxConcurrent < 1 || maxConcurrent > 32 || timeout <= 0 || timeout >= issuanceLease {
		return nil, ErrSigningPool
	}
	return &SigningPool{slots: make(chan struct{}, maxConcurrent), timeout: timeout}, nil
}

type signingOutcome struct {
	value identity.Result
	err   error
}

func (p *SigningPool) Sign(ctx context.Context, task func() (identity.Result, error)) (identity.Result, error) {
	var empty identity.Result
	if p == nil || task == nil {
		return empty, ErrSigningPool
	}
	bounded, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	select {
	case p.slots <- struct{}{}:
	case <-bounded.Done():
		return empty, bounded.Err()
	}

	done := make(chan signingOutcome, 1)
	go func() {
		defer func() { <-p.slots }()
		value, err := task()
		done <- signingOutcome{value: value, err: err}
	}()
	select {
	case result := <-done:
		return result.value, result.err
	case <-bounded.Done():
		return empty, bounded.Err()
	}
}
