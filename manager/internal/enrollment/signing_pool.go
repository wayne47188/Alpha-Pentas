package enrollment

import (
	"context"
	"errors"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

var ErrSigningPool = errors.New("certificate signing worker pool is unavailable")
var ErrSigningBusy = errors.New("certificate signing queue is full")

// SigningPool bounds active CA operations, queued work and caller wait time.
// A legacy non-cooperative crypto.Signer cannot be forcibly killed. A hung
// call therefore keeps only its worker slot occupied; queue capacity prevents
// unbounded goroutine growth while fencing prevents late DB commits.
type SigningPool struct {
	slots   chan struct{}
	queue   chan struct{}
	timeout time.Duration
}

func NewSigningPool(maxConcurrent int, timeout time.Duration) (*SigningPool, error) {
	return NewSigningPoolWithQueue(maxConcurrent, maxConcurrent, timeout)
}

func NewSigningPoolWithQueue(maxConcurrent, maxQueued int, timeout time.Duration) (*SigningPool, error) {
	if maxConcurrent < 1 || maxConcurrent > 32 || maxQueued < 0 || maxQueued > 256 ||
		timeout <= 0 || timeout >= issuanceLease {
		return nil, ErrSigningPool
	}
	return &SigningPool{
		slots:   make(chan struct{}, maxConcurrent),
		queue:   make(chan struct{}, maxQueued),
		timeout: timeout,
	}, nil
}

type signingOutcome struct {
	value identity.Result
	err   error
}

// Sign preserves compatibility for local crypto.Signer users. Prefer
// SignContext for adapters that can actually abort remote/HSM signing.
func (p *SigningPool) Sign(ctx context.Context, task func() (identity.Result, error)) (identity.Result, error) {
	if task == nil {
		return identity.Result{}, ErrSigningPool
	}
	return p.SignContext(ctx, func(context.Context) (identity.Result, error) {
		return task()
	})
}

// SignContext applies admission control before starting a signing goroutine,
// propagates a bounded context into the task, and holds the worker slot until
// the underlying signer actually exits.
func (p *SigningPool) SignContext(ctx context.Context, task func(context.Context) (identity.Result, error)) (identity.Result, error) {
	var empty identity.Result
	if p == nil || task == nil {
		return empty, ErrSigningPool
	}
	bounded, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	queued := false
	if cap(p.queue) > 0 {
		select {
		case p.queue <- struct{}{}:
			queued = true
		default:
			return empty, ErrSigningBusy
		}
		defer func() {
			if queued {
				<-p.queue
			}
		}()
	}

	select {
	case p.slots <- struct{}{}:
		if queued {
			<-p.queue
			queued = false
		}
	case <-bounded.Done():
		return empty, bounded.Err()
	}

	done := make(chan signingOutcome, 1)
	go func() {
		defer func() { <-p.slots }()
		value, err := task(bounded)
		done <- signingOutcome{value: value, err: err}
	}()

	select {
	case result := <-done:
		return result.value, result.err
	case <-bounded.Done():
		return empty, bounded.Err()
	}
}
