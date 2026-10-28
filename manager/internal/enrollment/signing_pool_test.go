package enrollment

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

func TestSigningPoolBoundsHungSigner(t *testing.T) {
	pool, err := NewSigningPool(1, 40*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		_, signErr := pool.Sign(context.Background(), func() (identity.Result, error) {
			close(entered)
			<-release
			return identity.Result{}, nil
		})
		first <- signErr
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first signing job not started")
	}
	if err := <-first; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung signer returned %v, want deadline", err)
	}
	var secondStarted atomic.Bool
	_, err = pool.Sign(context.Background(), func() (identity.Result, error) {
		secondStarted.Store(true)
		return identity.Result{}, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || secondStarted.Load() {
		t.Fatalf("capacity bypass or unexpected error: started=%v err=%v", secondStarted.Load(), err)
	}
	close(release)
	deadline := time.After(time.Second)
	for {
		if len(pool.slots) == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("signing capacity not released")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	_, err = pool.Sign(context.Background(), func() (identity.Result, error) {
		return identity.Result{}, nil
	})
	if err != nil {
		t.Fatalf("healthy signer blocked after recovery: %v", err)
	}
}

func TestSigningPoolBackpressureWhenQueueIsFull(t *testing.T) {
	pool, err := NewSigningPoolWithQueue(1, 1, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	firstStarted := make(chan struct{})
	go func() {
		_, _ = pool.Sign(context.Background(), func() (identity.Result, error) {
			close(firstStarted)
			<-release
			return identity.Result{}, nil
		})
	}()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("first signing job not started")
	}

	secondDone := make(chan error, 1)
	go func() {
		_, signErr := pool.Sign(context.Background(), func() (identity.Result, error) {
			return identity.Result{}, nil
		})
		secondDone <- signErr
	}()
	deadline := time.After(time.Second)
	for len(pool.queue) != 1 {
		select {
		case <-deadline:
			t.Fatal("second request never entered bounded queue")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	start := time.Now()
	_, err = pool.Sign(context.Background(), func() (identity.Result, error) {
		t.Fatal("overflow request must not start")
		return identity.Result{}, nil
	})
	if !errors.Is(err, ErrSigningBusy) {
		t.Fatalf("overflow returned %v, want ErrSigningBusy", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("backpressure did not fail fast")
	}

	close(release)
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("queued request failed after capacity returned: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued request did not drain")
	}
}

func TestSigningPoolPropagatesCancellation(t *testing.T) {
	pool, err := NewSigningPool(1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, signErr := pool.SignContext(ctx, func(taskCtx context.Context) (identity.Result, error) {
			close(started)
			<-taskCtx.Done()
			return identity.Result{}, taskCtx.Err()
		})
		result <- signErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("context-aware signer not started")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel returned %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not propagate")
	}
}

func TestSigningPoolRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := NewSigningPool(0, time.Second); !errors.Is(err, ErrSigningPool) {
		t.Fatalf("zero capacity accepted: %v", err)
	}
	if _, err := NewSigningPoolWithQueue(1, 257, time.Second); !errors.Is(err, ErrSigningPool) {
		t.Fatalf("unbounded queue accepted: %v", err)
	}
	if _, err := NewSigningPool(1, issuanceLease); !errors.Is(err, ErrSigningPool) {
		t.Fatalf("timeout not bounded by lease: %v", err)
	}
	var absent *SigningPool
	if _, err := absent.Sign(context.Background(), nil); !errors.Is(err, ErrSigningPool) {
		t.Fatalf("missing worker accepted: %v", err)
	}
}
