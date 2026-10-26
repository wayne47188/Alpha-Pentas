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

func TestSigningPoolRejectsUnsafeConfiguration(t *testing.T) {
	if _, err := NewSigningPool(0, time.Second); !errors.Is(err, ErrSigningPool) {
		t.Fatalf("zero capacity accepted: %v", err)
	}
	if _, err := NewSigningPool(1, issuanceLease); !errors.Is(err, ErrSigningPool) {
		t.Fatalf("timeout not bounded by lease: %v", err)
	}
	var absent *SigningPool
	if _, err := absent.Sign(context.Background(), nil); !errors.Is(err, ErrSigningPool) {
		t.Fatalf("missing worker accepted: %v", err)
	}
}
