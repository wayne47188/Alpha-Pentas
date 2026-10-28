package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
)

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "component": "alpha-pentas-manager"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	return mux
}

func run(ctx context.Context) error {
	addr := os.Getenv("ALPHA_MANAGER_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	healthServer := &http.Server{
		Addr:              addr,
		Handler:           newHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	operatorCfg, operatorEnabled, err := operatorConfigFromEnv()
	if err != nil {
		return err
	}
	var operatorServer *http.Server
	if operatorEnabled {
		builtServer, db, buildErr := newOperatorServer(ctx, operatorCfg)
		if buildErr != nil {
			return buildErr
		}
		operatorServer = builtServer
		defer db.Close()
	}

	agentCfg, agentEnabled, err := agentGRPCConfigFromEnv()
	if err != nil {
		return err
	}
	var agentServer *grpc.Server
	var agentListener net.Listener
	if agentEnabled {
		builtServer, db, buildErr := newAgentGRPCServer(ctx, agentCfg)
		if buildErr != nil {
			return buildErr
		}
		agentServer = builtServer
		defer db.Close()

		agentListener, err = net.Listen("tcp", agentCfg.Addr)
		if err != nil {
			return err
		}
		defer agentListener.Close()
	}

	errCh := make(chan error, 3)
	go func() {
		log.Printf("Alpha Pentas Manager health listener on %s", addr)
		serveErr := healthServer.ListenAndServe()
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
		}
	}()

	if operatorEnabled {
		go func() {
			log.Printf("Alpha Pentas Manager operator mTLS listener on %s", operatorCfg.Addr)
			serveErr := operatorServer.ListenAndServeTLS("", "")
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				errCh <- serveErr
			}
		}()
	}

	if agentEnabled {
		go func() {
			log.Printf("Alpha Pentas Manager Agent gRPC mTLS listener on %s", agentListener.Addr())
			if serveErr := agentServer.Serve(agentListener); serveErr != nil {
				errCh <- serveErr
			}
		}()
	}

	select {
	case <-ctx.Done():
	case err = <-errCh:
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	healthErr := healthServer.Shutdown(shutdownCtx)

	var operatorErr error
	if operatorServer != nil {
		operatorErr = operatorServer.Shutdown(shutdownCtx)
	}
	stopGRPCServer(shutdownCtx, agentServer)

	if err != nil {
		return err
	}
	if healthErr != nil {
		return healthErr
	}
	return operatorErr
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}
