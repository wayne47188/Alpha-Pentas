package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
	"github.com/wayne47188/Alpha-Pentas/manager/internal/enrollment"
	managertransport "github.com/wayne47188/Alpha-Pentas/manager/internal/transport"
	"google.golang.org/grpc"
)

type agentGRPCConfig struct {
	Addr                   string
	CertFile               string
	KeyFile                string
	ClientCAFile           string
	DatabaseURL            string
	SessionRecheckInterval time.Duration
}

func agentGRPCConfigFromEnv() (agentGRPCConfig, bool, error) {
	cfg := agentGRPCConfig{
		Addr:         os.Getenv("ALPHA_AGENT_GRPC_LISTEN"),
		CertFile:     os.Getenv("ALPHA_AGENT_TLS_CERT"),
		KeyFile:      os.Getenv("ALPHA_AGENT_TLS_KEY"),
		ClientCAFile: os.Getenv("ALPHA_AGENT_CLIENT_CA"),
		DatabaseURL:  os.Getenv("ALPHA_DATABASE_URL"),
	}
	enabled := cfg.Addr != "" || cfg.CertFile != "" || cfg.KeyFile != "" || cfg.ClientCAFile != ""
	if !enabled {
		return cfg, false, nil
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:9443"
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.ClientCAFile == "" || cfg.DatabaseURL == "" {
		return agentGRPCConfig{}, false, errors.New("Agent gRPC requires TLS cert, key, client CA and ALPHA_DATABASE_URL")
	}
	cfg.SessionRecheckInterval = 5 * time.Second
	return cfg, true, nil
}

func newAgentGRPCServer(ctx context.Context, cfg agentGRPCConfig) (*grpc.Server, *sql.DB, error) {
	serverCertificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load Agent gRPC server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("read Agent client CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("Agent client CA contains no certificates")
	}

	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("open Agent database: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("ping Agent database: %w", err)
	}

	authenticator, err := managertransport.NewAgentTLSAuthenticator(
		roots,
		(enrollment.SQLStore{DB: db}).CertificateStatus,
	)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	if cfg.SessionRecheckInterval > 0 {
		authenticator.SessionRecheckInterval = cfg.SessionRecheckInterval
	}
	options, err := authenticator.GRPCServerOptions(serverCertificate)
	if err != nil {
		db.Close()
		return nil, nil, err
	}

	server := grpc.NewServer(options...)
	managertransport.RegisterAgentControlServer(server, managertransport.BootstrapAgentControl{})
	return server, db, nil
}

func stopGRPCServer(ctx context.Context, server *grpc.Server) {
	if server == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		server.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		server.Stop()
		<-done
	}
}
