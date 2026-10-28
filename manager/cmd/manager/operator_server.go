package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
	"github.com/wayne47188/Alpha-Pentas/manager/internal/authz"
	"github.com/wayne47188/Alpha-Pentas/manager/internal/enrollment"
	"github.com/wayne47188/Alpha-Pentas/manager/internal/operator"
)

type operatorServerConfig struct {
	Addr         string
	CertFile     string
	KeyFile      string
	ClientCAFile string
	DatabaseURL  string
}

func operatorConfigFromEnv() (operatorServerConfig, bool, error) {
	cfg := operatorServerConfig{
		Addr:         os.Getenv("ALPHA_OPERATOR_LISTEN"),
		CertFile:     os.Getenv("ALPHA_OPERATOR_TLS_CERT"),
		KeyFile:      os.Getenv("ALPHA_OPERATOR_TLS_KEY"),
		ClientCAFile: os.Getenv("ALPHA_OPERATOR_CLIENT_CA"),
		DatabaseURL:  os.Getenv("ALPHA_DATABASE_URL"),
	}
	enabled := cfg.Addr != "" || cfg.CertFile != "" || cfg.KeyFile != "" || cfg.ClientCAFile != ""
	if !enabled {
		return cfg, false, nil
	}
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8443"
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.ClientCAFile == "" || cfg.DatabaseURL == "" {
		return operatorServerConfig{}, false, errors.New("operator API requires TLS cert, key, client CA and ALPHA_DATABASE_URL")
	}
	return cfg, true, nil
}

func loadOperatorTLSConfig(cfg operatorServerConfig) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load operator server certificate: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read operator client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("operator client CA contains no certificates")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

func newOperatorServer(ctx context.Context, cfg operatorServerConfig) (*http.Server, *sql.DB, error) {
	tlsConfig, err := loadOperatorTLSConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("open operator database: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = db.PingContext(pingCtx); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("ping operator database: %w", err)
	}

	limiter, err := operator.NewFixedWindowLimiter(30, time.Minute)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	service := operator.EnrollmentService{
		Authorization: authz.Authorizer{Grants: authz.PostgresGrants{DB: db}},
		Tokens:        enrollment.SQLStore{DB: db},
	}
	resolver := operator.PostgresPrincipalResolver{DB: db}
	audit := operator.PostgresDenialAudit{DB: db}

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/projects/{projectID}/enrollment-tokens",
		operator.RequireVerifiedOperator(
			resolver,
			operator.NewEnrollmentTokenHandler(service, limiter, audit),
		),
	)
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server, db, nil
}
