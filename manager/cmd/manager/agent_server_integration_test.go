package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	// Register lib/pq with database/sql for PostgreSQL integration tests.
	_ "github.com/lib/pq"
	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
	managertransport "github.com/wayne47188/Alpha-Pentas/manager/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type agentGRPCTestFixture struct {
	caFile     string
	serverCert string
	serverKey  string
	clientCert tls.Certificate
	clientDER  []byte
	roots      *x509.CertPool
	projectID  string
	agentID    string
}

func createAgentGRPCTestFixture(t *testing.T) agentGRPCTestFixture {
	t.Helper()
	dir := t.TempDir()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(300),
		Subject:               pkix.Name{CommonName: "Alpha Pentas Agent CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(2 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "agent-ca.pem")
	writePEM(t, caFile, "CERTIFICATE", caDER)

	_, serverKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(301),
		Subject:      pkix.Name{CommonName: "manager"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, serverKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	serverCertFile := filepath.Join(dir, "server.crt")
	serverKeyFile := filepath.Join(dir, "server.key")
	writePEM(t, serverCertFile, "CERTIFICATE", serverDER)
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, serverKeyFile, "PRIVATE KEY", serverKeyDER)

	projectID := "9b222222-2222-4222-8222-222222222222"
	agentID := "9b333333-3333-4333-8333-333333333333"
	_, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted"}}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := (identity.Issuer{CA: ca, Signer: caKey}).Issue(csr, projectID, agentID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return agentGRPCTestFixture{
		caFile:     caFile,
		serverCert: serverCertFile,
		serverKey:  serverKeyFile,
		clientCert: tls.Certificate{Certificate: [][]byte{issued.CertificateDER}, PrivateKey: agentKey},
		clientDER:  issued.CertificateDER,
		roots:      roots,
		projectID:  projectID,
		agentID:    agentID,
	}
}

func seedActiveAgentCertificate(t *testing.T, ctx context.Context, db *sql.DB, fixture agentGRPCTestFixture) string {
	t.Helper()
	tenantID := "9b111111-1111-4111-8111-111111111111"
	tokenID := "9b444444-4444-4444-8444-444444444444"
	certificateID := "9b555555-5555-4555-8555-555555555555"
	claimID := "9b666666-6666-4666-8666-666666666666"
	cert, err := x509.ParseCertificate(fixture.clientDER)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(fixture.clientDER)

	statements := []struct {
		query string
		args  []any
	}{
		{"INSERT INTO tenants(id,name) VALUES($1,'agent-grpc') ON CONFLICT(id) DO NOTHING", []any{tenantID}},
		{"INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'agent-grpc') ON CONFLICT(id) DO NOTHING", []any{fixture.projectID, tenantID}},
		{"INSERT INTO agents(id,project_id,state,enrolled_at) VALUES($1,$2,'active',now()) ON CONFLICT(id) DO UPDATE SET state='active',enrolled_at=now()", []any{fixture.agentID, fixture.projectID}},
		{"INSERT INTO enrollment_tokens(id,project_id,token_digest,expires_at,consumed_at,issued_by) VALUES($1,$2,decode(repeat('aa',32),'hex'),now()+interval '1 hour',now(),'grpc-test') ON CONFLICT(id) DO UPDATE SET consumed_at=now(),expires_at=now()+interval '1 hour'", []any{tokenID, fixture.projectID}},
		{"INSERT INTO agent_certificates(id,agent_id,issuer_key_id,serial_number,sha256_fingerprint,not_before,not_after,certificate_der) VALUES($1,$2,'grpc-test-ca',$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET revoked_at=NULL,certificate_der=EXCLUDED.certificate_der,sha256_fingerprint=EXCLUDED.sha256_fingerprint", []any{certificateID, fixture.agentID, cert.SerialNumber.String(), fingerprint[:], cert.NotBefore, cert.NotAfter, fixture.clientDER}},
		{"INSERT INTO enrollment_claims(id,token_id,project_id,agent_id,csr_sha256,state,issued_at,certificate_id) VALUES($1,$2,$3,$4,decode(repeat('bb',32),'hex'),'issued',now(),$5) ON CONFLICT(id) DO UPDATE SET state='issued',issued_at=now(),certificate_id=EXCLUDED.certificate_id", []any{claimID, tokenID, fixture.projectID, fixture.agentID, certificateID}},
	}
	for _, statement := range statements {
		if _, err = db.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return certificateID
}

func dialAgentManager(t *testing.T, address string, fixture agentGRPCTestFixture, withCertificate bool) *grpc.ClientConn {
	t.Helper()
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    fixture.roots,
		ServerName: "localhost",
	}
	if withCertificate {
		tlsConfig.Certificates = []tls.Certificate{fixture.clientCert}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		if withCertificate {
			t.Fatal(err)
		}
		return nil
	}
	if !withCertificate {
		_ = conn.Close()
		t.Fatal("Agent gRPC accepted client without certificate")
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func openManagerAgentStream(ctx context.Context, conn *grpc.ClientConn) (grpc.ClientStream, error) {
	return conn.NewStream(ctx,
		&grpc.StreamDesc{ServerStreams: true, ClientStreams: true},
		managertransport.AgentControlConnectMethod,
	)
}

func TestPostgresAgentGRPCMTLSIntegration(t *testing.T) {
	dsn := os.Getenv("ALPHA_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	fixture := createAgentGRPCTestFixture(t)
	certificateID := seedActiveAgentCertificate(t, ctx, db, fixture)

	server, serverDB, err := newAgentGRPCServer(ctx, agentGRPCConfig{
		Addr:                   "127.0.0.1:0",
		CertFile:               fixture.serverCert,
		KeyFile:                fixture.serverKey,
		ClientCAFile:           fixture.caFile,
		DatabaseURL:            dsn,
		SessionRecheckInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverDB.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn := dialAgentManager(t, listener.Addr().String(), fixture, true)

	wrongCtx, wrongCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer wrongCancel()
	wrongCtx = metadata.NewOutgoingContext(wrongCtx, metadata.Pairs(managertransport.ProjectMetadataKey, "9b777777-7777-4777-8777-777777777777"))
	wrongStream, err := openManagerAgentStream(wrongCtx, conn)
	if err == nil {
		err = wrongStream.SendMsg(&emptypb.Empty{})
	}
	if err == nil {
		err = wrongStream.RecvMsg(&emptypb.Empty{})
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-project gRPC error=%v", err)
	}

	streamCtx, streamCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer streamCancel()
	streamCtx = metadata.NewOutgoingContext(streamCtx, metadata.Pairs(managertransport.ProjectMetadataKey, fixture.projectID))
	stream, err := openManagerAgentStream(streamCtx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	if err = stream.RecvMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}

	if _, err = db.ExecContext(ctx, "UPDATE agent_certificates SET revoked_at=now() WHERE id=$1", certificateID); err != nil {
		t.Fatal(err)
	}
	revocationResult := make(chan error, 1)
	go func() {
		var message emptypb.Empty
		revocationResult <- stream.RecvMsg(&message)
	}()
	select {
	case err = <-revocationResult:
		if err == nil {
			t.Fatal("revoked Agent stream remained open")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("revoked Agent stream was not disconnected")
	}

	dialAgentManager(t, listener.Addr().String(), fixture, false)
}
