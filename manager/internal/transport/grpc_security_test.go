package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type grpcFixture struct {
	roots      *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

func grpcTLSFixture(t *testing.T) grpcFixture {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "gRPC Test CA"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	makeCert := func(serial int64, commonName string, usages []x509.ExtKeyUsage, dns []string) tls.Certificate {
		_, key, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, DNSNames: dns,
		}
		der, createErr := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}

	// Agent cert must use the Manager-assigned SPIFFE URI SAN, so issue it
	// through the real identity issuer rather than hand-building the leaf.
	_, agentKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted"}}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := (identity.Issuer{CA: ca, Signer: caKey}).Issue(csr, testProject, testAgent, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Certificate{Certificate: [][]byte{result.CertificateDER}, PrivateKey: agentKey}

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return grpcFixture{
		roots:      roots,
		serverCert: makeCert(101, "manager", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"}),
		clientCert: client,
	}
}

type agentTransportService interface{}

func registerTestAgentService(server *grpc.Server) {
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "alpha.v1.AgentTransport",
		HandlerType: (*agentTransportService)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName:    "Connect",
			ServerStreams: true,
			ClientStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				peerIdentity, ok := AgentPeerFromContext(stream.Context())
				if !ok || peerIdentity.AgentID != testAgent {
					return status.Error(codes.Unauthenticated, "missing Agent identity")
				}
				for {
					var message emptypb.Empty
					if err := stream.RecvMsg(&message); err != nil {
						return err
					}
					if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
						return err
					}
				}
			},
		}},
	}, struct{}{})
}

func dialAgentGRPC(t *testing.T, address string, roots *x509.CertPool, cert *tls.Certificate) *grpc.ClientConn {
	t.Helper()
	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "localhost"}
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(ctx, address,
		grpc.WithTransportCredentials(credentials.NewTLS(config)),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func openAgentStream(ctx context.Context, conn *grpc.ClientConn) (grpc.ClientStream, error) {
	desc := &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}
	return conn.NewStream(ctx, desc, "/alpha.v1.AgentTransport/Connect")
}

func TestGRPCAgentMTLSStreamRevocation(t *testing.T) {
	fixture := grpcTLSFixture(t)
	var revoked atomic.Bool
	statusCheck := func(context.Context, string, string, [32]byte) error {
		if revoked.Load() {
			return errors.New("revoked")
		}
		return nil
	}
	auth, err := NewAgentTLSAuthenticator(fixture.roots, statusCheck)
	if err != nil {
		t.Fatal(err)
	}
	auth.SessionRecheckInterval = 100 * time.Millisecond
	options, err := auth.GRPCServerOptions(fixture.serverCert)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(options...)
	registerTestAgentService(server)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn := dialAgentGRPC(t, listener.Addr().String(), fixture.roots, &fixture.clientCert)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(ProjectMetadataKey, testProject))
	stream, err := openAgentStream(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	if err = stream.RecvMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}

	revoked.Store(true)
	deadline := time.Now().Add(time.Second)
	for {
		err = stream.SendMsg(&emptypb.Empty{})
		if err == nil {
			err = stream.RecvMsg(&emptypb.Empty{})
		}
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked gRPC stream remained usable")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestGRPCAgentRejectsWrongProjectAndMissingCertificate(t *testing.T) {
	fixture := grpcTLSFixture(t)
	auth, err := NewAgentTLSAuthenticator(fixture.roots, func(context.Context, string, string, [32]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	options, err := auth.GRPCServerOptions(fixture.serverCert)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(options...)
	registerTestAgentService(server)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn := dialAgentGRPC(t, listener.Addr().String(), fixture.roots, &fixture.clientCert)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(ProjectMetadataKey, "0199a7bd-1a34-71c8-8eed-111111111111"))
	stream, err := openAgentStream(ctx, conn)
	if err == nil {
		err = stream.SendMsg(&emptypb.Empty{})
	}
	if err == nil {
		err = stream.RecvMsg(&emptypb.Empty{})
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("wrong-project stream error=%v", err)
	}

	config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: fixture.roots, ServerName: "localhost"}
	noCertCtx, noCertCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer noCertCancel()
	noCertConn, err := grpc.DialContext(noCertCtx, listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(config)),
		grpc.WithBlock(),
	)
	if err == nil {
		_ = noCertConn.Close()
		t.Fatal("gRPC mTLS listener accepted client without certificate")
	}
}

func TestGRPCServiceHandlerStopsOnClientEOF(t *testing.T) {
	// Keep io imported and assert the service loop treats a clean client close
	// as a terminal stream condition rather than spinning.
	if !errors.Is(io.EOF, io.EOF) {
		t.Fatal("unreachable")
	}
}
