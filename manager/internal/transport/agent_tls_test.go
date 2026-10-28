package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

const testProject = "0199a7bd-1a34-71c8-8eed-b55555555555"
const testAgent = "0199a7bd-1a34-71c8-8eed-a66666666666"

func agentTLSFixture(t *testing.T) (*x509.CertPool, *x509.Certificate) {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Agent Test CA"},
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
	cert, err := x509.ParseCertificate(result.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots, cert
}

func TestAuthorizeProjectRechecksRevocation(t *testing.T) {
	roots, cert := agentTLSFixture(t)
	var revoked atomic.Bool
	status := func(context.Context, string, string, [32]byte) error {
		if revoked.Load() {
			return errors.New("revoked")
		}
		return nil
	}
	auth, err := NewAgentTLSAuthenticator(roots, status)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	agentID, err := auth.AuthorizeProject(context.Background(), state, testProject)
	if err != nil || agentID != testAgent {
		t.Fatalf("authorized agent=%q err=%v", agentID, err)
	}
	revoked.Store(true)
	if _, err = auth.AuthorizeProject(context.Background(), state, testProject); !errors.Is(err, ErrAgentTLS) {
		t.Fatalf("revoked established peer allowed: %v", err)
	}
}

func TestAuthorizeProjectRejectsCrossProject(t *testing.T) {
	roots, cert := agentTLSFixture(t)
	status := func(context.Context, string, string, [32]byte) error { return nil }
	auth, err := NewAgentTLSAuthenticator(roots, status)
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	otherProject := "0199a7bd-1a34-71c8-8eed-111111111111"
	if _, err = auth.AuthorizeProject(context.Background(), state, otherProject); !errors.Is(err, ErrAgentTLS) {
		t.Fatalf("cross-project Agent allowed: %v", err)
	}
}

func TestWatchSessionCancelsAfterRevocation(t *testing.T) {
	roots, cert := agentTLSFixture(t)
	var revoked atomic.Bool
	status := func(context.Context, string, string, [32]byte) error {
		if revoked.Load() {
			return errors.New("revoked")
		}
		return nil
	}
	auth, err := NewAgentTLSAuthenticator(roots, status)
	if err != nil {
		t.Fatal(err)
	}
	auth.SessionRecheckInterval = 100 * time.Millisecond
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	peer, err := auth.authenticate(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}

	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = auth.WatchSession(sessionCtx, peer, cancel); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	select {
	case <-sessionCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("revoked session was not cancelled")
	}
}
