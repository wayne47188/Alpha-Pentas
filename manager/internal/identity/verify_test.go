package identity

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestVerifyAgentPeerRequiresActiveRecord(t *testing.T) {
	issuer, csr := fixture(t)
	issued, err := issuer.Issue(csr, project, agent, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer.CA)
	var called bool
	accept := func(_ context.Context, gotProject, gotAgent string, _ [32]byte) error {
		called = true
		if gotProject != project || gotAgent != agent {
			return errors.New("mismatched identity")
		}
		return nil
	}
	identity, err := VerifyAgentPeer(context.Background(), issued.CertificateDER, roots, project, time.Now(), accept)
	if err != nil || identity != agent || !called {
		t.Fatalf("verified identity %q error %v status called %v", identity, err, called)
	}
	if _, err := VerifyAgentPeer(context.Background(), issued.CertificateDER, roots, project, time.Now(), nil); !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("missing revocation checker allowed: %v", err)
	}
	reject := func(context.Context, string, string, [32]byte) error { return errors.New("revoked") }
	if _, err := VerifyAgentPeer(context.Background(), issued.CertificateDER, roots, project, time.Now(), reject); !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("revoked peer allowed: %v", err)
	}
}

func TestVerifyAgentPeerRejectsWrongScopeAndExpiry(t *testing.T) {
	issuer, csr := fixture(t)
	issued, err := issuer.Issue(csr, project, agent, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer.CA)
	allow := func(context.Context, string, string, [32]byte) error { return nil }
	other := "0199a7bd-1a34-71c8-8eed-111111111111"
	if _, err := VerifyAgentPeer(context.Background(), issued.CertificateDER, roots, other, time.Now(), allow); !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("cross-project peer allowed: %v", err)
	}
	if _, err := VerifyAgentPeer(context.Background(), issued.CertificateDER, roots, project, time.Now().Add(48*time.Hour), allow); !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("expired peer allowed: %v", err)
	}
	wrongRoots := x509.NewCertPool()
	if _, err := VerifyAgentPeer(context.Background(), issued.CertificateDER, wrongRoots, project, time.Now(), allow); !errors.Is(err, ErrPeerIdentity) {
		t.Fatalf("untrusted CA allowed: %v", err)
	}
}
