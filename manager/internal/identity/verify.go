package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrPeerIdentity = errors.New("untrusted agent identity")

// CertificateStatus is backed by the authoritative Manager database.
// Implementations must reject unknown, revoked, inactive, or expired records.
type CertificateStatus func(context.Context, string, string, [32]byte) error

type AgentPeer struct {
	ProjectID   string
	AgentID     string
	Fingerprint [32]byte
}

// VerifyAgentCertificate validates cryptographic identity and live Manager
// status, deriving project and Agent identity only from the signed URI SAN.
func VerifyAgentCertificate(ctx context.Context, der []byte, roots *x509.CertPool, at time.Time, status CertificateStatus) (AgentPeer, error) {
	var peer AgentPeer
	if roots == nil || status == nil || len(der) == 0 {
		return peer, ErrPeerIdentity
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return peer, ErrPeerIdentity
	}
	if _, err = cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: at,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return peer, fmt.Errorf("%w: certificate chain or usage", ErrPeerIdentity)
	}
	if cert.IsCA || len(cert.URIs) != 1 || len(cert.DNSNames) != 0 ||
		len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		return peer, ErrPeerIdentity
	}
	uri := cert.URIs[0]
	if uri.Scheme != "spiffe" || uri.Host != "alpha-pentas.local" ||
		uri.RawQuery != "" || uri.Fragment != "" || uri.User != nil {
		return peer, ErrPeerIdentity
	}

	parts := strings.Split(strings.TrimPrefix(uri.Path, "/"), "/")
	if len(parts) != 4 || parts[0] != "project" || parts[2] != "agent" ||
		!uuidRE.MatchString(parts[1]) || !uuidRE.MatchString(parts[3]) {
		return peer, ErrPeerIdentity
	}
	expectedPath := "/project/" + parts[1] + "/agent/" + parts[3]
	if uri.Path != expectedPath {
		return peer, ErrPeerIdentity
	}

	peer = AgentPeer{
		ProjectID:   parts[1],
		AgentID:     parts[3],
		Fingerprint: sha256.Sum256(der),
	}
	if err := status(ctx, peer.ProjectID, peer.AgentID, peer.Fingerprint); err != nil {
		return AgentPeer{}, fmt.Errorf("%w: certificate is not active", ErrPeerIdentity)
	}
	return peer, nil
}

// VerifyAgentPeer validates a certificate against an operation-scoped project.
// A verified TLS chain alone never grants application authorization.
func VerifyAgentPeer(ctx context.Context, der []byte, roots *x509.CertPool, expectedProject string, at time.Time, status CertificateStatus) (string, error) {
	if !uuidRE.MatchString(expectedProject) {
		return "", ErrPeerIdentity
	}
	peer, err := VerifyAgentCertificate(ctx, der, roots, at, status)
	if err != nil {
		return "", err
	}
	if peer.ProjectID != expectedProject {
		return "", ErrPeerIdentity
	}
	return peer.AgentID, nil
}
