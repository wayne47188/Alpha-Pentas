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

// VerifyAgentPeer validates cryptographic identity AND live Manager status.
// A verified TLS chain alone never grants application authorization.
func VerifyAgentPeer(ctx context.Context, der []byte, roots *x509.CertPool, expectedProject string, at time.Time, status CertificateStatus) (string, error) {
	if roots == nil || status == nil || !uuidRE.MatchString(expectedProject) || len(der) == 0 {
		return "", ErrPeerIdentity
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", ErrPeerIdentity
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return "", fmt.Errorf("%w: certificate chain or usage", ErrPeerIdentity)
	}
	if cert.IsCA || len(cert.URIs) != 1 || len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.EmailAddresses) != 0 {
		return "", ErrPeerIdentity
	}
	uri := cert.URIs[0]
	if uri.Scheme != "spiffe" || uri.Host != "alpha-pentas.local" || uri.RawQuery != "" || uri.Fragment != "" || uri.User != nil {
		return "", ErrPeerIdentity
	}
	prefix := "/project/" + expectedProject + "/agent/"
	if !strings.HasPrefix(uri.Path, prefix) {
		return "", ErrPeerIdentity
	}
	agentID := strings.TrimPrefix(uri.Path, prefix)
	if !uuidRE.MatchString(agentID) || uri.Path != prefix+agentID {
		return "", ErrPeerIdentity
	}
	digest := sha256.Sum256(der)
	if err := status(ctx, expectedProject, agentID, digest); err != nil {
		return "", fmt.Errorf("%w: certificate is not active", ErrPeerIdentity)
	}
	return agentID, nil
}
