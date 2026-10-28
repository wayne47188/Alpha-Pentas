package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

var ErrAgentTLS = errors.New("agent TLS identity rejected")

type AgentTLSAuthenticator struct {
	Roots            *x509.CertPool
	Status           identity.CertificateStatus
	HandshakeTimeout time.Duration
	Now              func() time.Time
}

func NewAgentTLSAuthenticator(roots *x509.CertPool, status identity.CertificateStatus) (AgentTLSAuthenticator, error) {
	if roots == nil || status == nil {
		return AgentTLSAuthenticator{}, ErrAgentTLS
	}
	return AgentTLSAuthenticator{
		Roots:            roots,
		Status:           status,
		HandshakeTimeout: 3 * time.Second,
		Now:              time.Now,
	}, nil
}

func (a AgentTLSAuthenticator) authenticate(ctx context.Context, state tls.ConnectionState) (identity.AgentPeer, error) {
	var empty identity.AgentPeer
	if a.Roots == nil || a.Status == nil || len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return empty, ErrAgentTLS
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	peer, err := identity.VerifyAgentCertificate(ctx, state.PeerCertificates[0].Raw, a.Roots, now, a.Status)
	if err != nil {
		return empty, errors.Join(ErrAgentTLS, err)
	}
	return peer, nil
}

// TLSConfig rejects unknown, expired, wrong-EKU and DB-revoked Agent
// certificates during the handshake. gRPC can consume this config via its TLS
// transport credentials when the server scaffold is introduced.
func (a AgentTLSAuthenticator) TLSConfig(serverCertificate tls.Certificate) (*tls.Config, error) {
	if len(serverCertificate.Certificate) == 0 || a.Roots == nil || a.Status == nil ||
		a.HandshakeTimeout <= 0 || a.HandshakeTimeout > 10*time.Second {
		return nil, ErrAgentTLS
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    a.Roots.Clone(),
		NextProtos:   []string{"h2"},
		VerifyConnection: func(state tls.ConnectionState) error {
			ctx, cancel := context.WithTimeout(context.Background(), a.HandshakeTimeout)
			defer cancel()
			_, err := a.authenticate(ctx, state)
			return err
		},
	}, nil
}

// AuthorizeProject must run on every privileged Agent operation. It re-checks
// authoritative certificate state, so revocation after connection
// establishment is enforced without waiting for the TLS session to expire.
func (a AgentTLSAuthenticator) AuthorizeProject(ctx context.Context, state tls.ConnectionState, expectedProject string) (string, error) {
	peer, err := a.authenticate(ctx, state)
	if err != nil {
		return "", err
	}
	if peer.ProjectID != expectedProject {
		return "", ErrAgentTLS
	}
	return peer.AgentID, nil
}
