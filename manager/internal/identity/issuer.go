package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"time"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var ErrCSR = errors.New("invalid agent CSR")

// Issuer accepts a previously provisioned CA certificate and signer.
// CA private keys are never created or stored in the Agent.
type Issuer struct {
	CA     *x509.Certificate
	Signer crypto.Signer
	Now    func() time.Time
}

type Result struct {
	CertificateDER []byte
	Serial         string
	Fingerprint    [32]byte
	NotAfter       time.Time
	IdentityURI    string
}

func ValidateCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 || len(der) > 64*1024 {
		return nil, ErrCSR
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil {
		return nil, ErrCSR
	}
	switch k := csr.PublicKey.(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return nil, ErrCSR
		}
	case *ecdsa.PublicKey:
		if k.Curve == nil || k.Curve.Params().BitSize < 256 {
			return nil, ErrCSR
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, ErrCSR
		}
	default:
		return nil, ErrCSR
	}
	// The manager alone assigns the identity SAN.
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			return nil, ErrCSR
		}
	}
	if len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 || len(csr.EmailAddresses) != 0 {
		return nil, ErrCSR
	}
	return csr, nil
}

func (i Issuer) Issue(csrDER []byte, projectID, agentID string, validFor time.Duration) (Result, error) {
	var out Result
	if !uuidRE.MatchString(projectID) || !uuidRE.MatchString(agentID) || validFor <= 0 || validFor > 7*24*time.Hour {
		return out, errors.New("invalid identity or certificate lifetime")
	}
	if i.CA == nil || i.Signer == nil || !i.CA.IsCA || i.CA.KeyUsage&x509.KeyUsageCertSign == 0 {
		return out, errors.New("CA is not configured for signing")
	}
	if !publicKeysEqual(i.CA.PublicKey, i.Signer.Public()) {
		return out, errors.New("CA key does not match certificate")
	}
	csr, err := ValidateCSR(csrDER)
	if err != nil {
		return out, err
	}
	now := time.Now()
	if i.Now != nil {
		now = i.Now()
	}
	notBefore := now.Add(-time.Minute)
	notAfter := now.Add(validFor)
	if notAfter.After(i.CA.NotAfter) {
		return out, errors.New("requested validity exceeds CA lifetime")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if err != nil {
		return out, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	uri, err := url.Parse(fmt.Sprintf("spiffe://alpha-pentas.local/project/%s/agent/%s", projectID, agentID))
	if err != nil {
		return out, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: agentID}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true, URIs: []*url.URL{uri}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.CA, csr.PublicKey, i.Signer)
	if err != nil {
		return out, err
	}
	out = Result{CertificateDER: der, Serial: serial.String(), Fingerprint: sha256.Sum256(der), NotAfter: notAfter, IdentityURI: uri.String()}
	return out, nil
}

func publicKeysEqual(a, b any) bool {
	aa, e1 := x509.MarshalPKIXPublicKey(a)
	bb, e2 := x509.MarshalPKIXPublicKey(b)
	return e1 == nil && e2 == nil && sha256.Sum256(aa) == sha256.Sum256(bb)
}
