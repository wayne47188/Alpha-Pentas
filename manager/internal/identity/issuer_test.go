package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

const project = "0199a7bd-1a34-71c8-8eed-b55555555555"
const agent = "0199a7bd-1a34-71c8-8eed-a66666666666"

func fixture(t *testing.T) (Issuer, []byte) {
	t.Helper()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
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
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted"}}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	return Issuer{CA: ca, Signer: caKey}, csrDER
}
func TestIssueAgentIdentity(t *testing.T) {
	issuer, csr := fixture(t)
	got, err := issuer.Issue(csr, project, agent, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(got.CertificateDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer.CA)
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != got.IdentityURI {
		t.Fatal("identity SAN mismatch")
	}
	if len(cert.DNSNames) != 0 || len(cert.IPAddresses) != 0 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("overprivileged certificate")
	}
}
func TestRejectBadCSRAndSAN(t *testing.T) {
	issuer, csr := fixture(t)
	csr[len(csr)-1] ^= 1
	if _, err := issuer.Issue(csr, project, agent, time.Hour); err == nil {
		t.Fatal("bad signature accepted")
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	uri, _ := url.Parse("spiffe://attacker.test/other")
	withSAN, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{uri}}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(withSAN, project, agent, time.Hour); err == nil {
		t.Fatal("untrusted SAN accepted")
	}
}
func TestRejectInvalidIdentity(t *testing.T) {
	issuer, csr := fixture(t)
	if _, err := issuer.Issue(csr, "not-uuid", agent, time.Hour); err == nil {
		t.Fatal("invalid project accepted")
	}
	if _, err := issuer.Issue(csr, project, agent, 8*24*time.Hour); err == nil {
		t.Fatal("excess lifetime accepted")
	}
}
