package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

type tlsFixture struct {
	serverCert string
	serverKey  string
	caCert     string
	clientCert tlsCertificatePair
	clientDER  []byte
}

type tlsCertificatePair struct {
	certFile string
	keyFile  string
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func createTLSFixture(t *testing.T) tlsFixture {
	t.Helper()
	dir := t.TempDir()
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Alpha Pentas Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
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
	caPath := filepath.Join(dir, "ca.pem")
	writePEM(t, caPath, "CERTIFICATE", caDER)

	makeLeaf := func(name string, serial int64, usages []x509.ExtKeyUsage, ips []net.IP) (string, string, []byte) {
		_, key, keyErr := ed25519.GenerateKey(rand.Reader)
		if keyErr != nil {
			t.Fatal(keyErr)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    now.Add(-time.Minute),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  usages,
			IPAddresses:  ips,
		}
		der, createErr := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if createErr != nil {
			t.Fatal(createErr)
		}
		certPath := filepath.Join(dir, name+".crt")
		keyPath := filepath.Join(dir, name+".key")
		writePEM(t, certPath, "CERTIFICATE", der)
		keyBytes, marshalErr := x509.MarshalPKCS8PrivateKey(key)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		writePEM(t, keyPath, "PRIVATE KEY", keyBytes)
		return certPath, keyPath, der
	}

	serverCert, serverKey, _ := makeLeaf("server", 2, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")})
	clientCert, clientKey, clientDER := makeLeaf("operator", 3, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	return tlsFixture{
		serverCert: serverCert,
		serverKey:  serverKey,
		caCert:     caPath,
		clientCert: tlsCertificatePair{certFile: clientCert, keyFile: clientKey},
		clientDER:  clientDER,
	}
}

func TestPostgresOperatorMTLSIntegration(t *testing.T) {
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
	tenant := "9a111111-1111-4111-8111-111111111111"
	project := "9a222222-2222-4222-8222-222222222222"
	if _, err = db.ExecContext(ctx, "INSERT INTO tenants(id,name) VALUES($1,'mtls-test') ON CONFLICT(id) DO NOTHING", tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, "INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'mtls-test') ON CONFLICT(id) DO NOTHING", project, tenant); err != nil {
		t.Fatal(err)
	}

	fixture := createTLSFixture(t)
	fingerprint := sha256.Sum256(fixture.clientDER)
	if _, err = db.ExecContext(ctx, `INSERT INTO operator_identities(certificate_sha256,operator_id,tenant_id,state)
 VALUES($1,'mtls-operator',$2,'active')
 ON CONFLICT(certificate_sha256) DO UPDATE SET operator_id=EXCLUDED.operator_id,tenant_id=EXCLUDED.tenant_id,state='active',revoked_at=NULL`,
		fingerprint[:], tenant); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO operator_grants(operator_id,tenant_id,project_id,action)
 VALUES('mtls-operator',$1,$2,'enrollment.token.issue')
 ON CONFLICT(operator_id,tenant_id,project_id,action) DO UPDATE SET revoked_at=NULL`, tenant, project); err != nil {
		t.Fatal(err)
	}

	server, serverDB, err := newOperatorServer(ctx, operatorServerConfig{
		Addr:         "127.0.0.1:0",
		CertFile:     fixture.serverCert,
		KeyFile:      fixture.serverKey,
		ClientCAFile: fixture.caCert,
		DatabaseURL:  dsn,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverDB.Close()

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.ServeTLS(listener, "", "")
	}()
	defer func() {
		shutdown, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
		select {
		case serveErr := <-serverErr:
			if serveErr != nil && serveErr != http.ErrServerClosed {
				t.Errorf("operator server: %v", serveErr)
			}
		case <-time.After(time.Second):
			t.Error("operator server did not stop")
		}
	}()

	caPEM, err := os.ReadFile(fixture.caCert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA rejected")
	}
	clientPair, err := tls.LoadX509KeyPair(fixture.clientCert.certFile, fixture.clientCert.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: []tls.Certificate{clientPair},
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	endpoint := "https://" + listener.Addr().String() + "/api/v1/projects/" + project + "/enrollment-tokens"

	request := func() *http.Response {
		t.Helper()
		body, _ := json.Marshal(map[string]int{"ttl_seconds": 60})
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Operator-ID", "attacker")
		response, requestErr := client.Do(req)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response
	}

	if response := request(); response.StatusCode != http.StatusCreated {
		t.Fatalf("authorized status=%d", response.StatusCode)
	}
	if _, err = db.ExecContext(ctx, `UPDATE operator_identities
 SET state='revoked',revoked_at=now() WHERE certificate_sha256=$1`, fingerprint[:]); err != nil {
		t.Fatal(err)
	}
	if response := request(); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked operator status=%d, want 401", response.StatusCode)
	}

	noCertClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}}, Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(`{"ttl_seconds":60}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = noCertClient.Do(req); err == nil {
		t.Fatal("mTLS listener accepted client without certificate")
	}
}
