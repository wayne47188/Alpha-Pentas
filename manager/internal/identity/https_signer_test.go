package identity

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPSignerSignsAndPropagatesContext(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatal("unexpected method")
		}
		var input remoteSignRequest
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		message, err := base64.RawStdEncoding.DecodeString(input.Message)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := private.Sign(rand.Reader, message, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(remoteSignResponse{Signature: base64.RawStdEncoding.EncodeToString(signature)})
	}))
	defer server.Close()

	signer, err := NewHTTPSigner(server.URL, public, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("certificate-tbs")
	signature, err := signer.SignContext(context.Background(), rand.Reader, message, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, message, signature) {
		t.Fatal("remote signature did not verify")
	}
}

func TestHTTPSignerHonorsCancellation(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	signer, err := NewHTTPSigner(server.URL, public, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = signer.SignContext(ctx, rand.Reader, []byte("blocked"), crypto.Hash(0))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want deadline exceeded", err)
	}
}

func TestHTTPSignerRejectsUnsafeEndpoint(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewHTTPSigner("http://signer.internal/v1/sign", public, http.DefaultClient); !errors.Is(err, ErrRemoteSigner) {
		t.Fatalf("plain HTTP accepted: %v", err)
	}
}
