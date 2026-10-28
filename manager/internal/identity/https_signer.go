package identity

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

var ErrRemoteSigner = errors.New("remote signer failure")

type HTTPSigner struct {
	endpoint *url.URL
	public   crypto.PublicKey
	client   *http.Client
}

type remoteSignRequest struct {
	Message string `json:"message"`
	Hash    string `json:"hash"`
}

type remoteSignResponse struct {
	Signature string `json:"signature"`
}

func NewHTTPSigner(endpoint string, public crypto.PublicKey, client *http.Client) (*HTTPSigner, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || public == nil || client == nil {
		return nil, ErrRemoteSigner
	}
	copied := *client
	copied.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("remote signer redirects are forbidden")
	}
	return &HTTPSigner{endpoint: u, public: public, client: &copied}, nil
}

func (s *HTTPSigner) Public() crypto.PublicKey {
	if s == nil {
		return nil
	}
	return s.public
}

func (s *HTTPSigner) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.SignContext(context.Background(), nil, message, opts)
}

func (s *HTTPSigner) SignContext(ctx context.Context, _ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if s == nil || s.client == nil || s.endpoint == nil || len(message) == 0 || opts == nil {
		return nil, ErrRemoteSigner
	}
	hashName := "none"
	if hash := opts.HashFunc(); hash != 0 {
		hashName = hash.String()
	}
	payload, err := json.Marshal(remoteSignRequest{
		Message: base64.RawStdEncoding.EncodeToString(message),
		Hash:    hashName,
	})
	if err != nil {
		return nil, ErrRemoteSigner
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, ErrRemoteSigner
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		return nil, ErrRemoteSigner
	}
	var out remoteSignResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 32*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil || out.Signature == "" {
		return nil, ErrRemoteSigner
	}
	signature, err := base64.RawStdEncoding.DecodeString(out.Signature)
	if err != nil || len(signature) == 0 || len(signature) > 16*1024 {
		return nil, ErrRemoteSigner
	}
	return signature, nil
}
