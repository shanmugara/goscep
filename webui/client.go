package webui

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Signer submits a CSR and returns the issued certificate PEM.
type Signer interface {
	Sign(ctx context.Context, csrPEM []byte, username string) ([]byte, error)
}

// RejectedError means goscep refused the CSR (4xx); its message is safe to show the user.
type RejectedError struct {
	Status  int
	Message string
}

func (e *RejectedError) Error() string {
	return fmt.Sprintf("goscep rejected the request (%d): %s", e.Status, e.Message)
}

// GoscepClient calls goscep's client-certificate port (8443) using the web UI's own
// client certificate, whose CN must be in goscep's allowedcns.yaml.
type GoscepClient struct {
	url  string
	http *http.Client
}

func NewGoscepClient(url, certFile, keyFile, caFile string) (*GoscepClient, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load goscep client certificate and key: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no certificates found in %s", caFile)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
			MinVersion:   tls.VersionTLS12,
		},
	}
	return &GoscepClient{url: url, http: &http.Client{Transport: transport, Timeout: 30 * time.Second}}, nil
}

func (g *GoscepClient) Sign(ctx context.Context, csrPEM []byte, username string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.url, bytes.NewReader(csrPEM))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	// informational only: goscep authenticates the web UI, not the end user
	req.Header.Set("X-Goscep-User", username)

	resp, err := g.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("goscep request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read goscep response: %w", err)
	}
	var out struct {
		Certificate string `json:"certificate"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("goscep returned %s with an unreadable body", resp.Status)
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		msg := out.Error
		if msg == "" {
			msg = resp.Status
		}
		return nil, &RejectedError{Status: resp.StatusCode, Message: msg}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("goscep returned %s: %s", resp.Status, out.Error)
	}
	if out.Certificate == "" {
		return nil, errors.New("goscep returned no certificate")
	}
	return []byte(out.Certificate), nil
}
