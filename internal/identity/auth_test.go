package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestAuthenticatorAPIKeyAndAgent(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{
		APIKeys: map[string]string{
			"key1": "principal1",
		},
		AgentSecrets: map[string]string{
			"agent1": "secret1",
		},
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	body := []byte(`{"schema_version":"v1","action_id":"act1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Nomos-Agent-Id", "agent1")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("secret1", body))

	id, err := auth.Verify(req, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Principal != "principal1" || id.Agent != "agent1" || id.Environment != "dev" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestAuthenticatorServiceSignature(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{
		ServiceSecrets: map[string]string{
			"service1": "svc-secret",
		},
		AgentSecrets: map[string]string{
			"agent1": "agent-secret",
		},
		Environment: "prod",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	body := []byte(`{"schema_version":"v1","action_id":"act1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.Header.Set("X-Nomos-Service-Id", "service1")
	req.Header.Set("X-Nomos-Service-Signature", hmacHex("svc-secret", body))
	req.Header.Set("X-Nomos-Agent-Id", "agent1")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("agent-secret", body))

	id, err := auth.Verify(req, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Principal != "service1" || id.Agent != "agent1" || id.Environment != "prod" {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

func TestAuthenticatorRejectsMissingAgent(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{
		APIKeys: map[string]string{
			"key1": "principal1",
		},
		AgentSecrets: map[string]string{
			"agent1": "secret1",
		},
		Environment: "dev",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	body := []byte(`{"schema_version":"v1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	req.Header.Set("Authorization", "Bearer key1")
	_, err = auth.Verify(req, body)
	if err == nil {
		t.Fatal("expected agent auth failure")
	}
}

func TestAuthenticatorSPIFFEIdentity(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{
		SPIFFEEnabled:     true,
		SPIFFETrustDomain: "example.org",
		AgentSecrets: map[string]string{
			"agent1": "secret1",
		},
		Environment: "prod",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	body := []byte(`{"schema_version":"v1","action_id":"act1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	spiffeID, _ := url.Parse("spiffe://example.org/workload/nomos")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			URIs: []*url.URL{spiffeID},
		}},
	}
	req.Header.Set("X-Nomos-Agent-Id", "agent1")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("secret1", body))

	id, err := auth.Verify(req, body)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Principal != "spiffe://example.org/workload/nomos" {
		t.Fatalf("unexpected SPIFFE principal: %+v", id)
	}
}

func TestAuthenticatorRejectsMismatchedSPIFFETrustDomain(t *testing.T) {
	auth, err := NewAuthenticator(AuthConfig{
		SPIFFEEnabled:     true,
		SPIFFETrustDomain: "example.org",
		AgentSecrets: map[string]string{
			"agent1": "secret1",
		},
		Environment: "prod",
	})
	if err != nil {
		t.Fatalf("new auth: %v", err)
	}
	body := []byte(`{"schema_version":"v1","action_id":"act1"}`)
	req := httptest.NewRequest(http.MethodPost, "/action", nil)
	spiffeID, _ := url.Parse("spiffe://other.org/workload/nomos")
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{
			URIs: []*url.URL{spiffeID},
		}},
	}
	req.Header.Set("X-Nomos-Agent-Id", "agent1")
	req.Header.Set("X-Nomos-Agent-Signature", hmacHex("secret1", body))
	_, err = auth.Verify(req, body)
	if err == nil {
		t.Fatal("expected principal authentication failure")
	}
}

func hmacHex(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
