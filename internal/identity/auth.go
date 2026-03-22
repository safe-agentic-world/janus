package identity

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type Authenticator struct {
	config     AuthConfig
	oidcPubKey *rsa.PublicKey
}

func NewAuthenticator(config AuthConfig) (*Authenticator, error) {
	auth := &Authenticator{config: config}
	if config.OIDCEnabled {
		key, err := loadRSAPublicKeyFromPEM(config.OIDCPublicKeyPath)
		if err != nil {
			return nil, err
		}
		auth.oidcPubKey = key
	}
	return auth, nil
}

func (a *Authenticator) Verify(req *http.Request, body []byte) (VerifiedIdentity, error) {
	if a.config.Environment == "" {
		return VerifiedIdentity{}, errors.New("environment is required")
	}
	principal, err := a.verifyPrincipal(req, body)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	agent, err := a.verifyAgent(req, body)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	return VerifiedIdentity{
		Principal:   principal,
		Agent:       agent,
		Environment: a.config.Environment,
	}, nil
}

func (a *Authenticator) VerifyPrincipalOnly(req *http.Request) (string, error) {
	if principal, ok := a.verifyAPIKey(req); ok {
		return principal, nil
	}
	if principal, ok := a.verifySPIFFEIdentity(req); ok {
		return principal, nil
	}
	if principal, ok := a.verifyOIDCToken(req); ok {
		return principal, nil
	}
	return "", errors.New("principal authentication failed")
}

func (a *Authenticator) verifyPrincipal(req *http.Request, body []byte) (string, error) {
	if principal, ok := a.verifyAPIKey(req); ok {
		return principal, nil
	}
	if principal, ok := a.verifySPIFFEIdentity(req); ok {
		return principal, nil
	}
	if principal, ok := a.verifyOIDCToken(req); ok {
		return principal, nil
	}
	if principal, ok := a.verifyServiceSignature(req, body); ok {
		return principal, nil
	}
	return "", errors.New("principal authentication failed")
}

func (a *Authenticator) verifyAPIKey(req *http.Request) (string, bool) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	key := strings.TrimSpace(parts[1])
	if key == "" {
		return "", false
	}
	principal, ok := a.config.APIKeys[key]
	return principal, ok
}

func (a *Authenticator) verifyServiceSignature(req *http.Request, body []byte) (string, bool) {
	serviceID := strings.TrimSpace(req.Header.Get("X-Nomos-Service-Id"))
	signature := strings.TrimSpace(req.Header.Get("X-Nomos-Service-Signature"))
	if serviceID == "" || signature == "" {
		return "", false
	}
	secret, ok := a.config.ServiceSecrets[serviceID]
	if !ok {
		return "", false
	}
	expected := hmacSHA256Hex([]byte(secret), body)
	return serviceID, hmac.Equal([]byte(signature), []byte(expected))
}

func (a *Authenticator) verifySPIFFEIdentity(req *http.Request) (string, bool) {
	if !a.config.SPIFFEEnabled || strings.TrimSpace(a.config.SPIFFETrustDomain) == "" || req == nil || req.TLS == nil || len(req.TLS.PeerCertificates) == 0 {
		return "", false
	}
	wantPrefix := "spiffe://" + strings.TrimSpace(a.config.SPIFFETrustDomain) + "/"
	for _, uri := range req.TLS.PeerCertificates[0].URIs {
		if uri == nil {
			continue
		}
		if strings.HasPrefix(uri.String(), wantPrefix) {
			return uri.String(), true
		}
	}
	return "", false
}

type oidcClaims struct {
	Sub string `json:"sub"`
	jwt.RegisteredClaims
}

func (a *Authenticator) verifyOIDCToken(req *http.Request) (string, bool) {
	if !a.config.OIDCEnabled || a.oidcPubKey == nil {
		return "", false
	}
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	tokenString := strings.TrimSpace(parts[1])
	if tokenString == "" {
		return "", false
	}
	claims := &oidcClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	token, err := parser.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return a.oidcPubKey, nil
	})
	if err != nil || token == nil || !token.Valid {
		return "", false
	}
	if claims.Issuer != a.config.OIDCIssuer {
		return "", false
	}
	if !audienceContains(claims.Audience, a.config.OIDCAudience) {
		return "", false
	}
	if strings.TrimSpace(claims.Sub) == "" {
		return "", false
	}
	return claims.Sub, true
}

func audienceContains(audiences []string, wanted string) bool {
	for _, aud := range audiences {
		if aud == wanted {
			return true
		}
	}
	return false
}

func (a *Authenticator) verifyAgent(req *http.Request, body []byte) (string, error) {
	agentID := strings.TrimSpace(req.Header.Get("X-Nomos-Agent-Id"))
	signature := strings.TrimSpace(req.Header.Get("X-Nomos-Agent-Signature"))
	if agentID == "" || signature == "" {
		return "", errors.New("agent authentication failed")
	}
	secret, ok := a.config.AgentSecrets[agentID]
	if !ok {
		return "", errors.New("agent authentication failed")
	}
	expected := hmacSHA256Hex([]byte(secret), body)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return "", errors.New("agent authentication failed")
	}
	return agentID, nil
}

func hmacSHA256Hex(secret, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func loadRSAPublicKeyFromPEM(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid oidc public key pem")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		if key, ok := parsed.(*rsa.PublicKey); ok {
			return key, nil
		}
		return nil, errors.New("oidc public key is not rsa")
	}
	cert, certErr := x509.ParseCertificate(block.Bytes)
	if certErr == nil {
		if key, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return key, nil
		}
	}
	return nil, errors.New("invalid oidc public key material")
}
