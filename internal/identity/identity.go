package identity

type VerifiedIdentity struct {
	Principal   string
	Agent       string
	Environment string
}

type AuthConfig struct {
	APIKeys           map[string]string
	ServiceSecrets    map[string]string
	AgentSecrets      map[string]string
	Environment       string
	OIDCEnabled       bool
	OIDCIssuer        string
	OIDCAudience      string
	OIDCPublicKeyPath string
	SPIFFEEnabled     bool
	SPIFFETrustDomain string
}
