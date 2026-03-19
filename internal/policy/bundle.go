package policy

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
	"gopkg.in/yaml.v3"
)

type Bundle struct {
	Version       string         `json:"version" yaml:"version"`
	Rules         []Rule         `json:"rules" yaml:"rules"`
	Hash          string         `json:"-" yaml:"-"`
	SourceBundles []BundleSource `json:"-" yaml:"-"`
}

type Rule struct {
	ID           string         `json:"id" yaml:"id"`
	ActionType   string         `json:"action_type" yaml:"action_type"`
	Resource     string         `json:"resource" yaml:"resource"`
	Decision     string         `json:"decision" yaml:"decision"`
	Principals   []string       `json:"principals,omitempty" yaml:"principals,omitempty"`
	Agents       []string       `json:"agents,omitempty" yaml:"agents,omitempty"`
	Environments []string       `json:"environments,omitempty" yaml:"environments,omitempty"`
	RiskFlags    []string       `json:"risk_flags,omitempty" yaml:"risk_flags,omitempty"`
	ExecMatch    *ExecMatch     `json:"exec_match,omitempty" yaml:"exec_match,omitempty"`
	Obligations  map[string]any `json:"obligations,omitempty" yaml:"obligations,omitempty"`
	SourcePath   string         `json:"-" yaml:"-"`
	SourceHash   string         `json:"-" yaml:"-"`
}

type ExecMatch struct {
	ArgvPatterns [][]string `json:"argv_patterns,omitempty" yaml:"argv_patterns,omitempty"`
}

const obligationExecAllowlist = "exec_allowlist"

type BundleSource struct {
	Path              string `json:"path"`
	Hash              string `json:"hash"`
	Role              string `json:"role,omitempty"`
	SignatureVerified bool   `json:"signature_verified,omitempty"`
}

type LoadOptions struct {
	VerifySignature bool
	SignaturePath   string
	PublicKeyPath   string
}

const (
	ExecCompatibilityLegacyAllowlistFallback = "legacy_allowlist_fallback"
	ExecCompatibilityStrict                  = "strict"
)

func LoadBundle(path string) (Bundle, error) {
	return LoadBundleWithOptions(path, LoadOptions{})
}

func LoadBundleWithOptions(path string, options LoadOptions) (Bundle, error) {
	if path == "" {
		return Bundle{}, errors.New("bundle path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("read bundle: %w", err)
	}
	bundle, err := decodeBundle(data, path)
	if err != nil {
		return Bundle{}, err
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, err
	}
	if options.VerifySignature {
		if err := verifyBundleSignature(data, options.SignaturePath, options.PublicKeyPath); err != nil {
			return Bundle{}, err
		}
	}
	canonical, err := canonicalBundleBytes(bundle)
	if err != nil {
		return Bundle{}, fmt.Errorf("canonicalize bundle: %w", err)
	}
	bundle.Hash = canonicaljson.HashSHA256(canonical)
	return bundle, nil
}

func decodeBundle(data []byte, path string) (Bundle, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return decodeYAMLBundle(data)
	default:
		return decodeJSONBundle(data)
	}
}

func decodeJSONBundle(data []byte) (Bundle, error) {
	var bundle Bundle
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Bundle{}, errors.New("bundle contains trailing data")
	}
	return bundle, nil
}

func decodeYAMLBundle(data []byte) (Bundle, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if len(root.Content) == 0 {
		return Bundle{}, errors.New("decode bundle: empty yaml document")
	}
	if err := rejectDuplicateYAMLKeys(root.Content[0], "$"); err != nil {
		return Bundle{}, err
	}
	var bundle Bundle
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&bundle); err != nil {
		return Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Bundle{}, errors.New("bundle contains trailing data")
		}
		return Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	return bundle, nil
}

func rejectDuplicateYAMLKeys(node *yaml.Node, path string) error {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := rejectDuplicateYAMLKeys(child, path); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		seen := map[string]struct{}{}
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("decode bundle: duplicate yaml key %q at %s", key.Value, path)
			}
			seen[key.Value] = struct{}{}
			childPath := path + "." + key.Value
			if path == "$" {
				childPath = "$." + key.Value
			}
			if err := rejectDuplicateYAMLKeys(value, childPath); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for idx, child := range node.Content {
			if err := rejectDuplicateYAMLKeys(child, fmt.Sprintf("%s[%d]", path, idx)); err != nil {
				return err
			}
		}
	}
	return nil
}

func canonicalBundleBytes(bundle Bundle) ([]byte, error) {
	typed := bundle
	typed.Hash = ""
	encoded, err := json.Marshal(typed)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func verifyBundleSignature(bundleData []byte, signaturePath, publicKeyPath string) error {
	if signaturePath == "" || publicKeyPath == "" {
		return errors.New("signature and public key paths are required")
	}
	sigData, err := os.ReadFile(signaturePath)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	sigRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigData)))
	if err != nil {
		return errors.New("signature must be base64")
	}
	pubPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return errors.New("invalid public key pem")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return errors.New("invalid rsa public key")
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not rsa")
	}
	digest := sha256.Sum256(bundleData)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigRaw); err != nil {
		return errors.New("policy bundle signature verification failed")
	}
	return nil
}

func (b Bundle) Validate() error {
	if b.Version != "v1" {
		return errors.New("bundle version must be v1")
	}
	if len(b.Rules) == 0 {
		return errors.New("bundle rules are required")
	}
	seen := map[string]struct{}{}
	for _, rule := range b.Rules {
		if rule.ID == "" {
			return errors.New("rule id is required")
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if rule.ActionType == "" {
			return fmt.Errorf("rule %s missing action_type", rule.ID)
		}
		if rule.Resource == "" {
			return fmt.Errorf("rule %s missing resource", rule.ID)
		}
		if rule.Decision != DecisionAllow && rule.Decision != DecisionDeny && rule.Decision != DecisionRequireApproval {
			return fmt.Errorf("rule %s has invalid decision", rule.ID)
		}
		if rule.ExecMatch != nil {
			if rule.ActionType != "process.exec" && rule.ActionType != "*" {
				return fmt.Errorf("rule %s exec_match requires action_type process.exec or *", rule.ID)
			}
			if _, ok := rule.Obligations[obligationExecAllowlist]; ok {
				return fmt.Errorf("rule %s must not declare both exec_match and exec_allowlist", rule.ID)
			}
			if len(rule.ExecMatch.ArgvPatterns) == 0 {
				return fmt.Errorf("rule %s exec_match.argv_patterns is required", rule.ID)
			}
			for idx, pattern := range rule.ExecMatch.ArgvPatterns {
				if len(pattern) == 0 {
					return fmt.Errorf("rule %s exec_match.argv_patterns[%d] must not be empty", rule.ID, idx)
				}
				for tokenIdx, token := range pattern {
					if token == "" {
						return fmt.Errorf("rule %s exec_match.argv_patterns[%d][%d] must not be empty", rule.ID, idx, tokenIdx)
					}
				}
			}
		}
	}
	return nil
}

func NormalizeExecCompatibilityMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ExecCompatibilityLegacyAllowlistFallback:
		return ExecCompatibilityLegacyAllowlistFallback
	case ExecCompatibilityStrict:
		return ExecCompatibilityStrict
	default:
		return ""
	}
}

func ValidateExecCompatibility(bundle Bundle, mode string) error {
	normalizedMode := NormalizeExecCompatibilityMode(mode)
	if normalizedMode == "" {
		return fmt.Errorf("invalid exec compatibility mode %q", strings.TrimSpace(mode))
	}
	if normalizedMode != ExecCompatibilityStrict {
		return nil
	}
	for _, rule := range bundle.Rules {
		if rule.ActionType != "process.exec" && rule.ActionType != "*" {
			continue
		}
		if rule.Decision != DecisionAllow && rule.Decision != DecisionRequireApproval {
			continue
		}
		if _, ok := rule.Obligations[obligationExecAllowlist]; ok {
			return fmt.Errorf("rule %s uses legacy exec_allowlist but policy.exec_compatibility_mode=strict", rule.ID)
		}
	}
	return nil
}
