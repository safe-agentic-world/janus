package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/safe-agentic-world/nomos/internal/canonicaljson"
)

const mergeAlgorithmVersion = "nomos.policy.merge.v1"

type MultiLoadOptions struct {
	VerifySignatures bool
	SignaturePaths   []string
	PublicKeyPath    string
	BundleRoles      []string
}

func LoadBundles(paths []string) (Bundle, error) {
	return LoadBundlesWithOptions(paths, MultiLoadOptions{})
}

func LoadBundlesWithOptions(paths []string, options MultiLoadOptions) (Bundle, error) {
	normalized := make([]string, 0, len(paths))
	for _, path := range paths {
		trimmed := strings.TrimSpace(path)
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	if len(normalized) == 0 {
		return Bundle{}, errors.New("at least one bundle path is required")
	}
	if len(options.BundleRoles) > 0 && len(options.BundleRoles) != len(normalized) {
		return Bundle{}, errors.New("policy_bundle_roles must match policy_bundle_paths when provided")
	}
	if len(normalized) == 1 {
		loadOptions := LoadOptions{
			VerifySignature: options.VerifySignatures,
			PublicKeyPath:   options.PublicKeyPath,
		}
		if len(options.SignaturePaths) > 0 {
			loadOptions.SignaturePath = options.SignaturePaths[0]
		}
		bundle, err := LoadBundleWithOptions(normalized[0], loadOptions)
		if err != nil {
			return Bundle{}, err
		}
		role := ""
		if len(options.BundleRoles) > 0 {
			role = strings.TrimSpace(options.BundleRoles[0])
		}
		bundle.SourceBundles = []BundleSource{{
			Path:              normalized[0],
			Hash:              bundle.Hash,
			Role:              role,
			SignatureVerified: options.VerifySignatures,
		}}
		return bundle, nil
	}
	if options.VerifySignatures && len(options.SignaturePaths) != len(normalized) {
		return Bundle{}, errors.New("signature_paths must match policy_bundle_paths when policy.verify_signatures is true")
	}
	merged := Bundle{
		Version:       "v1",
		Rules:         make([]Rule, 0),
		SourceBundles: make([]BundleSource, 0, len(normalized)),
	}
	seenRuleIDs := map[string]string{}
	inputHashes := make([]string, 0, len(normalized))
	for idx, path := range normalized {
		loadOptions := LoadOptions{
			VerifySignature: options.VerifySignatures,
			PublicKeyPath:   options.PublicKeyPath,
		}
		if options.VerifySignatures {
			loadOptions.SignaturePath = options.SignaturePaths[idx]
		}
		bundle, err := LoadBundleWithOptions(path, loadOptions)
		if err != nil {
			return Bundle{}, fmt.Errorf("load bundle %s: %w", path, err)
		}
		role := ""
		if len(options.BundleRoles) > 0 {
			role = strings.TrimSpace(options.BundleRoles[idx])
		}
		merged.SourceBundles = append(merged.SourceBundles, BundleSource{
			Path:              path,
			Hash:              bundle.Hash,
			Role:              role,
			SignatureVerified: options.VerifySignatures,
		})
		inputHashes = append(inputHashes, bundle.Hash)
		for _, rule := range bundle.Rules {
			if existing, ok := seenRuleIDs[rule.ID]; ok {
				return Bundle{}, fmt.Errorf("duplicate rule id %q across bundles %s and %s", rule.ID, existing, path)
			}
			rule.SourcePath = path
			rule.SourceHash = bundle.Hash
			merged.Rules = append(merged.Rules, rule)
			seenRuleIDs[rule.ID] = path
		}
	}
	hash, err := mergedBundleHash(inputHashes)
	if err != nil {
		return Bundle{}, err
	}
	merged.Hash = hash
	return merged, nil
}

func mergedBundleHash(inputHashes []string) (string, error) {
	payload := map[string]any{
		"merge_algorithm_version": mergeAlgorithmVersion,
		"bundle_hashes":           inputHashes,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	canonical, err := canonicaljson.Canonicalize(data)
	if err != nil {
		return "", err
	}
	return canonicaljson.HashSHA256(canonical), nil
}

func BundleSourceLabels(bundle Bundle) []string {
	return policyBundleSources(bundle)
}
