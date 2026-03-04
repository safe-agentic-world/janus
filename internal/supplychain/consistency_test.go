package supplychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseWorkflowAndDocsStayInSync(t *testing.T) {
	root := repoRoot(t)

	workflow := mustReadFile(t, filepath.Join(root, ".github", "workflows", "release.yml"))
	releaseVerification := mustReadFile(t, filepath.Join(root, "docs", "release-verification.md"))
	supplyChain := mustReadFile(t, filepath.Join(root, "docs", "supply-chain-security.md"))

	requiredWorkflowSnippets := []string{
		"go install github.com/anchore/syft/cmd/syft@v1.24.0",
		"go install github.com/sigstore/cosign/v2/cmd/cosign@v2.4.1",
		"dist/nomos-sbom.spdx.json",
		"dist/nomos-provenance.intoto.jsonl",
		"sign-blob --yes",
		"id-token: write",
	}
	for _, snippet := range requiredWorkflowSnippets {
		if !strings.Contains(workflow, snippet) {
			t.Fatalf("release workflow missing %q", snippet)
		}
	}

	requiredAssetNames := []string{
		"nomos-checksums.txt",
		"nomos-sbom.spdx.json",
		"nomos-provenance.intoto.jsonl",
		"nomos-linux-amd64.tar.gz",
	}
	for _, asset := range requiredAssetNames {
		if !strings.Contains(releaseVerification, asset) {
			t.Fatalf("release verification doc missing asset %q", asset)
		}
		if !strings.Contains(workflow, asset) && asset != "nomos-linux-amd64.tar.gz" {
			t.Fatalf("release workflow missing artifact reference %q", asset)
		}
	}

	requiredVerificationClaims := []string{
		"Sigstore keyless signing",
		"Fulcio",
		"Rekor",
		"https://token.actions.githubusercontent.com",
		"If any required file is missing, verification has failed",
		"An invalid signature or missing artifact means the release cannot be trusted",
		"policy.verify_signatures",
	}
	for _, snippet := range requiredVerificationClaims {
		if !strings.Contains(releaseVerification, snippet) {
			t.Fatalf("release verification doc missing %q", snippet)
		}
	}

	requiredSupplyChainClaims := []string{
		"SPDX JSON",
		"nomos-sbom.spdx.json",
		"nomos-provenance.intoto.jsonl",
		"https://slsa.dev/provenance/v1",
		"policy bundle trust remains separate from binary trust",
		"does not publish container images",
	}
	for _, snippet := range requiredSupplyChainClaims {
		if !strings.Contains(supplyChain, snippet) {
			t.Fatalf("supply-chain doc missing %q", snippet)
		}
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(dir, "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "TASKS.md")); err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}
