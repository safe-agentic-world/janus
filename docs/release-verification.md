# Release Verification

This document explains how to verify official Nomos release artifacts.

## Trust Root

Nomos release assets are signed with Sigstore keyless signing.

Verification trust root:

- Fulcio-issued signing certificate
- Rekor transparency log inclusion
- GitHub Actions OIDC identity for the Nomos release workflow

Expected signer identity:

- workflow: `.github/workflows/release.yml`
- repository: `safe-agentic-world/nomos`
- OIDC issuer: `https://token.actions.githubusercontent.com`

## Release Assets To Verify

At minimum, each official release publishes:

- `nomos-linux-amd64.tar.gz`
- `nomos-linux-arm64.tar.gz`
- `nomos-darwin-amd64.tar.gz`
- `nomos-darwin-arm64.tar.gz`
- `nomos-windows-amd64.zip`
- `nomos-windows-arm64.zip`
- `nomos-checksums.txt`
- `nomos-sbom.spdx.json`
- `nomos-provenance.intoto.jsonl`

Each signed asset also has:

- `<asset>.sig`
- `<asset>.pem`

Current note:

- the official release workflow publishes signed archives and signed metadata files
- the official release workflow does not publish container images, so image signature verification is not part of the current release path

## Prerequisites

- `cosign` installed locally
- the downloaded release assets in one directory

## 1. Verify Metadata Assets Exist

Before cryptographic verification, confirm these files are present:

- `nomos-checksums.txt`
- `nomos-checksums.txt.sig`
- `nomos-checksums.txt.pem`
- `nomos-sbom.spdx.json`
- `nomos-sbom.spdx.json.sig`
- `nomos-sbom.spdx.json.pem`
- `nomos-provenance.intoto.jsonl`
- `nomos-provenance.intoto.jsonl.sig`
- `nomos-provenance.intoto.jsonl.pem`

If any required file is missing, verification has failed and the release should be treated as untrusted.

## 2. Verify Signed Checksums

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/safe-agentic-world/nomos/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature nomos-checksums.txt.sig \
  --certificate nomos-checksums.txt.pem \
  nomos-checksums.txt
```

Then verify the target archive against the published checksum list:

```bash
sha256sum -c nomos-checksums.txt --ignore-missing
```

## 3. Verify An Individual Archive Signature

Example:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/safe-agentic-world/nomos/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature nomos-linux-amd64.tar.gz.sig \
  --certificate nomos-linux-amd64.tar.gz.pem \
  nomos-linux-amd64.tar.gz
```

## 4. Verify SBOM And Provenance Signatures

SBOM:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/safe-agentic-world/nomos/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature nomos-sbom.spdx.json.sig \
  --certificate nomos-sbom.spdx.json.pem \
  nomos-sbom.spdx.json
```

Provenance:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/safe-agentic-world/nomos/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature nomos-provenance.intoto.jsonl.sig \
  --certificate nomos-provenance.intoto.jsonl.pem \
  nomos-provenance.intoto.jsonl
```

## What Verification Failure Means

Treat verification as failed if:

- any expected artifact is missing
- `cosign verify-blob` returns a non-zero exit code
- the certificate identity does not match the expected release workflow
- the OIDC issuer is not `https://token.actions.githubusercontent.com`
- the archive digest does not match `nomos-checksums.txt`

An invalid signature or missing artifact means the release cannot be trusted as an official Nomos release.

## Binary Trust vs Policy Bundle Trust

Release verification answers:

- "Is this Nomos binary or archive an authentic official build?"

It does not answer:

- "Is the policy bundle loaded by this runtime trusted?"

Policy bundles remain a separate trust domain and should be verified with Nomos policy bundle verification controls (`policy.verify_signatures`) where enabled.
