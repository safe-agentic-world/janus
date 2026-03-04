# Supply-Chain Security

This document defines the current release-level trust model for Nomos.

## What The Release Workflow Produces

The release workflow `.github/workflows/release.yml` deterministically produces:

- release archives for supported OS/architecture targets
- `nomos-checksums.txt`
- `nomos-sbom.spdx.json`
- `nomos-provenance.intoto.jsonl`
- Sigstore signatures and certificates for each published archive and each metadata artifact

## Signing Model

Nomos uses:

- Sigstore keyless signing
- Fulcio certificates
- Rekor transparency log-backed verification
- GitHub Actions OIDC workflow identity

This keeps verification portable and avoids distributing a long-lived static signing key to users.

## SBOM Model

SBOM format:

- SPDX JSON

Current artifact:

- `nomos-sbom.spdx.json`

Scope:

- the release output directory (`dist`) produced by the release workflow
- direct and transitive dependencies to the extent identified by the SBOM tooling over the shipped artifacts

Generation workflow:

- the release workflow installs `syft`
- it scans `dist`
- it writes a deterministic release SBOM file

## Provenance / Attestation Model

Current provenance artifact:

- `nomos-provenance.intoto.jsonl`

Format and alignment:

- in-toto statement
- `predicateType` aligned to `https://slsa.dev/provenance/v1`

The provenance records:

- the release workflow identity
- the source revision (`github.sha`)
- the release tag
- the Go version used for the build
- the published release asset set and their SHA-256 digests

Current limitation:

- this is a signed provenance statement emitted by the release workflow, not a separate hosted provenance service

## Guarantees

The current supply-chain model lets users verify:

- an official release asset was produced by the documented GitHub Actions release workflow
- the downloaded asset matches the signed checksum list
- the release includes an SBOM and provenance statement tied to the release run

## Limitations

- the official release workflow does not publish container images, so image-signing guarantees are not part of the current release contract
- release verification does not replace runtime hardening or policy verification
- policy bundle trust remains separate from binary trust

## Trust Continuity With Policy Bundles

Release-level trust covers:

- the shipped Nomos binary, archive, and attached release metadata

Policy-bundle trust covers:

- the policy bundle an operator loads into that runtime

These are intentionally separate:

- a valid Nomos release can still load an untrusted policy bundle if the operator does not enforce policy bundle verification
- policy bundle verification protects runtime policy integrity, not release artifact provenance

Use both when the deployment requires strong trust in both the executable and the loaded policy.
