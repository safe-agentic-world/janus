#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required environment variable: ${name}" >&2
    exit 1
  fi
}

require_env "PACKAGES_REPO_TOKEN"
require_env "RELEASE_TAG"
require_env "SOURCE_REPOSITORY"
require_env "CHECKSUM_FILE"

if [[ ! -f "${CHECKSUM_FILE}" ]]; then
  echo "checksum file not found: ${CHECKSUM_FILE}" >&2
  exit 1
fi

HOMEBREW_REPO="${HOMEBREW_REPO:-safe-agentic-world/homebrew-nomos}"
SCOOP_REPO="${SCOOP_REPO:-safe-agentic-world/scoop-nomos}"
AUTHOR_NAME="${GIT_AUTHOR_NAME:-nomos-release-bot}"
AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-nomos-release-bot@users.noreply.github.com}"
VERSION="${RELEASE_TAG#v}"
BASE_URL="https://github.com/${SOURCE_REPOSITORY}/releases/download/${RELEASE_TAG}"

lookup_sha() {
  local artifact="$1"
  awk -v wanted="${artifact}" '$2 == wanted { print $1 }' "${CHECKSUM_FILE}"
}

DARWIN_AMD64_SHA="$(lookup_sha nomos-darwin-amd64.tar.gz)"
DARWIN_ARM64_SHA="$(lookup_sha nomos-darwin-arm64.tar.gz)"
WINDOWS_AMD64_SHA="$(lookup_sha nomos-windows-amd64.zip)"
WINDOWS_ARM64_SHA="$(lookup_sha nomos-windows-arm64.zip)"

for value_name in DARWIN_AMD64_SHA DARWIN_ARM64_SHA WINDOWS_AMD64_SHA WINDOWS_ARM64_SHA; do
  if [[ -z "${!value_name}" ]]; then
    echo "missing checksum for ${value_name}" >&2
    exit 1
  fi
done

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

clone_repo() {
  local repo="$1"
  local target_dir="$2"
  local repo_url
  repo_url="https://x-access-token:${PACKAGES_REPO_TOKEN}@github.com/${repo}.git"
  git clone --depth 1 "${repo_url}" "${target_dir}"
}

commit_and_push_repo() {
  local repo_dir="$1"
  local commit_subject="$2"

  cd "${repo_dir}"
  git config user.name "${AUTHOR_NAME}"
  git config user.email "${AUTHOR_EMAIL}"

  if git diff --cached --quiet; then
    echo "repository already up to date: ${repo_dir}"
    return
  fi

  git commit -m "${commit_subject}"
  git push origin HEAD:main
}

clone_repo "${HOMEBREW_REPO}" "${workdir}/homebrew-repo"
clone_repo "${SCOOP_REPO}" "${workdir}/scoop-repo"

cd "${workdir}/homebrew-repo"
mkdir -p Formula

cat > Formula/nomos.rb <<EOF
class Nomos < Formula
  desc "Zero-trust control plane for AI agent side effects"
  homepage "https://github.com/${SOURCE_REPOSITORY}"
  version "${VERSION}"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "${BASE_URL}/nomos-darwin-arm64.tar.gz"
      sha256 "${DARWIN_ARM64_SHA}"
    else
      url "${BASE_URL}/nomos-darwin-amd64.tar.gz"
      sha256 "${DARWIN_AMD64_SHA}"
    end
  end

  def install
    bin.install "nomos"
  end

  test do
    assert_match "version=", shell_output("#{bin}/nomos version")
  end
end
EOF

git add Formula/nomos.rb
commit_and_push_repo "${workdir}/homebrew-repo" "nomos ${RELEASE_TAG}"

cd "${workdir}/scoop-repo"
mkdir -p bucket

cat > bucket/nomos.json <<EOF
{
  "version": "${VERSION}",
  "description": "Zero-trust control plane for AI agent side effects",
  "homepage": "https://github.com/${SOURCE_REPOSITORY}",
  "license": "Apache-2.0",
  "architecture": {
    "64bit": {
      "url": "${BASE_URL}/nomos-windows-amd64.zip",
      "hash": "${WINDOWS_AMD64_SHA}"
    },
    "arm64": {
      "url": "${BASE_URL}/nomos-windows-arm64.zip",
      "hash": "${WINDOWS_ARM64_SHA}"
    }
  },
  "bin": "nomos.exe",
  "checkver": {
    "github": "${SOURCE_REPOSITORY}"
  },
  "autoupdate": {
    "architecture": {
      "64bit": {
        "url": "https://github.com/${SOURCE_REPOSITORY}/releases/download/v\$version/nomos-windows-amd64.zip"
      },
      "arm64": {
        "url": "https://github.com/${SOURCE_REPOSITORY}/releases/download/v\$version/nomos-windows-arm64.zip"
      }
    }
  }
}
EOF

git add bucket/nomos.json
commit_and_push_repo "${workdir}/scoop-repo" "nomos ${RELEASE_TAG}"
