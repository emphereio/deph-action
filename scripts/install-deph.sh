#!/usr/bin/env bash
# Download a pinned, checksum-verified deph binary from the public deph distribution
# repo (emphereio/deph-dist). Prints the absolute path to the installed binary on
# stdout (last line); all diagnostics go to stderr. The action never builds deph from
# source, and the deph engine source repo stays private — only signed release binaries
# are published to the distribution repo.
set -Eeuo pipefail

log() { printf 'deph-action: %s\n' "$*" >&2; }
die() { log "$*"; exit 1; }

version="${DEPH_VERSION:-}"
repo="${DEPH_REPO:-emphereio/deph-dist}"
# Provenance is verified against the workflow that BUILT the binary (the private deph
# source repo), not the distribution repo it is downloaded from. Even if deph-dist is
# compromised, a tainted binary cannot carry a valid attestation from this workflow.
attest_repo="${DEPH_ATTEST_REPO:-emphereio/deph}"
attest_workflow="${DEPH_ATTEST_WORKFLOW:-.github/workflows/release.yml}"
[[ -n "$version" ]] || die "DEPH_VERSION is required"

command -v gh >/dev/null 2>&1 || die "gh CLI is required to download the deph release"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# Map the runner architecture to the released asset name.
case "$(uname -m)" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
os="linux"
asset="deph_${os}_${arch}"

# Cache by version+asset so repeated runs on a warm runner skip the download.
install_dir="${RUNNER_TOOL_CACHE:-${RUNNER_TEMP:-/tmp}}/deph/${version}"
bin="${install_dir}/deph"

# Reuse a cached binary only if it still matches the checksum recorded beside it
# at install time — never trust an unverified binary, even on a warm runner.
if [[ -x "$bin" && -f "$bin.sha256" ]]; then
  if [[ "$(sha256_of "$bin")" == "$(cat "$bin.sha256")" ]]; then
    log "using verified cached deph ${version} (${asset}) at ${bin}"
    printf '%s\n' "$bin"
    exit 0
  fi
  log "cached deph failed re-verification; re-downloading"
fi

mkdir -p "$install_dir"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

bundle_asset="${asset}.sigstore.jsonl"
log "downloading ${asset}, ${bundle_asset}, and checksums.txt for ${repo}@${version}"
gh release download "$version" \
  --repo "$repo" \
  --pattern "$asset" \
  --pattern "$bundle_asset" \
  --pattern "checksums.txt" \
  --dir "$tmp" \
  --clobber \
  || die "failed to download deph ${version} from ${repo} (asset ${asset})"

[[ -f "$tmp/$asset" ]] || die "release asset ${asset} not found in ${repo}@${version}"
[[ -f "$tmp/$bundle_asset" ]] || die "provenance bundle ${bundle_asset} not found in ${repo}@${version}"
[[ -f "$tmp/checksums.txt" ]] || die "checksums.txt not found in ${repo}@${version}"

# Verify the asset against the published sha256 before trusting the binary.
expected="$(awk -v a="$asset" '$2 == a || $2 == "*"a {print $1}' "$tmp/checksums.txt" | head -n1)"
[[ -n "$expected" ]] || die "no checksum for ${asset} in checksums.txt"

actual="$(sha256_of "$tmp/$asset")"
[[ "$actual" == "$expected" ]] || die "checksum mismatch for ${asset}: expected ${expected}, got ${actual}"

# Verify SLSA build provenance before trusting the binary. A checksum only proves the
# file matches checksums.txt — and an attacker who can publish a release publishes a
# matching checksums.txt too. The attestation is a Sigstore-signed proof that THIS
# artifact was built by the expected workflow in the expected repo; it cannot be forged
# without that workflow's identity. This is the real defense against a tainted release.
# We verify against the BUNDLE shipped beside the binary (the build repo is private, so
# its attestations can't be fetched by external consumers — the bundle verifies offline).
# Fail closed: an unverifiable binary is never installed.
log "verifying build provenance (${attest_repo} ${attest_workflow})"
gh attestation verify "$tmp/$asset" \
  --bundle "$tmp/$bundle_asset" \
  --repo "$attest_repo" \
  --signer-workflow "${attest_repo}/${attest_workflow}" \
  >&2 || die "provenance verification failed for ${asset}: refusing to install an unattested binary"

install -m 0755 "$tmp/$asset" "$bin"
printf '%s' "$actual" >"$bin.sha256" # sidecar so cache hits can re-verify
log "installed verified deph ${version} (${asset}) to ${bin}"
"$bin" version >&2 || true
printf '%s\n' "$bin"
