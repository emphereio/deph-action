#!/usr/bin/env bash
# deph-action orchestrator: install deph, feed it the built image, run one scan,
# and turn the result into a digest-bound path verdict. Never fails the job on
# findings (deph exit 1) — only a real scan error (exit 2) is fatal here; the
# fail-on gate is enforced by a later composite step.
set -Eeuo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
log() { printf 'deph-action: %s\n' "$*" >&2; }
die() { log "$*"; exit 2; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

out_set() {
  # Emit a GitHub Actions step output (no-op locally when GITHUB_OUTPUT is unset).
  [[ -n "${GITHUB_OUTPUT:-}" ]] && printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
  return 0
}

# ---- inputs -----------------------------------------------------------------
image="${DEPH_IMAGE:-}"
[[ -n "$image" ]] || die "input 'image' is required"

fail_on="${DEPH_FAIL_ON:-none}"
case "$fail_on" in
  none | any-reachable | reachable-high | reachable-critical) ;;
  *) die "fail-on must be one of: none, any-reachable, reachable-high, reachable-critical" ;;
esac

workspace="${GITHUB_WORKSPACE:-$PWD}"
out_dir="${DEPH_OUTPUT_DIRECTORY:-deph-report}"
case "$out_dir" in
  /*) ;;
  *) out_dir="$workspace/$out_dir" ;;
esac
mkdir -p "$out_dir"

report_json="$out_dir/deph-report.json"
report_html="$out_dir/report.html"
verdict_json="$out_dir/verdict.json"
summary_md="$out_dir/summary.md"
sarif_file="$out_dir/deph.sarif"
sbom_file="$out_dir/deph.cdx.json"

# ---- obtain deph ------------------------------------------------------------
# DEPH_BIN lets tests inject a stub binary; otherwise download a verified release.
deph_bin="${DEPH_BIN:-}"
if [[ -z "$deph_bin" ]]; then
  deph_bin="$("$here/install-deph.sh" | tail -n1)"
fi
[[ -x "$deph_bin" ]] || die "deph binary was not available"

# ---- resolve the image source (deph cannot read the local Docker daemon) ----
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

scan_target="$image"
source_mode="registry"
image_tar=""

if command -v docker >/dev/null 2>&1 && docker image inspect "$image" >/dev/null 2>&1; then
  source_mode="local-daemon"
  image_tar="$tmp/image.tar"
  log "image '$image' found in the local Docker daemon — saving to a tarball for deph"
  docker save "$image" -o "$image_tar" || die "docker save failed for '$image'"
  scan_target="$image_tar"
else
  log "treating '$image' as a registry reference (deph will pull it)"
fi

# ---- resolve the digest the verdict binds to, honestly labelled -------------
# Strength order: provided > repo-digest > tar-sha256 > config-id.
digest=""
digest_kind=""

extract_digest() { # echoes sha256:... if the arg carries one
  case "$1" in
    *@sha256:*) printf 'sha256:%s' "${1##*@sha256:}" ;;
  esac
}

# Resolve the registry content digest for a tag ref via whatever tool is present.
# All read-only, auth via the existing docker keychain. Empty if none can.
resolve_registry_digest() {
  local ref="$1" d=""
  if command -v docker >/dev/null 2>&1 && docker buildx version >/dev/null 2>&1; then
    d="$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
  fi
  if [[ -z "$d" ]] && command -v crane >/dev/null 2>&1; then
    d="$(crane digest "$ref" 2>/dev/null || true)"
  fi
  if [[ -z "$d" ]] && command -v skopeo >/dev/null 2>&1; then
    d="$(skopeo inspect --format '{{.Digest}}' "docker://$ref" 2>/dev/null || true)"
  fi
  printf '%s' "$d"
}

if [[ -n "${DEPH_IMAGE_DIGEST:-}" ]]; then
  digest="${DEPH_IMAGE_DIGEST}"
  digest_kind="provided"
elif d="$(extract_digest "$image")" && [[ -n "$d" ]]; then
  digest="$d"
  digest_kind="repo-digest"
elif [[ "$source_mode" == "local-daemon" ]]; then
  repo_digest="$(docker image inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$image" 2>/dev/null || true)"
  if d="$(extract_digest "$repo_digest")" && [[ -n "$d" ]]; then
    digest="$d"
    digest_kind="repo-digest"
  elif [[ -n "$image_tar" ]]; then
    digest="sha256:$(sha256_of "$image_tar")"
    digest_kind="tar-sha256"
  else
    digest="$(docker image inspect --format '{{.Id}}' "$image" 2>/dev/null || true)"
    [[ -n "$digest" ]] && digest_kind="config-id"
  fi
else
  # registry tag ref with no inline digest — resolve it from the registry.
  d="$(resolve_registry_digest "$image")"
  if [[ -n "$d" ]]; then
    digest="$d"
    digest_kind="repo-digest"
  fi
fi
if [[ -n "$digest" ]]; then
  log "binding verdict to ${digest} (${digest_kind})"
else
  log "no image digest resolved — pass image-digest for a strong binding"
fi

# ---- scan once: JSON (source of truth) + self-contained HTML ----------------
# Severity + VEX apply to EVERY pass, so the JSON verdict, SARIF, and SBOM agree
# (a VEX-suppressed finding must not leak into SARIF the verdict excluded).
common_flags=()
[[ -n "${DEPH_SEVERITY:-}" ]] && common_flags+=(--severity "$DEPH_SEVERITY")
if [[ -n "${DEPH_VEX:-}" ]]; then
  # space- or comma-separated list of VEX docs
  for v in ${DEPH_VEX//,/ }; do common_flags+=(--vex "$v"); done
fi

scan_flags=(scan "$scan_target" "${common_flags[@]}" --format json -o "$report_json" --ui-out "$report_html")
log "scanning: deph ${scan_flags[*]}"
set +e
"$deph_bin" "${scan_flags[@]}"
deph_exit=$?
set -e
log "deph scan exited ${deph_exit} (0=clean, 1=findings, 2=error)"
[[ "$deph_exit" -le 1 ]] || die "deph scan failed (exit ${deph_exit})"
[[ -s "$report_json" ]] || die "deph did not produce a report at ${report_json}"

# ---- opt-in extra passes (formats are mutually exclusive in deph) -----------
sarif_out=""
if [[ "${DEPH_UPLOAD_SARIF:-false}" == "true" ]]; then
  log "extra pass: reachable-only SARIF"
  if "$deph_bin" scan "$scan_target" "${common_flags[@]}" --format sarif --reachable-only -o "$sarif_file"; then
    sarif_out="$sarif_file"
  else
    log "warning: SARIF pass failed; continuing without SARIF"
  fi
fi

sbom_out=""
if [[ "${DEPH_UPLOAD_SBOM:-false}" == "true" ]]; then
  log "extra pass: CycloneDX SBOM"
  if "$deph_bin" scan "$scan_target" "${common_flags[@]}" --format cyclonedx -o "$sbom_file"; then
    sbom_out="$sbom_file"
  else
    log "warning: SBOM pass failed; continuing without SBOM"
  fi
fi

# ---- compose the verdict + summary -----------------------------------------
verdict_line="$(
  DEPH_REPORT_JSON="$report_json" \
  DEPH_VERDICT_JSON="$verdict_json" \
  DEPH_SUMMARY_MD="$summary_md" \
  DEPH_IMAGE_REF="$image" \
  DEPH_IMAGE_DIGEST_RESOLVED="$digest" \
  DEPH_IMAGE_DIGEST_KIND="$digest_kind" \
  DEPH_SOURCE_MODE="$source_mode" \
  DEPH_FAIL_ON="$fail_on" \
  DEPH_EXIT="$deph_exit" \
  DEPH_REPORT_HTML="$report_html" \
  DEPH_SARIF_OUT="$sarif_out" \
  DEPH_SBOM_OUT="$sbom_out" \
  python3 "$here/verdict.py"
)"

# verdict.py prints one JSON line of scalars for the action outputs.
read_scalar() { printf '%s' "$verdict_line" | python3 -c "import json,sys;print(json.load(sys.stdin).get('$1',''))"; }

total="$(read_scalar total)"
in_path="$(read_scalar in_path)"
linked="$(read_scalar linked)"
not_found="$(read_scalar not_found_in_path)"
gate_tripped="$(read_scalar gate_tripped)"
gate_reason="$(read_scalar gate_reason)"

# ---- outputs ----------------------------------------------------------------
out_set "report-json" "$report_json"
out_set "verdict-json" "$verdict_json"
out_set "summary-markdown" "$summary_md"
out_set "report-html" "$report_html"
out_set "sarif" "$sarif_out"
out_set "sbom-cyclonedx" "$sbom_out"
out_set "image-digest" "$digest"
out_set "total-cves" "$total"
out_set "in-path-cves" "$in_path"
out_set "linked-cves" "$linked"
out_set "not-found-in-path-cves" "$not_found"
out_set "gate-tripped" "$gate_tripped"
out_set "gate-reason" "$gate_reason"
out_set "deph-exit-code" "$deph_exit"
out_set "output-directory" "$out_dir"

# ---- sticky PR comment (best-effort) ----------------------------------------
case "${DEPH_COMMENT_ON_PR:-auto}" in
  off) ;;
  always) DEPH_SUMMARY_MD="$summary_md" "$here/comment.sh" || log "warning: PR comment failed" ;;
  auto)
    if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" || "${GITHUB_EVENT_NAME:-}" == "pull_request_target" ]]; then
      DEPH_SUMMARY_MD="$summary_md" "$here/comment.sh" || log "warning: PR comment failed"
    fi
    ;;
esac

log "done — ${in_path}/${total} known CVEs in the execution path"
