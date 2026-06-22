#!/usr/bin/env bash
# Deterministic deph stand-in for offline tests. Emits the checked-in fixture
# report for --format json, minimal valid files for sarif/cyclonedx/ui-out, and
# exits 1 (findings) so the gate path is exercised without a real scan or image.
set -Eeuo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "version" ]]; then
  echo "deph fake-0.0.0 (test stub)"
  exit 0
fi

fmt="json"
out=""
ui_out=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[$i]}" in
    --format) fmt="${args[$((i + 1))]}" ;;
    -o | --output) out="${args[$((i + 1))]}" ;;
    --ui-out) ui_out="${args[$((i + 1))]}" ;;
  esac
done

case "$fmt" in
  json) [[ -n "$out" ]] && cp "$here/sample-deph-report.json" "$out" ;;
  sarif) [[ -n "$out" ]] && printf '{"version":"2.1.0","runs":[]}\n' >"$out" ;;
  cyclonedx) [[ -n "$out" ]] && printf '{"bomFormat":"CycloneDX","specVersion":"1.6"}\n' >"$out" ;;
esac
[[ -n "$ui_out" ]] && printf '<!doctype html><title>fake</title>\n' >"$ui_out"

# Fixture carries CVEs → signal findings, like the real binary.
exit 1
