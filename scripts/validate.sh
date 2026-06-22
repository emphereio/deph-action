#!/usr/bin/env bash
# Offline self-test for deph-action: shell syntax, the verdict transform against
# a checked-in deph report fixture, schema validation, and the expected
# tier split. Does not download deph or run a scan.
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "==> shell syntax"
bash -n scripts/*.sh

echo "==> python parse"
python3 -c "import ast; ast.parse(open('scripts/verdict.py').read())"

echo "==> verdict transform against fixture"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

scalars="$(
  DEPH_REPORT_JSON="testdata/sample-deph-report.json" \
  DEPH_VERDICT_JSON="$tmp/verdict.json" \
  DEPH_SUMMARY_MD="$tmp/summary.md" \
  DEPH_IMAGE_REF="ghcr.io/acme/app:latest" \
  DEPH_IMAGE_DIGEST_RESOLVED="sha256:deadbeef" \
  DEPH_IMAGE_DIGEST_KIND="provided" \
  DEPH_SOURCE_MODE="local-daemon" \
  DEPH_FAIL_ON="reachable-critical" \
  DEPH_EXIT="1" \
  DEPH_VERSION="v0.0.0-test" \
  python3 scripts/verdict.py
)"

echo "    scalars: $scalars"
test -s "$tmp/verdict.json"
test -s "$tmp/summary.md"
python3 -m json.tool "$tmp/verdict.json" >/dev/null

echo "==> assert expected tier split (in_path=2, linked=1, not_found=1, gate tripped)"
python3 - "$scalars" <<'PY'
import json, sys
s = json.loads(sys.argv[1])
expected = {"total": 4, "in_path": 2, "linked": 1, "not_found_in_path": 1, "gate_tripped": "true"}
for k, v in expected.items():
    assert s[k] == v, f"{k}: expected {v}, got {s[k]}"
print("    tier split OK")
PY

echo "==> end-to-end run.sh with a fake deph binary (gate path, fully offline)"
chmod +x testdata/fake-deph.sh
e2e="$tmp/e2e"
mkdir -p "$e2e"
out_file="$tmp/gh_output"
: >"$out_file"
# image-digest set to skip any registry digest resolver (keeps the test hermetic).
DEPH_BIN="$root/testdata/fake-deph.sh" \
DEPH_IMAGE="example/app:latest" \
DEPH_IMAGE_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000" \
DEPH_FAIL_ON="reachable-critical" \
DEPH_COMMENT_ON_PR="off" \
DEPH_OUTPUT_DIRECTORY="$e2e" \
GITHUB_WORKSPACE="$tmp" \
GITHUB_OUTPUT="$out_file" \
GITHUB_STEP_SUMMARY="$tmp/step_summary" \
bash scripts/run.sh

test -s "$e2e/verdict.json"
test -s "$e2e/report.html"
grep -q '^gate-tripped=true$' "$out_file" || { echo "expected gate-tripped=true" >&2; exit 1; }
grep -q '^in-path-cves=2$' "$out_file" || { echo "expected in-path-cves=2" >&2; exit 1; }
grep -q '^deph-exit-code=1$' "$out_file" || { echo "expected deph-exit-code=1" >&2; exit 1; }
echo "    run.sh gate path OK"

echo "==> end-to-end run.sh with fail-on=none (gate must NOT trip)"
out_file2="$tmp/gh_output2"
: >"$out_file2"
DEPH_BIN="$root/testdata/fake-deph.sh" \
DEPH_IMAGE="example/app:latest" \
DEPH_IMAGE_DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000" \
DEPH_FAIL_ON="none" \
DEPH_COMMENT_ON_PR="off" \
DEPH_OUTPUT_DIRECTORY="$tmp/e2e2" \
GITHUB_WORKSPACE="$tmp" \
GITHUB_OUTPUT="$out_file2" \
bash scripts/run.sh
grep -q '^gate-tripped=false$' "$out_file2" || { echo "expected gate-tripped=false" >&2; exit 1; }
echo "    run.sh no-gate path OK"

echo "==> validate verdict.json against schema (if jsonschema available)"
if python3 -c "import jsonschema" 2>/dev/null; then
  python3 - "$tmp/verdict.json" schema/deph-verdict.schema.json <<'PY'
import json, sys
import jsonschema
doc = json.load(open(sys.argv[1]))
schema = json.load(open(sys.argv[2]))
jsonschema.validate(doc, schema)
print("    schema OK")
PY
else
  echo "    jsonschema not installed; skipping (json.tool already confirmed well-formed)"
fi

echo "OK"
