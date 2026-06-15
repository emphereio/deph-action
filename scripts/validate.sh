#!/usr/bin/env bash
set -Eeuo pipefail

bash -n scripts/*.sh
./scripts/run.sh --self-test

tmp="${TMPDIR:-/tmp}/deph-action-validate-$$"
mkdir -p "$tmp/work" "$tmp/workspace"
trap 'rm -rf "$tmp"' EXIT

DEPH_IMAGE="example/app:latest" \
DEPH_TEST_COMMAND="printf 'ok\\n'" \
DEPH_WORKING_DIRECTORY="$tmp/work" \
DEPH_OUTPUT_DIRECTORY="$tmp/out" \
DEPH_FAIL_ON_TEST_FAILURE="true" \
GITHUB_WORKSPACE="$tmp/workspace" \
GITHUB_REPOSITORY="emphereio/validate" \
GITHUB_REF="refs/heads/main" \
GITHUB_SHA="0000000000000000000000000000000000000000" \
GITHUB_RUN_ID="1" \
GITHUB_RUN_ATTEMPT="1" \
./scripts/run.sh

python3 -m json.tool "$tmp/out/deph-evidence.json" >/dev/null
