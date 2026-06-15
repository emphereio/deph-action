#!/usr/bin/env bash
set -Eeuo pipefail

epoch_ms() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import time; print(time.time_ns() // 1000000)'
  else
    printf '%s000\n' "$(date +%s)"
  fi
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="${TMPDIR:-/tmp}/deph-action-self-test-$$"
  mkdir -p "$tmp/work"
  DEPH_IMAGE="example/app:latest" \
  DEPH_TEST_COMMAND="printf 'ok\\n'" \
  DEPH_WORKING_DIRECTORY="$tmp/work" \
  DEPH_OUTPUT_DIRECTORY="$tmp/out" \
  DEPH_FAIL_ON_TEST_FAILURE="true" \
  GITHUB_WORKSPACE="$tmp/workspace" \
  GITHUB_REPOSITORY="emphereio/self-test" \
  GITHUB_REF="refs/heads/main" \
  GITHUB_SHA="0000000000000000000000000000000000000000" \
  GITHUB_RUN_ID="1" \
  GITHUB_RUN_ATTEMPT="1" \
  GITHUB_STEP_SUMMARY="$tmp/summary" \
  "$0"
  test -s "$tmp/out/deph-evidence.json"
  test -s "$tmp/out/summary.md"
  rm -rf "$tmp"
  exit 0
fi

image="${DEPH_IMAGE:-}"
test_command="${DEPH_TEST_COMMAND:-}"
work_dir="${DEPH_WORKING_DIRECTORY:-.}"
out_dir="${DEPH_OUTPUT_DIRECTORY:-deph-evidence}"
fail_on_test_failure="${DEPH_FAIL_ON_TEST_FAILURE:-true}"
workspace="${GITHUB_WORKSPACE:-$PWD}"

if [[ -z "$image" ]]; then
  echo "deph-action: input 'image' is required" >&2
  exit 2
fi

case "$fail_on_test_failure" in
  true|false) ;;
  *)
    echo "deph-action: fail-on-test-failure must be 'true' or 'false'" >&2
    exit 2
    ;;
esac

case "$work_dir" in
  /*) ;;
  *) work_dir="$workspace/$work_dir" ;;
esac

case "$out_dir" in
  /*) ;;
  *) out_dir="$workspace/$out_dir" ;;
esac

if [[ ! -d "$work_dir" ]]; then
  echo "deph-action: working-directory does not exist: $work_dir" >&2
  exit 2
fi

mkdir -p "$out_dir"
report_json="$out_dir/deph-evidence.json"
summary_md="$out_dir/summary.md"
test_log="$out_dir/test.log"

test_exit=""
test_started=""
test_finished=""
test_duration_ms=""

if [[ -n "$test_command" ]]; then
  test_started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  start_ms="$(epoch_ms)"
  set +e
  (cd "$work_dir" && bash -lc "$test_command") >"$test_log" 2>&1
  test_exit="$?"
  set -e
  end_ms="$(epoch_ms)"
  test_finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  test_duration_ms="$(( end_ms - start_ms ))"
else
  : >"$test_log"
fi


json_escape() {
  local s="${1:-}"
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  printf '%s' "$s"
}

json_string_or_null() {
  if [[ -z "${1:-}" ]]; then
    printf 'null'
  else
    printf '"%s"' "$(json_escape "$1")"
  fi
}

json_number_or_null() {
  if [[ -z "${1:-}" ]]; then
    printf 'null'
  else
    printf '%s' "$1"
  fi
}

cat >"$report_json" <<JSON
{
  "schema_version": "0.1.0",
  "producer": {
    "name": "deph-action",
    "version": "0.1.0"
  },
  "image": "$(json_escape "$image")",
  "source": {
    "repository": "$(json_escape "${GITHUB_REPOSITORY:-}")",
    "ref": "$(json_escape "${GITHUB_REF:-}")",
    "sha": "$(json_escape "${GITHUB_SHA:-}")",
    "run_id": "$(json_escape "${GITHUB_RUN_ID:-}")",
    "run_attempt": "$(json_escape "${GITHUB_RUN_ATTEMPT:-}")"
  },
  "test_window": {
    "command": $(json_string_or_null "$test_command"),
    "working_directory": "$(json_escape "$work_dir")",
    "started_at": $(json_string_or_null "$test_started"),
    "finished_at": $(json_string_or_null "$test_finished"),
    "duration_ms": $(json_number_or_null "$test_duration_ms"),
    "exit_code": $(json_number_or_null "$test_exit"),
    "log_path": "$(json_escape "$test_log")"
  },
  "artifacts": {
    "summary_markdown": "$(json_escape "$summary_md")",
    "report_json": "$(json_escape "$report_json")"
  }
}
JSON

{
  echo "## deph evidence report"
  echo
  echo "| field | value |"
  echo "| --- | --- |"
  echo "| image | \`$image\` |"
  echo "| repository | \`${GITHUB_REPOSITORY:-}\` |"
  echo "| ref | \`${GITHUB_REF:-}\` |"
  echo "| sha | \`${GITHUB_SHA:-}\` |"
  if [[ -n "$test_command" ]]; then
    echo "| test command | \`$test_command\` |"
    echo "| test exit code | \`$test_exit\` |"
    echo "| test duration | \`${test_duration_ms}ms\` |"
  else
    echo "| test command | not provided |"
  fi
  echo
  echo "Generated artifacts:"
  echo
  echo "- \`$report_json\`"
  echo "- \`$summary_md\`"
  if [[ -n "$test_command" ]]; then
    echo "- \`$test_log\`"
  fi
} >"$summary_md"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "report-json=$report_json"
    echo "summary-markdown=$summary_md"
    echo "test-exit-code=$test_exit"
    echo "output-directory=$out_dir"
  } >>"$GITHUB_OUTPUT"
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$summary_md" >>"$GITHUB_STEP_SUMMARY"
fi

if [[ -n "$test_exit" && "$test_exit" != "0" && "$fail_on_test_failure" == "true" ]]; then
  echo "deph-action: test-command failed with exit code $test_exit" >&2
  exit "$test_exit"
fi
