#!/usr/bin/env bash
# Bridges the action to the remediation layer (remediate/). Two modes:
#   plan        - turn a scan report into a fix plan and post it as a sticky PR comment
#   investigate - answer a question against an existing report (the @deph bot)
# Fail-degraded: with no DEPH_LLM_MODEL the agent emits the deterministic plan and
# this still succeeds; it never fails the job.
set -Eeuo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
log() { printf 'deph-action: %s\n' "$*" >&2; }
out_set() { [[ -n "${GITHUB_OUTPUT:-}" ]] && printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"; }

# The agent reads these directly (OpenAI-compatible; any provider/local).
export DEPH_LLM_BASE_URL="${DEPH_LLM_BASE_URL:-https://api.openai.com/v1}"
export DEPH_LLM_MODEL="${DEPH_LLM_MODEL:-}"
export DEPH_LLM_API_KEY="${DEPH_LLM_API_KEY:-}"

report="${DEPH_REMEDIATE_REPORT:-}"
outdir="${DEPH_OUTPUT_DIRECTORY:-deph-report}"
agent="$root/remediate/agent.py"
[[ -n "$report" && -f "$report" ]] || { log "no report at '$report'; skipping remediation"; exit 0; }
mkdir -p "$outdir"

case "${DEPH_REMEDIATE_MODE:-plan}" in
  plan)
    md="$outdir/remediation.md"
    # The auto comment is DETERMINISTIC by design — no model on every PR (no slop,
    # reproducible, no key, no tokens). The AI is opt-in via the @deph bot.
    DEPH_REMEDIATE_IMAGE="${DEPH_IMAGE:-}" python3 "$root/remediate/plan.py" "$report" >"$md"
    # Point at the full report instead of restating it; invite the opt-in bot.
    {
      printf '\n---\n'
      if [[ -n "${GITHUB_RUN_ID:-}" && -n "${GITHUB_REPOSITORY:-}" ]]; then
        printf 'Full reachability graph + evidence: the `deph-report` artifact (report.html) on [this run](%s/%s/actions/runs/%s).\n' \
          "${GITHUB_SERVER_URL:-https://github.com}" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID"
      fi
      printf 'Ask `@deph <question>` on this PR to dig into any of it.\n'
    } >>"$md"
    out_set "remediation-markdown" "$md"
    log "remediation plan -> $md"
    if [[ "${DEPH_COMMENT_ON_PR:-auto}" != "off" ]]; then
      DEPH_SUMMARY_MD="$md" DEPH_COMMENT_MARKER="<!-- deph-remediate -->" \
        "$here/comment.sh" || log "warning: remediation comment failed"
    fi
    ;;
  investigate)
    q="${DEPH_REMEDIATE_QUESTION:-Summarize the most urgent reachable CVEs and the smallest set of upgrades that clears them.}"
    ans="$outdir/answer.md"
    python3 "$agent" "$report" --mode ask --ask "$q" >"$ans"
    out_set "remediation-markdown" "$ans"
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
      { echo "answer<<__DEPH_EOF__"; cat "$ans"; echo "__DEPH_EOF__"; } >>"$GITHUB_OUTPUT"
    fi
    log "investigation answer -> $ans"
    ;;
  *)
    log "unknown DEPH_REMEDIATE_MODE='${DEPH_REMEDIATE_MODE:-}'"; exit 1 ;;
esac
