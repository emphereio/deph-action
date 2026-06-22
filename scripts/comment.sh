#!/usr/bin/env bash
# Upsert a single sticky PR comment carrying the deph summary. Idempotent: finds
# a prior comment by its hidden marker and edits it, else creates one. No-op when
# there is no PR, no token, or insufficient permission — never fails the job.
set -Eeuo pipefail

log() { printf 'deph-action: %s\n' "$*" >&2; }

marker="<!-- deph-action -->"
body_file="${DEPH_SUMMARY_MD:-}"
repo="${GITHUB_REPOSITORY:-}"

[[ -n "$body_file" && -s "$body_file" ]] || { log "no summary to comment"; exit 0; }
[[ -n "$repo" ]] || { log "no repository in context; skipping PR comment"; exit 0; }
command -v gh >/dev/null 2>&1 || { log "gh not available; skipping PR comment"; exit 0; }
[[ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]] || { log "no token; skipping PR comment"; exit 0; }

# Resolve the PR number from the event payload, falling back to refs/pull/N/merge.
pr=""
if [[ -n "${GITHUB_EVENT_PATH:-}" && -f "${GITHUB_EVENT_PATH:-}" ]]; then
  pr="$(python3 -c "import json,os;d=json.load(open(os.environ['GITHUB_EVENT_PATH']));print(d.get('pull_request',{}).get('number') or d.get('number') or '')" 2>/dev/null || true)"
fi
if [[ -z "$pr" && "${GITHUB_REF:-}" =~ ^refs/pull/([0-9]+)/ ]]; then
  pr="${BASH_REMATCH[1]}"
fi
[[ -n "$pr" ]] || { log "no pull request in context; skipping PR comment"; exit 0; }

# Find an existing deph-action comment by marker.
existing_id="$(gh api --paginate "repos/$repo/issues/$pr/comments" \
  --jq ".[] | select(.body | contains(\"$marker\")) | .id" 2>/dev/null | head -n1 || true)"

if [[ -n "$existing_id" ]]; then
  log "updating sticky PR comment #$existing_id on PR #$pr"
  gh api --method PATCH "repos/$repo/issues/comments/$existing_id" \
    -F body=@"$body_file" >/dev/null
else
  log "creating sticky PR comment on PR #$pr"
  gh api --method POST "repos/$repo/issues/$pr/comments" \
    -F body=@"$body_file" >/dev/null
fi
