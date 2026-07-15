#!/usr/bin/env python3
"""Build sanitized @deph conversation history from a PR's comments — IRONCLAD.

Only two things become turns: the bot's own marked replies (assistant) and @deph
comments from trusted authors (user). Everything else — third-party comments, the
other sticky comments, the triggering comment itself — is ignored. Each turn is
length-capped and the list is count-bounded. The agent re-sanitizes on top.

Reads the GitHub issue-comments JSON on stdin, emits a JSON array of
{role, content} turns on stdout. Env:
  DEPH_CURRENT_COMMENT_ID  the comment that triggered this run (excluded)
  DEPH_TRUSTED             comma list of allowed author_association (default OWNER,MEMBER,COLLABORATOR)
Stdlib only.
"""
import json
import os
import sys

BOT_MARK = "<!-- deph-bot-reply -->"
MAX_TURNS = 8
MAX_CHARS = 4000


def build(comments, current_id, trusted):
    turns = []
    for c in comments if isinstance(comments, list) else []:
        if not isinstance(c, dict):
            continue
        if current_id is not None and c.get("id") == current_id:
            continue
        body = c.get("body") or ""
        if not isinstance(body, str):
            continue
        if BOT_MARK in body:
            turns.append({"role": "assistant", "content": body.replace(BOT_MARK, "").strip()[:MAX_CHARS]})
        elif c.get("author_association") in trusted and "@deph" in body:
            turns.append({"role": "user", "content": body.replace("@deph", "").strip()[:MAX_CHARS]})
    return [t for t in turns if t["content"]][-MAX_TURNS:]


def main():
    try:
        comments = json.load(sys.stdin)
    except Exception:
        comments = []
    cur = os.environ.get("DEPH_CURRENT_COMMENT_ID")
    try:
        cur = int(cur) if cur else None
    except ValueError:
        cur = None
    trusted = {s.strip() for s in (os.environ.get("DEPH_TRUSTED")
               or "OWNER,MEMBER,COLLABORATOR").split(",") if s.strip()}
    json.dump(build(comments, cur, trusted), sys.stdout)


if __name__ == "__main__":
    main()
