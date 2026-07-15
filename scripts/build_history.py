#!/usr/bin/env python3
"""Build sanitized @deph conversation history from a PR's comments — IRONCLAD.

Only two things become turns: the bot's own marked replies (assistant) and @deph
comments from trusted authors (user). Everything else — third-party comments, the
other sticky comments, the triggering comment itself — is ignored. Each turn is
length-capped and the list is count-bounded. The agent re-sanitizes on top.

An assistant turn must satisfy BOTH conditions: the comment carries the bot marker
AND it was posted by the bot account itself (a Bot-type actor whose login is in the
allow-list). The marker alone is public — it appears in every bot reply — so a check
on the marker string by itself is forgeable: any commenter, including an unauthorized
one, could paste it and have their text treated as a prior *assistant* message. The
identity check closes that.

Reads the GitHub issue-comments JSON on stdin, emits a JSON array of
{role, content} turns on stdout. Env:
  DEPH_CURRENT_COMMENT_ID  the comment that triggered this run (excluded)
  DEPH_TRUSTED             comma list of allowed author_association (default OWNER,MEMBER,COLLABORATOR)
  DEPH_BOT_LOGINS          comma list of bot accounts that post replies (default github-actions[bot])
Stdlib only.
"""
import json
import os
import sys

BOT_MARK = "<!-- deph-bot-reply -->"
DEFAULT_BOT_LOGINS = ("github-actions[bot]",)
MAX_TURNS = 8
MAX_CHARS = 4000


def _from_bot(comment, bot_logins):
    """True only if the comment was posted by an allow-listed Bot-type account.

    Both are required: a Bot actor type and a known bot login. A human commenter
    (type 'User') who pastes the marker fails here, so the marker cannot be forged
    into an assistant turn.
    """
    user = comment.get("user")
    if not isinstance(user, dict):
        return False
    return user.get("type") == "Bot" and user.get("login") in bot_logins


def build(comments, current_id, trusted, bot_logins=DEFAULT_BOT_LOGINS):
    bot_logins = set(bot_logins)
    turns = []
    for c in comments if isinstance(comments, list) else []:
        if not isinstance(c, dict):
            continue
        if current_id is not None and c.get("id") == current_id:
            continue
        body = c.get("body") or ""
        if not isinstance(body, str):
            continue
        if BOT_MARK in body and _from_bot(c, bot_logins):
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
    bot_logins = {s.strip() for s in (os.environ.get("DEPH_BOT_LOGINS")
                  or ",".join(DEFAULT_BOT_LOGINS)).split(",") if s.strip()}
    json.dump(build(comments, cur, trusted, bot_logins), sys.stdout)


if __name__ == "__main__":
    main()
