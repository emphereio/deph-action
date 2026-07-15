#!/usr/bin/env python3
"""Owner-controlled access policy for deph AI invocations (the @deph bot).

Reads `.deph.yml` (or `.github/deph.yml`) `access:` and decides whether an actor may
invoke. Default when no file/section exists: OWNER, MEMBER, COLLABORATOR — the prior
gate. Owners tighten (explicit allowlist) or widen it by committing the policy, which
is a reviewed change, not a workflow edit.

    access:
      associations: [OWNER, MEMBER, COLLABORATOR]   # GitHub relationship allowed
      users: [alice, bob]                            # usernames always allowed
      deny:  [mallory]                               # usernames always denied (wins)

Emits `allowed=true|false` and `reason=...` to GITHUB_OUTPUT. Stdlib only — a minimal
YAML subset for this fixed schema, so no dependency is needed on the runner.
"""
import os
import re
import sys

DEFAULT_ASSOCIATIONS = ["OWNER", "MEMBER", "COLLABORATOR"]


def _inline_list(rest):
    rest = rest.strip()
    if rest.startswith("[") and rest.endswith("]"):
        return [x.strip().strip("\"'") for x in rest[1:-1].split(",") if x.strip()]
    return [rest.strip("\"'")] if rest else []


def parse_access(text):
    """Return {associations: [...]|None, users: [...], deny: [...]} or None if no access: block."""
    acc = {"associations": None, "users": [], "deny": []}
    found = in_access = False
    cur = None
    for raw in (text or "").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        s = raw.strip()
        if indent == 0:
            in_access = (s.rstrip(":") == "access")
            found = found or in_access
            cur = None
            continue
        if not in_access:
            continue
        m = re.match(r"(associations|users|deny)\s*:\s*(.*)$", s)
        if m:
            cur = m.group(1)
            vals = _inline_list(m.group(2))
            if cur == "associations":
                acc["associations"] = [v.upper() for v in vals] if vals else []
            else:
                acc[cur] = [v.lower() for v in vals]
            if vals:
                cur = None
            continue
        bm = re.match(r"-\s*(.+)$", s)
        if bm and cur:
            v = bm.group(1).strip().strip("\"'")
            if cur == "associations":
                acc["associations"] = (acc["associations"] or []) + [v.upper()]
            else:
                acc[cur].append(v.lower())
    return acc if found else None


def decide(access, actor, association):
    actor = (actor or "").lower()
    assoc = (association or "").upper()
    if access is None:
        return assoc in DEFAULT_ASSOCIATIONS, "default policy (OWNER/MEMBER/COLLABORATOR)"
    if actor in access.get("deny", []):
        return False, "actor is on the deny list"
    if actor in access.get("users", []):
        return True, "actor on the allowed-users list"
    assocs = access["associations"] if access.get("associations") is not None else DEFAULT_ASSOCIATIONS
    if assoc in assocs:
        return True, f"association {assoc} permitted"
    return False, f"association {assoc or '(none)'} not permitted and actor not allow-listed"


def _read_policy():
    candidates = [os.environ.get("DEPH_POLICY_FILE") or "", ".deph.yml", ".github/deph.yml"]
    for p in candidates:
        if p and os.path.exists(p):
            with open(p) as f:
                return f.read()
    return ""


def main():
    access = parse_access(_read_policy())
    allowed, reason = decide(access, os.environ.get("DEPH_ACTOR"), os.environ.get("DEPH_ASSOCIATION"))
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"allowed={'true' if allowed else 'false'}\n")
            f.write(f"reason={reason}\n")
    sys.stderr.write(f"deph authorize: actor={os.environ.get('DEPH_ACTOR')!r} -> {allowed} ({reason})\n")


if __name__ == "__main__":
    main()
