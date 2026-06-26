#!/usr/bin/env python3
"""Deterministic remediation rollup over a deph report JSON.

This is the verified floor the AI layer plans on top of: no AI, no network.
For each vulnerable package it computes the single version bump that clears the
most CVEs, then splits and ranks by what actually matters (reachable risk,
base-os vs application). The AI layer proposes targets and pulls fresh data;
this module is the comparator that decides what a given target really clears.
"""
import argparse
import json
import os
import re
import sys

# Package names and versions are read from an untrusted scanned image and end up
# in PR comments and copy-pasteable commands, so treat them as hostile: validate
# against a conservative charset, and escape markdown when displaying.
# \Z (not $) so a trailing newline can't pass validation.
_SAFE_TOKEN = re.compile(r"\A[@A-Za-z0-9][A-Za-z0-9._+:~@/-]{0,199}\Z")
_MD_SPECIAL = re.compile(r"[`*_~\[\]()<>|\\]")


def safe_token(s):
    return isinstance(s, str) and bool(_SAFE_TOKEN.match(s)) and ".." not in s


def md_escape(s):
    return _MD_SPECIAL.sub(lambda m: "\\" + m.group(), str(s))


# deph node type -> human ecosystem label + the install verb we can suggest.
ECOSYSTEM = {
    "os-package": ("OS", "apt-get install {name}={ver}"),
    "pip-package": ("PyPI", "pip install {name}=={ver}"),
    "npm-package": ("npm", "npm install {name}@{ver}"),
    "go-module": ("Go", "go get {name}@v{ver}"),
    "java-package": ("Maven", "bump {name} to {ver}"),
    "gem-package": ("RubyGems", "gem install {name} -v {ver}"),
    "rust-package": ("crates.io", "cargo update -p {name} --precise {ver}"),
    "php-package": ("Composer", "composer require {name}:{ver}"),
}


def _loose(v: str):
    """Ecosystem-agnostic ordering tuple. Fallback when packaging can't parse."""
    out = []
    for p in re.findall(r"\d+|[a-zA-Z]+", str(v)):
        out.append((0, int(p)) if p.isdigit() else (1, p))
    return tuple(out)


def _norm(v):
    """Strip common ecosystem prefixes so Go ('go1.25.7', 'v1.44.0') compares cleanly."""
    v = str(v).strip()
    for pre in ("go", "v"):
        if v.startswith(pre) and v[len(pre):len(pre) + 1].isdigit():
            return v[len(pre):]
    return v


def is_downgrade(cur, target):
    """Best-effort: is target <= cur? Normalizes ecosystem prefixes first, then uses
    PEP 440 when available, else the loose comparator. Used only to drop downgrade /
    no-op suggestions (grype's fix_version is normally a forward fix)."""
    nc, nt = _norm(cur), _norm(target)
    try:
        from packaging.version import Version
        return Version(nt) <= Version(nc)
    except Exception:
        return _loose(nt) <= _loose(nc)


def max_version(versions):
    """Highest version in a same-ecosystem group.

    Uses PEP 440 / semver ordering via `packaging` when the whole group parses;
    otherwise falls back to a loose numeric/alpha split. In production this is
    where deph's grype comparators would be the source of truth — the point is
    the *comparison* is deterministic, never the model's guess.
    """
    try:
        from packaging.version import Version
        return max(versions, key=Version)
    except Exception:
        return max(versions, key=_loose)


def fix_command(node_type, name, ver):
    tmpl = ECOSYSTEM.get(node_type, ("", "upgrade {name} to {ver}"))[1]
    return tmpl.format(name=name, ver=ver)


def eco_label(node_type):
    return ECOSYSTEM.get(node_type, ("?", ""))[0]


def build_plan(report):
    g = report["graph"]
    nodes = g["nodes"]
    prio = g.get("cve_priority", {})

    def pscore(cid):
        return prio.get(cid, {}).get("priority")

    packages = []
    unfixable = []

    for n in nodes.values():
        cves = n.get("cves") or []
        if not cves:
            continue
        node_type = n.get("type", "")
        fixable, nofix = [], []
        for c in cves:
            entry = {
                "id": c["id"],
                "severity": c.get("severity"),
                "tier": c.get("tier"),
                "reachable": bool(c.get("reachable")),
                "priority": pscore(c["id"]),
                "epss": c.get("epss_score"),
                "fix_version": c.get("fix_version"),
            }
            (fixable if c.get("fix_version") else nofix).append(entry)

        if fixable:
            target = max_version([e["fix_version"] for e in fixable])
            name = n.get("name")
            cur = n.get("version")
            # Never suggest a downgrade: skip only when we can reliably prove the
            # installed version already satisfies the fix (feed anomaly). Mismatched
            # formats stay in — better to show a real upgrade than hide it.
            if cur and is_downgrade(cur, target):
                continue
            # Only emit a runnable command when the names validate; an unusual
            # string is itself a signal, not something to paste into a shell.
            verified = safe_token(name) and safe_token(str(target)) and safe_token(str(cur or ""))
            packages.append({
                "package": name,
                "ecosystem": eco_label(node_type),
                "node_type": node_type,
                "current_version": cur,
                "layer_origin": n.get("layer_origin"),
                "target_version": target,
                "name_verified": verified,
                "command": fix_command(node_type, name, target) if verified else None,
                "clears": fixable,
                "reachable_cleared": sum(1 for e in fixable if e["reachable"]),
                "priority_cleared": round(sum(e["priority"] or 0 for e in fixable), 1),
            })
        for e in nofix:
            unfixable.append({
                "package": n.get("name"),
                "layer_origin": n.get("layer_origin"),
                "fix_state": next((c.get("fix_state") for c in cves if c["id"] == e["id"]), None),
                **e,
            })

    # rank by reachable risk removed, then total priority, then count.
    packages.sort(
        key=lambda p: (p["reachable_cleared"], p["priority_cleared"], len(p["clears"])),
        reverse=True,
    )

    # image-wide stats over UNIQUE cve ids.
    uniq = {}
    for n in nodes.values():
        for c in n.get("cves") or []:
            cur = uniq.get(c["id"], {"reachable": False, "fixable": False, "base": False, "app": False})
            cur["reachable"] |= bool(c.get("reachable"))
            cur["fixable"] |= bool(c.get("fix_version"))
            if c.get("layer_origin") == "base-image":
                cur["base"] = True
            elif c.get("layer_origin") == "application":
                cur["app"] = True
            uniq[c["id"]] = cur
    stats = {
        "total": len(uniq),
        "reachable": sum(1 for v in uniq.values() if v["reachable"]),
        "resolvable": sum(1 for v in uniq.values() if v["fixable"]),
        "resolvable_reachable": sum(1 for v in uniq.values() if v["fixable"] and v["reachable"]),
        "base_os": sum(1 for v in uniq.values() if v["base"]),
        "app": sum(1 for v in uniq.values() if v["app"]),
    }

    return {
        "image": g.get("image_ref") or report.get("image"),
        "stats": stats,
        "packages": packages,
        "unfixable": unfixable,
    }


def _major_bump(cur, target):
    """Heuristic: do the leading integers differ? (Flags semver/PEP440 major jumps.)"""
    a = re.match(r"\D*(\d+)", str(cur or ""))
    b = re.match(r"\D*(\d+)", str(target or ""))
    return bool(a and b and a.group(1) != b.group(1))


def _rows(items, limit, flag_major):
    lines = []
    ranked = sorted(items, key=lambda p: (p["reachable_cleared"], p["priority_cleared"]), reverse=True)
    for p in ranked[:limit]:
        cav = " · major bump" if (flag_major and _major_bump(p["current_version"], p["target_version"])) else ""
        if p.get("command"):
            tail = f" · `{p['command']}`"
        else:
            tail = " · ⚠ unusual name, verify manually"
        lines.append(
            f"- `{md_escape(p['package'])}` {md_escape(p['current_version'])} → "
            f"{md_escape(p['target_version'])} — {p['reachable_cleared']} reachable{cav}{tail}"
        )
    if len(ranked) > limit:
        lines.append(f"- …and {len(ranked) - limit} more")
    return lines


def render_markdown(plan, top=6):
    """Terse fix-path. Split by who fixes it (app deps vs OS packages), since those
    are usually different people, with the command honest to each."""
    s = plan["stats"]
    pkgs = plan["packages"]
    # Focus on reachable risk, and split by who owns the fix (app deps vs OS packages
    # are usually different people). Only list upgrades that clear a reachable CVE.
    app = [p for p in pkgs if p["node_type"] != "os-package" and p["reachable_cleared"] > 0]
    osp = [p for p in pkgs if p["node_type"] == "os-package" and p["reachable_cleared"] > 0]
    cleared = len({c["id"] for p in (app + osp) for c in p["clears"] if c.get("reachable")})
    non_reach = len(pkgs) - len(app) - len(osp)
    uf_reach = len({u["id"] for u in plan["unfixable"] if u.get("reachable")})

    out = [f"## deph fix path — {md_escape(plan['image'] or 'image')}"]
    if not app and not osp:
        out.append(f"No reachable CVE is fixable by an upgrade ({s['reachable']} reachable; "
                   "the rest have no upstream fix or are already current).")
        return "\n".join(out)

    out.append(f"**{len(app) + len(osp)} upgrade(s) clear {cleared} of {s['reachable']} reachable CVEs.**")
    out.append("")

    if app:
        out.append("**App dependencies** — you own these: pin in your manifest "
                   "(requirements.txt / package.json …) and rebuild.")
        out += _rows(app, top, flag_major=True)
        out.append("")
    if osp:
        out.append("**OS / base image** — usually your platform/base-image team: bump the base "
                   "image, or patch in the Dockerfile (`RUN` the command below).")
        out += _rows(osp, 4, flag_major=False)
        out.append("")

    notes = []
    if uf_reach:
        notes.append(f"{uf_reach} reachable CVE(s) have no upstream fix yet — track, can't upgrade away.")
    if non_reach:
        notes.append(f"{non_reach} more package(s) only clear non-reachable CVEs (see report).")
    out += notes
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Deterministic remediation rollup over a deph report.")
    ap.add_argument("report", help="deph report JSON (the full --format json output)")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    ap.add_argument("--top", type=int, default=8)
    args = ap.parse_args()

    with open(args.report) as f:
        report = json.load(f)
    plan = build_plan(report)
    # Local images scan from a tarball, so the report's image_ref is a temp path —
    # let the caller supply the friendly name for the title.
    plan["image"] = os.environ.get("DEPH_REMEDIATE_IMAGE") or plan["image"]

    if args.format == "json":
        json.dump(plan, sys.stdout, indent=2)
        print()
    else:
        print(render_markdown(plan, top=args.top))


if __name__ == "__main__":
    main()
