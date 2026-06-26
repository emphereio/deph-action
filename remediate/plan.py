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
            # Never suggest a downgrade or no-op: if the installed version already
            # satisfies the highest fix, the CVE is already cleared or a feed
            # anomaly — not something an upgrade fixes. Skip it.
            if cur and max_version([cur, target]) == cur:
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


SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEGLIGIBLE": 4, "UNKNOWN": 5}


def render_markdown(plan, top=8):
    s = plan["stats"]
    out = []
    out.append(f"## deph remediation plan — {plan['image']}")
    out.append(
        f"{s['total']} CVEs · **{s['reachable']} reachable** · "
        f"{s['resolvable']} resolvable by upgrade ({s['resolvable_reachable']} of them reachable) · "
        f"base-os {s['base_os']} / app {s['app']}"
    )
    out.append("")

    # Lead with packages that clear reachable risk; fall back to highest priority.
    actionable = [p for p in plan["packages"] if p["reachable_cleared"] > 0] or plan["packages"]
    out.append("### Do first — ranked by reachable risk removed")
    for p in actionable[:top]:
        rc = p["reachable_cleared"]
        n = len(p["clears"])
        tag = f"{rc} reachable" if rc else "0 reachable"
        out.append(
            f"- **{md_escape(p['package'])} {md_escape(p['current_version'])} → "
            f"{md_escape(p['target_version'])}** clears {n} CVE(s) ({tag}) · "
            f"{p['ecosystem']} · {p['layer_origin']}"
        )
        if p.get("command"):
            out.append(f"  `{p['command']}`")
        else:
            out.append("  ⚠ unusual package/version string — verify manually before upgrading")
    out.append("")

    # Base-OS rollup: one line, since the move is usually a base-image bump.
    base = [p for p in plan["packages"] if p["layer_origin"] == "base-image"]
    base_cleared = sum(len(p["clears"]) for p in base)
    if base:
        out.append(
            f"### Base OS — {len(base)} package(s), {base_cleared} CVE(s) resolvable"
        )
        out.append(
            "These come from the base image (build-history attribution, not your Dockerfile). "
            "Bumping the base image tag is usually the single move that clears most of them."
        )
        out.append("")

    if plan["unfixable"]:
        uniq_uf = sorted({u["id"]: u for u in plan["unfixable"]}.values(),
                         key=lambda u: SEV_RANK.get((u["severity"] or "UNKNOWN").upper(), 9))
        out.append(f"### No fix available — {len(uniq_uf)} CVE(s)")
        for u in uniq_uf[:5]:
            out.append(
                f"- {md_escape(u['id'])} ({md_escape(u['package'])}, "
                f"{md_escape(u['fix_state'] or 'no fix')}) — track, not actionable here."
            )
        out.append("")

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

    if args.format == "json":
        json.dump(plan, sys.stdout, indent=2)
        print()
    else:
        print(render_markdown(plan, top=args.top))


if __name__ == "__main__":
    main()
