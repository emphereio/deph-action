#!/usr/bin/env python3
"""Deterministic CVE triage — the first-line noise cut.

Buckets every finding ACT / WATCH / IGNORE, each anchored to a real deph field
(tier, evidence, reachability_class, controllability, runtime_observed, EPSS).
This is the truth: the AI digest narrates on top but may never move a CVE to a
softer bucket than the deterministic call. IGNORE only ever rests on a hard fact
(deph found no execution path), never on a guess.

Stdlib only.
"""
import argparse
import json
import sys
from collections import Counter

ACT, WATCH, IGNORE = "act", "watch", "ignore"
_RANK = {ACT: 0, WATCH: 1, IGNORE: 2}


def _epss(c):
    e = c.get("epss_score")
    return float(e) if isinstance(e, (int, float)) else 0.0


def classify(c):
    """(bucket, reason) for one CVE annotation, anchored to present fields only."""
    tier = c.get("tier")
    sev = (c.get("severity") or "").upper()
    epss = _epss(c)

    if tier == "installed":
        return IGNORE, "no execution path — deph found no route to the vulnerable code"
    if tier == "linked":
        return WATCH, "linked/present, but no traced call path"

    # tier == reachable: rank by the strongest signal deph actually recorded.
    if c.get("runtime_observed"):
        return ACT, "runtime-confirmed — observed executing"
    if c.get("controllability") == "external-input":
        cls = c.get("reachability_class") or "request"
        return ACT, f"reachable on an externally-controlled path ({cls})"
    if c.get("reachability_class") == "request":
        return ACT, "reachable on the request path"
    if c.get("evidence") == "traced":
        return ACT, "full call path traced from app code"
    if sev == "CRITICAL" or epss >= 0.10:
        return ACT, f"reachable; elevated exploit signal (EPSS {epss:.0%}, {sev or 'unrated'})"
    return WATCH, f"reachable, low exploit signal (EPSS {epss:.0%})"


def build_triage(report):
    """Dedup CVEs by id, keep the strongest bucket across instances, collect packages."""
    g = report["graph"]
    prio = g.get("cve_priority", {})
    best = {}
    for n in g["nodes"].values():
        pkg = n.get("name")
        for c in n.get("cves") or []:
            bucket, reason = classify(c)
            cid = c["id"]
            cur = best.get(cid)
            if cur is None or _RANK[bucket] < _RANK[cur["bucket"]]:
                best[cid] = {
                    "id": cid, "bucket": bucket, "reason": reason,
                    "severity": c.get("severity"), "epss": _epss(c),
                    "priority": prio.get(cid, {}).get("priority"),
                    "packages": {pkg} if pkg else set(),
                }
            elif pkg:
                best[cid]["packages"].add(pkg)
    items = list(best.values())
    for it in items:
        it["packages"] = sorted(it["packages"])
    items.sort(key=lambda x: (_RANK[x["bucket"]], -(x["priority"] or 0)))
    return {
        "total": len(items),
        "counts": {b: sum(1 for it in items if it["bucket"] == b) for b in (ACT, WATCH, IGNORE)},
        "items": items,
    }


def render_markdown(tri, image=None, act_limit=12):
    c = tri["counts"]
    out = [f"## deph triage — {image or 'image'}"]
    out.append(f"**{tri['total']} findings → {c[ACT]} act · {c[WATCH]} watch · {c[IGNORE]} ignore.**")
    out.append("")

    act = [it for it in tri["items"] if it["bucket"] == ACT]
    if act:
        out.append(f"### Act now ({len(act)})")
        for it in act[:act_limit]:
            pkgs = ", ".join(it["packages"][:3]) or "—"
            out.append(f"- `{it['id']}` · {pkgs} · {it['reason']}")
        if len(act) > act_limit:
            out.append(f"- …and {len(act) - act_limit} more")
        out.append("")

    if c[WATCH]:
        out.append(f"### Watch ({c[WATCH]})")
        out.append("Reachable but low signal, or linked without a traced path. "
                   "Revisit if exploited or before a release.")
        out.append("")

    if c[IGNORE]:
        out.append(f"### Safe to ignore ({c[IGNORE]})")
        out.append("deph found **no execution path** to the vulnerable code — present in the "
                   "image, not in your runtime. The bulk of the scanner's noise lands here.")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Deterministic CVE triage over a deph report.")
    ap.add_argument("report")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    args = ap.parse_args()
    with open(args.report) as f:
        report = json.load(f)
    tri = build_triage(report)
    if args.format == "json":
        json.dump(tri, sys.stdout, indent=2)
        print()
    else:
        print(render_markdown(tri, image=report.get("graph", {}).get("image_ref")))


if __name__ == "__main__":
    main()
