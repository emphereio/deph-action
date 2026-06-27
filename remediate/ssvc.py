#!/usr/bin/env python3
"""Deterministic SSVC over a deph report — the CISA deployer decision, in code.

SSVC is a decision tree, so the verdict needs no model: each decision point is
computed from a deph signal, and the outcome (Act / Attend / Track) is a documented
function of those points. The AI's job is only the attack-scenario narrative on top.

Decision points (deployer tree):
  Exploitation  none | poc | active     ← KEV, else EPSS (proxy; KEV feed would sharpen)
  Automatable   no | yes                ← CVSS AV:N + AC:L + PR:N + UI:N
  Technical     partial | total         ← CVSS C:H or I:H
  Exposure      small | controlled | open ← reachability + posture (net-facing? local?)

Scope: the reachable set (deph's gate). Installed/linked are out of scope here.
Stdlib only.
"""
import argparse
import json
import os
import sys
from collections import Counter

from triage import _cvss, _epss


def _image_label(report):
    """Local images scan from a tarball, so image_ref is a temp path — clean it."""
    ref = os.environ.get("DEPH_REMEDIATE_IMAGE") or report["graph"].get("image_ref") or "image"
    if ref.endswith(".tar") or ref.startswith("/tmp") or "/tmp." in ref:
        return "the scanned image"
    return ref

_RANK = {"Act": 0, "Attend": 1, "Track": 2}


def exploitation(c):
    if c.get("known_exploited"):
        return "active"
    return "poc" if _epss(c) >= 0.10 else "none"


def automatable(m):
    return "yes" if (m.get("AV") == "N" and m.get("AC") == "L"
                     and m.get("PR") == "N" and m.get("UI") == "N") else "no"


def technical_impact(m):
    return "total" if (m.get("C") == "H" or m.get("I") == "H") else "partial"


def exposure(c, net_exposed):
    """reachable + network-facing ⇒ open; reachable but local/internal ⇒ controlled."""
    if c.get("tier") != "reachable":
        return "small"
    m = _cvss(c.get("cvss_vector"))
    if m.get("AV") in ("L", "P") or c.get("reachability_class") in ("binary", "startup", "background"):
        return "controlled"
    return "open" if net_exposed else "controlled"


def decide(expl, expo, autom, impact):
    """SSVC-deployer-aligned roll-up of the four points. Documented and total."""
    if expl == "active":
        return "Act"
    if expo == "open" and autom == "yes" and impact == "total":
        return "Act"
    if expo == "open" and (autom == "yes" or impact == "total"):
        return "Attend"
    if expo == "open" or expl == "poc":
        return "Attend"
    return "Track"


def ssvc_one(c, net_exposed):
    m = _cvss(c.get("cvss_vector"))
    e, a = exploitation(c), automatable(m)
    i, x = technical_impact(m), exposure(c, net_exposed)
    return {"exploitation": e, "automatable": a, "impact": i, "exposure": x,
            "decision": decide(e, x, a, i)}


def build_ssvc(report, net_exposed=True):
    """Per-CVE SSVC decision over the reachable set, deduped by id (highest decision kept)."""
    g = report["graph"]
    prio = g.get("cve_priority", {})
    best = {}
    for n in g["nodes"].values():
        pkg = n.get("name")
        for c in n.get("cves") or []:
            if c.get("tier") != "reachable":
                continue
            s = ssvc_one(c, net_exposed)
            cid = c["id"]
            cur = best.get(cid)
            if cur is None or _RANK[s["decision"]] < _RANK[cur["decision"]]:
                best[cid] = {"id": cid, "package": pkg, "severity": c.get("severity"),
                             "priority": prio.get(cid, {}).get("priority"), **s}
    items = sorted(best.values(), key=lambda r: (_RANK[r["decision"]], -(r["priority"] or 0)))
    return {"total": len(items),
            "counts": {k: sum(1 for r in items if r["decision"] == k) for k in ("Act", "Attend", "Track")},
            "net_exposed_assumed": net_exposed,
            "items": items}


def _posture_line(report):
    g = report["graph"]
    cfg = [x.get("title") for x in (g.get("findings") or []) if x.get("category") == "config"]
    secrets = sum(1 for x in (g.get("findings") or []) if x.get("category") == "secret")
    eps = sorted({n.get("name") for n in g["nodes"].values() if n.get("type") == "app-entrypoint"})
    bits = []
    if any("root" in (c or "").lower() for c in cfg):
        bits.append("runs as **root**")
    if any("port" in (c or "").lower() for c in cfg):
        bits.append("exposed port")
    if secrets:
        bits.append(f"{secrets} secret(s) in image")
    if eps:
        bits.append("entrypoint: " + ", ".join(eps[:3]))
    return " · ".join(bits) or "posture: limited signal"


def render_markdown(report, net_exposed=True):
    s = build_ssvc(report, net_exposed)
    c = s["counts"]
    out = [f"## deph threat model — {_image_label(report)}"]
    out.append(_posture_line(report))
    out.append("")
    out.append(f"**SSVC (deployer): {c['Act']} Act · {c['Attend']} Attend · {c['Track']} Track** "
               f"over {s['total']} reachable CVEs.")
    if net_exposed:
        out.append("> Assumes the service is network-exposed (not observable from the image). "
                   "If it isn't, `open` exposures drop and most Act → Attend.")
    out.append("")
    act = [r for r in s["items"] if r["decision"] == "Act"]
    if act:
        out.append("| CVE | package | SSVC [expl/auto/impact/expo] |")
        out.append("|---|---|---|")
        for r in act:
            out.append(f"| {r['id']} | {r['package']} | "
                       f"{r['exploitation']}/{r['automatable']}/{r['impact']}/{r['exposure']} |")
    else:
        out.append("No CVE reaches **Act** under SSVC.")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Deterministic SSVC over a deph report.")
    ap.add_argument("report")
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    ap.add_argument("--not-exposed", action="store_true", help="assume the service is NOT network-exposed")
    args = ap.parse_args()
    with open(args.report) as f:
        report = json.load(f)
    if args.format == "json":
        json.dump(build_ssvc(report, not args.not_exposed), sys.stdout, indent=2)
        print()
    else:
        print(render_markdown(report, not args.not_exposed))


if __name__ == "__main__":
    main()
