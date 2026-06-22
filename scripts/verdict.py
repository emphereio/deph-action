#!/usr/bin/env python3
"""Turn a deph JSON report into a digest-bound path verdict + Markdown summary.

Reads the deph report named by DEPH_REPORT_JSON, writes verdict.json and
summary.md, appends the summary to GITHUB_STEP_SUMMARY, and prints a single
JSON line of scalar values that run.sh forwards to the action outputs.

The public language is deliberately honest: deph reports what it *found in the
execution path*, what is *linked/present*, and what it *found no path to* — never
a claim of proof that something is safe or unreachable.
"""
import json
import os
import sys

# deph CVE tiers, strongest first. Mirrors internal/scan/result.go buildResult:
# dedupe CVEs by ID, keep the most-reachable tier, skip VEX-suppressed.
TIER_RANK = {"reachable": 3, "linked": 2, "installed": 1}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NEGLIGIBLE": 0, "UNKNOWN": 0}


def env(name, default=""):
    return os.environ.get(name, default)


def load_report(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def collect_cves(report):
    """Return {cve_id: best_annotation} keyed by most-reachable, non-suppressed tier."""
    graph = report.get("graph", {}) or {}
    nodes = graph.get("nodes", {}) or {}
    priority = graph.get("cve_priority", {}) or {}
    best = {}
    for node in nodes.values():
        for cve in node.get("cves", []) or []:
            if cve.get("vex_suppressed"):
                continue
            cid = cve.get("id")
            if not cid:
                continue
            rank = TIER_RANK.get(cve.get("tier", ""), 0)
            cur = best.get(cid)
            if cur is None or rank > TIER_RANK.get(cur.get("tier", ""), 0):
                best[cid] = cve
    return best, priority


def top_call(cve):
    chains = cve.get("call_chains") or []
    if not chains:
        return ""
    c = chains[0]
    return f"{c.get('file','')}:{c.get('function','')}:{c.get('line','')}".strip(":")


def in_path_entry(cve, priority):
    cid = cve.get("id")
    pr = (priority.get(cid) or {}).get("priority", 0) if cid else 0
    return {
        "id": cid,
        "severity": (cve.get("severity") or "UNKNOWN").upper(),
        "cvss": cve.get("cvss_score"),
        "epss": cve.get("epss_score"),
        "kev": bool(cve.get("known_exploited")),
        "fix_version": cve.get("fix_version", ""),
        "evidence": cve.get("evidence", ""),
        "reachable_from": cve.get("reachable_from", []) or [],
        "top_call": top_call(cve),
        "priority": pr,
    }


def evaluate_gate(policy, in_path_cves):
    if policy == "none" or not in_path_cves:
        return False, ""
    if policy == "any-reachable":
        return True, f"{len(in_path_cves)} CVE(s) in the execution path"
    if policy == "reachable-critical":
        n = sum(1 for c in in_path_cves if c["severity"] == "CRITICAL")
        return (n > 0), (f"{n} in-path CRITICAL" if n else "")
    if policy == "reachable-high":
        n = sum(1 for c in in_path_cves if c["severity"] in ("CRITICAL", "HIGH"))
        return (n > 0), (f"{n} in-path CRITICAL/HIGH" if n else "")
    return False, ""


def render_summary(verdict):
    s = verdict["summary"]
    img = verdict["image"]
    ref = img["ref"]
    digest = img.get("digest", "")
    shown = f"{ref}@{digest}" if digest else ref
    lines = []
    lines.append("## deph — what's in your execution path")
    lines.append("")
    lines.append(f"image `{shown}`")
    if img.get("digest_kind"):
        lines.append(f"<sub>digest binding: {img['digest_kind']}</sub>")
    lines.append("")
    lines.append(
        f"**{s['total']}** known CVEs · "
        f"**{s['in_path']}** in your execution path · "
        f"{s['linked']} linked/present · "
        f"{s['not_found_in_path']} no path found"
    )
    lines.append("")
    cves = verdict["in_path_cves"]
    if cves:
        lines.append("| in-path CVE | severity | fix | evidence |")
        lines.append("|---|---|---|---|")
        for c in cves[:25]:
            fix = c["fix_version"] or "—"
            ev = c["evidence"] or "—"
            frm = c["reachable_from"][0] if c["reachable_from"] else ""
            ev_txt = f"{ev}: {frm}" if frm else ev
            kev = " · KEV" if c["kev"] else ""
            lines.append(f"| {c['id']}{kev} | {c['severity']} | {fix} | {ev_txt} |")
        if len(cves) > 25:
            lines.append("")
            lines.append(f"…and {len(cves) - 25} more in-path CVEs (see verdict.json).")
    else:
        lines.append("No known CVEs were found in the execution path.")
    lines.append("")
    nfp = s["not_found_in_path"]
    if nfp:
        verb = "is" if nfp == 1 else "are"
        lines.append(
            f"{nfp} CVE{'' if nfp == 1 else 's'} {verb} present but deph found "
            "no execution path to the affected code."
        )
    gate = verdict["gate"]
    if gate["tripped"]:
        lines.append("")
        lines.append(f"❌ **gate `{gate['policy']}` failed** — {gate['reason']}")
    lines.append("")
    lines.append(
        f"<sub>deph {verdict['producer']['deph_version']} · "
        f"run #{verdict['source'].get('run_id','')}</sub>"
    )
    lines.append("<!-- deph-action -->")
    return "\n".join(lines) + "\n"


def main():
    report = load_report(env("DEPH_REPORT_JSON"))
    best, priority = collect_cves(report)

    in_path, linked, not_found = [], 0, 0
    for cve in best.values():
        tier = cve.get("tier", "")
        if tier == "reachable":
            in_path.append(in_path_entry(cve, priority))
        elif tier == "linked":
            linked += 1
        else:
            not_found += 1

    in_path.sort(key=lambda c: (c["priority"] or 0, SEV_RANK.get(c["severity"], 0)), reverse=True)

    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for c in in_path:
        key = c["severity"].lower()
        if key in by_sev:
            by_sev[key] += 1

    policy = env("DEPH_FAIL_ON", "none")
    tripped, reason = evaluate_gate(policy, in_path)

    verdict = {
        "schema_version": "1.0.0",
        "producer": {
            "name": "deph-action",
            "version": env("DEPH_ACTION_VERSION", "1.0.0"),
            "deph_version": env("DEPH_VERSION", ""),
        },
        "image": {
            "ref": env("DEPH_IMAGE_REF"),
            "digest": env("DEPH_IMAGE_DIGEST_RESOLVED"),
            "digest_kind": env("DEPH_IMAGE_DIGEST_KIND"),
            "source_mode": env("DEPH_SOURCE_MODE"),
        },
        "source": {
            "repository": env("GITHUB_REPOSITORY"),
            "ref": env("GITHUB_REF"),
            "sha": env("GITHUB_SHA"),
            "run_id": env("GITHUB_RUN_ID"),
            "run_attempt": env("GITHUB_RUN_ATTEMPT"),
            "workflow": env("GITHUB_WORKFLOW"),
            "event": env("GITHUB_EVENT_NAME"),
        },
        "summary": {
            "total": len(in_path) + linked + not_found,
            "in_path": len(in_path),
            "linked": linked,
            "not_found_in_path": not_found,
            "in_path_by_severity": by_sev,
            "kev_in_path": sum(1 for c in in_path if c["kev"]),
            "fixable_in_path": sum(1 for c in in_path if c["fix_version"]),
        },
        "in_path_cves": in_path,
        "gate": {"policy": policy, "tripped": tripped, "reason": reason},
        "deph_exit": int(env("DEPH_EXIT", "0") or 0),
        "artifacts": {
            "report_json": env("DEPH_REPORT_JSON"),
            "report_html": env("DEPH_REPORT_HTML"),
            "sarif": env("DEPH_SARIF_OUT"),
            "sbom_cyclonedx": env("DEPH_SBOM_OUT"),
            "summary_md": env("DEPH_SUMMARY_MD"),
        },
    }

    with open(env("DEPH_VERDICT_JSON"), "w", encoding="utf-8") as fh:
        json.dump(verdict, fh, indent=2)
        fh.write("\n")

    summary = render_summary(verdict)
    with open(env("DEPH_SUMMARY_MD"), "w", encoding="utf-8") as fh:
        fh.write(summary)
    step_summary = env("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as fh:
            fh.write(summary)

    # One JSON line of scalars for run.sh -> action outputs.
    print(json.dumps({
        "total": verdict["summary"]["total"],
        "in_path": verdict["summary"]["in_path"],
        "linked": verdict["summary"]["linked"],
        "not_found_in_path": verdict["summary"]["not_found_in_path"],
        "gate_tripped": "true" if tripped else "false",
        "gate_reason": reason,
    }))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 — surface a clean error to the runner
        print(f"deph-action: verdict generation failed: {exc}", file=sys.stderr)
        sys.exit(2)
