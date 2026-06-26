#!/usr/bin/env python3
"""Tools the remediation agent reasons with.

Two kinds, deliberately:

  deterministic (truth, reproducible) — read deph's report and verify version math.
    The agent never gets trusted for "this bump clears these CVEs"; it proposes a
    target and `cves_cleared` decides what that actually clears.

  live (fresh, advisory) — reach the registry for versions newer than the scan DB.
    Timestamped and labelled; this is where the agent earns its keep.

Stdlib only: no anthropic/packaging/requests. `packaging` is used if present for
correct PEP 440 ordering, else a loose fallback.
"""
import json
import re
import urllib.parse
import urllib.request
import urllib.error

from plan import build_plan, max_version, _loose, eco_label
from triage import build_triage

# Package names that reach a registry URL. Conservative on purpose: covers pip,
# npm (incl. @scope/name), deb, etc.; rejects anything that could escape the path.
# \Z (not $) so a trailing newline can't sneak through.
_PKG_RE = re.compile(r"\A[@A-Za-z0-9][A-Za-z0-9._@/-]{0,127}\Z")
_MAX_HTTP_BYTES = 5_000_000


def _safe_pkg(package):
    return isinstance(package, str) and bool(_PKG_RE.match(package)) and ".." not in package


# ── version comparison (deterministic) ────────────────────────────────────────

def version_le(a, b):
    """True if a <= b for same-ecosystem versions (how deph groups them)."""
    if a == b:
        return True
    try:
        from packaging.version import Version
        return Version(a) <= Version(b)
    except Exception:
        return _loose(a) <= _loose(b)


# ── deterministic tools over the report ───────────────────────────────────────

def _iter_cves(report):
    g = report["graph"]
    prio = g.get("cve_priority", {})
    for n in g["nodes"].values():
        for c in n.get("cves") or []:
            yield n, c, prio.get(c["id"], {}).get("priority")


def graph_query(report, tier=None, reachable=None, severity=None, layer=None, limit=50):
    """Filtered CVE list. All filters optional; AND-combined."""
    out = []
    for n, c, p in _iter_cves(report):
        if tier and c.get("tier") != tier:
            continue
        if reachable is not None and bool(c.get("reachable")) != reachable:
            continue
        if severity and (c.get("severity") or "").upper() != severity.upper():
            continue
        if layer and c.get("layer_origin") != layer:
            continue
        out.append({
            "id": c["id"], "package": n.get("name"), "ecosystem": eco_label(n.get("type", "")),
            "version": n.get("version"), "severity": c.get("severity"), "tier": c.get("tier"),
            "reachable": bool(c.get("reachable")), "priority": p,
            "fix_version": c.get("fix_version"), "layer_origin": c.get("layer_origin"),
            "epss": c.get("epss_score"),
        })
    out.sort(key=lambda x: (x["priority"] or 0), reverse=True)
    return out[:limit]


def cves_cleared(report, package, target_version):
    """THE VERIFIER. Given a proposed target, which of `package`'s CVEs clear?

    Deterministic: a CVE clears iff it has a fix_version and fix_version <= target.
    This is what keeps the agent honest — it proposes the target, this decides.
    """
    cleared, not_cleared, nofix = [], [], []
    found = False
    for n, c, p in _iter_cves(report):
        if n.get("name") != package:
            continue
        found = True
        row = {"id": c["id"], "severity": c.get("severity"), "reachable": bool(c.get("reachable")),
               "priority": p, "fix_version": c.get("fix_version")}
        fv = c.get("fix_version")
        if not fv:
            nofix.append(row)
        elif version_le(fv, target_version):
            cleared.append(row)
        else:
            not_cleared.append(row)
    return {
        "package": package, "target_version": target_version, "exists": found,
        "cleared": cleared, "cleared_count": len(cleared),
        "cleared_reachable": sum(1 for r in cleared if r["reachable"]),
        "not_cleared": not_cleared, "no_fix": nofix,
    }


def package_remediation(report, package):
    """The per-package rollup from the deterministic plan."""
    plan = build_plan(report)
    for p in plan["packages"]:
        if p["package"] == package:
            return p
    return {"package": package, "note": "no fixable CVEs found on this package"}


def plan_remediation(report):
    """The whole-image deterministic plan."""
    return build_plan(report)


def posture(report):
    """The image's deployment posture — the threat-model context that sits beside
    reachability: what runs, how it's configured, and what's dangerous in the image.
    These are the facts that turn 'reachable' into 'realistically exploitable here'."""
    g = report["graph"]
    by_cat = {}
    for x in g.get("findings") or []:
        by_cat.setdefault(x.get("category", "?"), []).append(
            {"severity": x.get("severity"), "title": x.get("title")})
    eps = [n.get("name") for n in g["nodes"].values() if n.get("type") == "app-entrypoint"]
    inv = [n.get("name") for n in g["nodes"].values() if n.get("type") == "binary-invocation"]
    return {
        "image": g.get("image_ref"), "platform": g.get("os_family"),
        "entrypoints": eps, "invocations": sorted(set(inv))[:20],
        "config": by_cat.get("config", []),
        "secrets": len(by_cat.get("secret", [])),
        "secret_titles": [s["title"] for s in by_cat.get("secret", [])][:5],
        "supply_chain": {k: len(by_cat.get(k, []))
                         for k in ("ghost-binary", "lifecycle-hook", "typosquat",
                                   "phantom-dep", "execution-surface") if by_cat.get(k)},
    }


def cve_context(report, cve_id):
    """Everything a human analyst reads to judge a CVE in context: the description,
    CVSS vector, EPSS, the reachable-from path, the affected package/version, and
    the image + platform. The deterministic reachability is the gate; this is the
    material the AI reasons over WITHIN that gate."""
    g = report["graph"]
    instances, src = [], None
    for n in g["nodes"].values():
        for c in n.get("cves") or []:
            if c["id"] != cve_id:
                continue
            src = c
            instances.append({
                "package": n.get("name"), "version": n.get("version"),
                "node_type": n.get("type"), "tier": c.get("tier"),
                "evidence": c.get("evidence"), "reachability_class": c.get("reachability_class"),
                "controllability": c.get("controllability"),
                "reachable_from": (c.get("reachable_from") or [])[:12],
                "layer_origin": c.get("layer_origin"),
            })
    if not src:
        return {"cve": cve_id, "note": "not found"}
    return {
        "cve": cve_id,
        "description": src.get("summary"),
        "severity": src.get("severity"),
        "cvss_vector": src.get("cvss_vector"),
        "cvss_score": src.get("cvss_score"),
        "epss": src.get("epss_score"),
        "fix_version": src.get("fix_version"),
        "image": g.get("image_ref"),
        "platform": g.get("os_family"),
        "instances": instances,
    }


def explain_reachability(report, cve_id):
    """Reachability evidence for one CVE: where it sits and how deph reached it."""
    hits = []
    for n, c, p in _iter_cves(report):
        if c["id"] != cve_id:
            continue
        hits.append({
            "package": n.get("name"), "node": n.get("id"),
            "tier": c.get("tier"), "reachable": bool(c.get("reachable")),
            "evidence": c.get("evidence"), "reachability_class": c.get("reachability_class"),
            "controllability": c.get("controllability"),
            "runtime_observed": bool(c.get("runtime_observed")),
            "reachable_from": c.get("reachable_from"),
            "layer_origin": c.get("layer_origin"), "priority": p,
        })
    return {"cve": cve_id, "instances": hits} if hits else {"cve": cve_id, "note": "not found"}


# ── live tool (fresh, advisory) ───────────────────────────────────────────────

def latest_releases(ecosystem, package, timeout=8):
    """Versions the scan DB may not know yet. Currently PyPI + npm.

    Returns the latest stable + a few recent, with the source and a freshness note.
    Advisory by construction: the result is point-in-time, not reproducible.
    """
    eco = (ecosystem or "").lower()
    if not _safe_pkg(package):
        return {"ecosystem": ecosystem, "package": package, "error": "rejected: unsafe package name"}
    quoted = urllib.parse.quote(package, safe="@/")
    try:
        if eco in ("pypi", "pip", "python"):
            d = _get_json(f"https://pypi.org/pypi/{quoted}/json", timeout)
            rels = [v for v, files in d.get("releases", {}).items()
                    if files and not all(f.get("yanked") for f in files)]
            stable = [v for v in rels if not any(ch in v for ch in ("a", "b", "rc", "dev"))]
            latest = max_version(stable or rels) if (stable or rels) else None
            return {"ecosystem": "PyPI", "package": package, "source": "pypi.org",
                    "latest_stable": latest, "info_version": d.get("info", {}).get("version"),
                    "recent": sorted(stable, key=_loose, reverse=True)[:5], "note": "live, advisory"}
        if eco in ("npm", "node"):
            d = _get_json(f"https://registry.npmjs.org/{quoted}", timeout)
            return {"ecosystem": "npm", "package": package, "source": "registry.npmjs.org",
                    "latest_stable": d.get("dist-tags", {}).get("latest"), "note": "live, advisory"}
        return {"ecosystem": ecosystem, "package": package,
                "note": f"live lookup not implemented for {ecosystem} yet"}
    except urllib.error.HTTPError as e:
        return {"ecosystem": ecosystem, "package": package, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"ecosystem": ecosystem, "package": package, "error": str(e)}


def _get_json(url, timeout):
    """GET a JSON document with a bounded read. URL host is fixed by the caller;
    only the (validated, quoted) package path varies."""
    req = urllib.request.Request(url, headers={"accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read(_MAX_HTTP_BYTES))


# ── registry the agent dispatches against ─────────────────────────────────────

# Each entry: (callable, needs_report, json-schema of args for the Anthropic tools API)
REGISTRY = {
    "graph_query": (graph_query, True, {
        "type": "object",
        "properties": {
            "tier": {"type": "string", "enum": ["reachable", "linked", "installed"]},
            "reachable": {"type": "boolean"},
            "severity": {"type": "string"},
            "layer": {"type": "string", "enum": ["base-image", "application"]},
            "limit": {"type": "integer"},
        },
    }),
    "cves_cleared": (cves_cleared, True, {
        "type": "object",
        "properties": {"package": {"type": "string"}, "target_version": {"type": "string"}},
        "required": ["package", "target_version"],
    }),
    "package_remediation": (package_remediation, True, {
        "type": "object", "properties": {"package": {"type": "string"}}, "required": ["package"],
    }),
    "plan_remediation": (plan_remediation, True, {"type": "object", "properties": {}}),
    "triage": (build_triage, True, {"type": "object", "properties": {}}),
    "posture": (posture, True, {"type": "object", "properties": {}}),
    "explain_reachability": (explain_reachability, True, {
        "type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"],
    }),
    "cve_context": (cve_context, True, {
        "type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"],
    }),
    "latest_releases": (latest_releases, False, {
        "type": "object",
        "properties": {"ecosystem": {"type": "string"}, "package": {"type": "string"}},
        "required": ["ecosystem", "package"],
    }),
}

TOOL_DESCRIPTIONS = {
    "graph_query": "Filter deph's CVEs by tier/reachable/severity/layer. Deterministic.",
    "cves_cleared": "VERIFIER: given a package and a proposed target version, return exactly which CVEs that bump clears. Always use this to check a target before recommending it. Deterministic.",
    "package_remediation": "The deterministic rollup for one package (its computed target + cleared CVEs).",
    "plan_remediation": "The whole-image deterministic remediation plan (ranked upgrades + stats).",
    "triage": "Deterministic triage: every CVE bucketed act/watch/ignore with an anchored reason. The buckets are authoritative — never soften them.",
    "posture": "The image's deployment posture: what runs (entrypoints/invocations), how it's configured (runs-as-root, exposed ports), secrets in the image, and supply-chain findings. The context for threat modeling.",
    "explain_reachability": "Reachability evidence for one CVE: tier, evidence, call path, runtime. Deterministic.",
    "cve_context": "Everything an analyst reads about one CVE: description, CVSS vector, EPSS, the reachable-from path, package/version, and the image + platform. Use it to judge real-world exploitability in THIS image.",
    "latest_releases": "LIVE registry lookup for versions newer than the scan DB. Advisory, point-in-time.",
}


def tool_list():
    """Provider-neutral tool catalog. Wire-format adapters (OpenAI/MCP/etc.)
    build their own shapes from this — the tools are the contract, the model
    and protocol are the caller's choice."""
    return [{"name": name, "description": TOOL_DESCRIPTIONS[name], "schema": schema}
            for name, (_fn, _needs, schema) in REGISTRY.items()]


def dispatch(name, args, report):
    fn, needs_report, _schema = REGISTRY[name]
    return fn(report, **args) if needs_report else fn(**args)
