#!/usr/bin/env python3
"""Robustness + golden tests for the deterministic pipeline.

Robustness: no malformed report shape may crash any entrypoint.
Golden: a fixed synthetic report pins exact triage/SSVC/plan outputs so behavior
can't silently drift.

Run:  python3 -m unittest -q   (from this directory)
"""
import unittest

import plan
import triage
import ssvc
import tools

# A fixed report with hand-computed expected outcomes.
GOLDEN = {"graph": {
    "image_ref": "test:img", "os_family": "debian",
    "cve_priority": {"CVE-A": {"priority": 50}},
    "findings": [{"category": "config", "severity": "high", "title": "Container runs as root"}],
    "nodes": {
        "pip:flask": {"type": "pip-package", "name": "flask", "version": "2.0.0",
                      "layer_origin": "application", "cves": [
            {"id": "CVE-A", "tier": "reachable", "reachable": True, "evidence": "traced",
             "severity": "HIGH", "fix_version": "2.5.0",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "epss_score": 0.02},
            {"id": "CVE-B", "tier": "reachable", "reachable": True, "severity": "MEDIUM",
             "fix_version": "3.1.0", "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            {"id": "CVE-C", "tier": "installed", "reachable": False, "severity": "LOW"},
        ]},
        "os:libc6": {"type": "os-package", "name": "libc6", "version": "2.0",
                     "layer_origin": "base-image", "cves": [
            {"id": "CVE-D", "tier": "reachable", "reachable": True, "severity": "HIGH",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"},
        ]},
    },
}}

MALFORMED = [
    {}, None, {"x": 1}, {"graph": "nope"}, {"graph": []}, {"graph": {"nodes": None}},
    {"graph": {"nodes": "x"}}, {"graph": {"nodes": {"n": "x"}}},
    {"graph": {"nodes": {"n": {"cves": "x"}}}},
    {"graph": {"nodes": {"n": {"cves": ["x", {"id": "C", "tier": "reachable"}]}}}},
    {"graph": {"nodes": {"n": {"type": "pip-package", "name": "p", "cves": [{"tier": "reachable"}]}}}},
]


class Robustness(unittest.TestCase):
    def test_no_entrypoint_crashes_on_malformed(self):
        calls = [
            lambda r: plan.build_plan(r),
            lambda r: plan.render_markdown(plan.build_plan(r)),
            lambda r: triage.build_triage(r),
            lambda r: triage.render_markdown(triage.build_triage(r)),
            lambda r: ssvc.build_ssvc(r),
            lambda r: ssvc.render_markdown(r),
            lambda r: tools.posture(r),
            lambda r: tools.graph_query(r),
            lambda r: tools.cves_cleared(r, "p", "1.0"),
            lambda r: tools.cve_context(r, "C"),
            lambda r: tools.explain_reachability(r, "C"),
        ]
        for r in MALFORMED:
            for fn in calls:
                try:
                    fn(r)
                except Exception as e:  # noqa: BLE001
                    self.fail(f"crashed on {r!r}: {type(e).__name__}: {e}")


class Golden(unittest.TestCase):
    def test_triage_buckets(self):
        c = triage.build_triage(GOLDEN)["counts"]
        # CVE-A traced+AV:N -> act; CVE-D net-unauth -> act; CVE-B AV:L -> watch; CVE-C installed -> ignore
        self.assertEqual(c, {"act": 2, "watch": 1, "ignore": 1})

    def test_ssvc_decisions(self):
        c = ssvc.build_ssvc(GOLDEN)["counts"]
        # CVE-A open/automatable/total -> Act; CVE-D open/automatable/partial(DoS) -> Attend; CVE-B local -> Track
        self.assertEqual(c, {"Act": 1, "Attend": 1, "Track": 1})

    def test_ssvc_not_exposed_demotes(self):
        c = ssvc.build_ssvc(GOLDEN, net_exposed=False)["counts"]
        self.assertEqual(c["Act"], 0)  # nothing is open when not network-exposed

    def test_plan_rollup(self):
        p = plan.build_plan(GOLDEN)
        self.assertEqual(len(p["packages"]), 1)
        pkg = p["packages"][0]
        self.assertEqual(pkg["package"], "flask")
        self.assertEqual(pkg["target_version"], "3.1.0")     # max of 2.5.0, 3.1.0
        self.assertEqual(pkg["reachable_cleared"], 2)
        self.assertIn("CVE-D", {u["id"] for u in p["unfixable"]})  # libc6, no fix

    def test_cves_cleared_verifier(self):
        v = tools.cves_cleared(GOLDEN, "flask", "2.5.0")
        self.assertEqual({c["id"] for c in v["cleared"]}, {"CVE-A"})   # CVE-B fix 3.1 > 2.5
        self.assertEqual({c["id"] for c in v["not_cleared"]}, {"CVE-B"})


if __name__ == "__main__":
    unittest.main()
