#!/usr/bin/env python3
"""Tests for the remediation layer. Stdlib unittest, no network, no fixtures on disk.

Run:  python3 -m unittest -q     (from this directory)
"""
import unittest

import plan
import tools


def _report(nodes):
    """Minimal deph-report shape: {graph: {nodes, cve_priority}}."""
    return {"graph": {"nodes": nodes, "cve_priority": {}}}


def _node(name, ntype, version, cves, layer="application"):
    return {"id": f"{ntype}:{name}", "type": ntype, "name": name,
            "version": version, "layer_origin": layer, "cves": cves}


def _cve(cid, fix=None, reachable=False, tier="installed", sev="HIGH"):
    return {"id": cid, "fix_version": fix, "reachable": reachable,
            "tier": tier, "severity": sev}


class VersionCompare(unittest.TestCase):
    def test_ordering(self):
        self.assertTrue(tools.version_le("1.0.0", "1.0.1"))
        self.assertFalse(tools.version_le("2.0", "1.0"))

    def test_ties_are_le(self):
        self.assertTrue(tools.version_le("1.0", "1.0"))
        self.assertTrue(tools.version_le("1.0", "1.0.0"))  # PEP 440 equal

    def test_loose_fallback_does_not_raise(self):
        # Debian-style strings packaging can't parse must still compare.
        self.assertTrue(tools.version_le("2.36-9+deb12u13", "2.36-9+deb12u14"))


class Rollup(unittest.TestCase):
    def setUp(self):
        self.report = _report({
            "pip:flask": _node("flask", "pip-package", "2.0", [
                _cve("CVE-1", fix="2.5", reachable=True, tier="reachable"),
                _cve("CVE-2", fix="3.1", reachable=False),
                _cve("CVE-3", fix=None),  # no fix
            ]),
        })

    def test_target_is_highest_fix(self):
        p = plan.build_plan(self.report)["packages"][0]
        self.assertEqual(p["target_version"], "3.1")

    def test_clears_split_and_unfixable(self):
        out = plan.build_plan(self.report)
        p = out["packages"][0]
        self.assertEqual(len(p["clears"]), 2)
        self.assertEqual(p["reachable_cleared"], 1)
        self.assertEqual([u["id"] for u in out["unfixable"]], ["CVE-3"])

    def test_no_downgrade_or_noop(self):
        # Installed version already at/above the fix -> not an upgrade, must be skipped.
        rep = _report({
            "pip:already": _node("already", "pip-package", "2.0",
                                 [_cve("CVE-X", fix="1.0", reachable=True, tier="reachable")]),
            "pip:noop": _node("noop", "pip-package", "3.1",
                              [_cve("CVE-Y", fix="3.1", reachable=True, tier="reachable")]),
            "pip:real": _node("real", "pip-package", "1.0",
                              [_cve("CVE-Z", fix="2.0", reachable=True, tier="reachable")]),
        })
        names = [p["package"] for p in plan.build_plan(rep)["packages"]]
        self.assertEqual(names, ["real"])

    def test_cves_cleared_is_the_verifier(self):
        # Bumping only to 2.5 clears CVE-1 but not CVE-2 (fix 3.1).
        v = tools.cves_cleared(self.report, "flask", "2.5")
        ids = {c["id"] for c in v["cleared"]}
        self.assertEqual(ids, {"CVE-1"})
        self.assertEqual({c["id"] for c in v["not_cleared"]}, {"CVE-2"})
        self.assertEqual({c["id"] for c in v["no_fix"]}, {"CVE-3"})


class Security(unittest.TestCase):
    def test_safe_token_accepts_real_names(self):
        for ok in ["flask", "good-pkg_1.2", "@scope/name", "2.36-9+deb12u14"]:
            self.assertTrue(plan.safe_token(ok), ok)

    def test_safe_token_rejects_injection(self):
        for bad in ["flask; rm -rf /", "a`whoami`", "x\ny", "..", "a/../b", "**md**", ""]:
            self.assertFalse(plan.safe_token(bad), bad)

    def test_pkg_validation_rejects_traversal_and_newline(self):
        for bad in ["../../etc/passwd", "flask\n", "a b", "a/../b", ".."]:
            self.assertFalse(tools._safe_pkg(bad), bad)

    def test_latest_releases_rejects_before_network(self):
        # Unsafe name must error out without touching the network.
        r = tools.latest_releases("PyPI", "../../etc/passwd")
        self.assertIn("unsafe", r.get("error", ""))

    def test_render_omits_command_for_unsafe_name(self):
        report = _report({"pip:evil": _node(
            "evil; rm -rf / `x`", "pip-package", "1.0",
            [_cve("CVE-9", fix="2.0", reachable=True, tier="reachable")])})
        out = plan.build_plan(report)
        self.assertFalse(out["packages"][0]["name_verified"])
        self.assertIsNone(out["packages"][0]["command"])
        md = plan.render_markdown(out)
        self.assertNotIn("rm -rf / `", md)   # no unescaped backtick-command
        self.assertIn("verify manually", md)


if __name__ == "__main__":
    unittest.main()
