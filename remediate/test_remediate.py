#!/usr/bin/env python3
"""Tests for the remediation layer. Stdlib unittest, no network, no fixtures on disk.

Run:  python3 -m unittest -q     (from this directory)
"""
import json
import os
import sys
import unittest
from unittest import mock

import plan
import tools
import triage
import ssvc

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import authorize  # noqa: E402


def _report(nodes):
    """Minimal deph-report shape: {graph: {nodes, cve_priority}}."""
    return {"graph": {"nodes": nodes, "cve_priority": {}}}


def _node(name, ntype, version, cves, layer="application"):
    return {"id": f"{ntype}:{name}", "type": ntype, "name": name,
            "version": version, "layer_origin": layer, "cves": cves}


def _cve(cid, fix=None, reachable=False, tier="installed", sev="HIGH", cvss=None, epss=None):
    c = {"id": cid, "fix_version": fix, "reachable": reachable, "tier": tier, "severity": sev}
    if cvss:
        c["cvss_vector"] = cvss
    if epss is not None:
        c["epss_score"] = epss
    return c


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


class Downgrade(unittest.TestCase):
    def test_normalizes_go_and_v_prefixes(self):
        self.assertTrue(plan.is_downgrade("v1.44.0", "v1.41.0"))     # real downgrade
        self.assertFalse(plan.is_downgrade("go1.25.7", "1.25.11"))   # real upgrade, kept
        self.assertTrue(plan.is_downgrade("go1.26.3", "1.25.11"))    # already ahead, dropped

    def test_keeps_real_upgrades_in_odd_formats(self):
        self.assertFalse(plan.is_downgrade("2.36-9+deb12u13", "2.36-9+deb12u14"))


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


class Triage(unittest.TestCase):
    def test_ignore_only_on_no_path(self):
        b, r = triage.classify(_cve("X", tier="installed"))
        self.assertEqual(b, triage.IGNORE)
        self.assertIn("no execution path", r)

    def test_linked_is_watch(self):
        self.assertEqual(triage.classify(_cve("X", tier="linked"))[0], triage.WATCH)

    def test_runtime_observed_acts(self):
        c = _cve("X", tier="reachable")
        c["runtime_observed"] = True
        b, r = triage.classify(c)
        self.assertEqual(b, triage.ACT)
        self.assertIn("runtime-confirmed", r)

    def test_external_input_acts(self):
        c = _cve("X", tier="reachable")
        c["controllability"] = "external-input"
        self.assertEqual(triage.classify(c)[0], triage.ACT)

    def test_reachable_low_signal_watches(self):
        c = _cve("X", tier="reachable", sev="MEDIUM")  # no path/exploit signal
        self.assertEqual(triage.classify(c)[0], triage.WATCH)

    def test_cvss_network_unauth_acts(self):
        c = _cve("X", tier="reachable", sev="MEDIUM",
                 cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        b, r = triage.classify(c)
        self.assertEqual(b, triage.ACT)
        self.assertIn("AV:N/PR:N/UI:N", r)

    def test_cvss_local_only_demotes_to_watch(self):
        # Reachable but local-only and not critical/high-EPSS -> watch, with the reason.
        c = _cve("X", tier="reachable", sev="MEDIUM",
                 cvss="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
        b, r = triage.classify(c)
        self.assertEqual(b, triage.WATCH)
        self.assertIn("local access", r)

    def test_cvss_dos_only_watches(self):
        # Network but needs privileges, availability-only impact -> DoS, watch.
        c = _cve("X", tier="reachable", sev="HIGH", epss=0.0,
                 cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H")
        b, r = triage.classify(c)
        self.assertEqual(b, triage.WATCH)
        self.assertIn("DoS", r)

    def test_strongest_bucket_wins_across_packages(self):
        rep = _report({
            "a": _node("dup", "pip-package", "1.0", [_cve("CVE-D", tier="installed")]),
            "b": _node("dup2", "pip-package", "1.0",
                       [dict(_cve("CVE-D", tier="reachable"), evidence="traced")]),
        })
        t = build_triage_local(rep)
        item = next(i for i in t["items"] if i["id"] == "CVE-D")
        self.assertEqual(item["bucket"], triage.ACT)  # reachable instance wins over installed


def build_triage_local(rep):
    return triage.build_triage(rep)


class SSVC(unittest.TestCase):
    NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"   # network, unauth, total
    LOCAL = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # local

    def test_act_requires_open_automatable_total(self):
        c = _cve("X", tier="reachable", cvss=self.NET)
        self.assertEqual(ssvc.ssvc_one(c, net_exposed=True)["decision"], "Act")

    def test_local_vector_is_controlled_not_act(self):
        c = _cve("X", tier="reachable", cvss=self.LOCAL)
        s = ssvc.ssvc_one(c, net_exposed=True)
        self.assertEqual(s["exposure"], "controlled")
        self.assertNotEqual(s["decision"], "Act")

    def test_not_exposed_demotes_out_of_act(self):
        c = _cve("X", tier="reachable", cvss=self.NET)
        self.assertNotEqual(ssvc.ssvc_one(c, net_exposed=False)["decision"], "Act")

    def test_binary_class_not_act(self):
        c = _cve("X", tier="reachable", cvss=self.NET)
        c["reachability_class"] = "binary"
        self.assertEqual(ssvc.ssvc_one(c, net_exposed=True)["exposure"], "controlled")


class Authorize(unittest.TestCase):
    def test_default_when_no_policy(self):
        self.assertTrue(authorize.decide(None, "x", "OWNER")[0])
        self.assertTrue(authorize.decide(None, "x", "COLLABORATOR")[0])
        self.assertFalse(authorize.decide(None, "x", "NONE")[0])
        self.assertFalse(authorize.decide(None, "x", "")[0])

    def test_no_access_block_is_none(self):
        self.assertIsNone(authorize.parse_access("other:\n  x: 1\n"))

    def test_user_allowlist_case_insensitive(self):
        acc = authorize.parse_access("access:\n  associations: []\n  users:\n    - alice\n")
        self.assertTrue(authorize.decide(acc, "Alice", "NONE")[0])   # allowed via users
        self.assertFalse(authorize.decide(acc, "bob", "OWNER")[0])   # associations [] excludes OWNER

    def test_deny_overrides(self):
        acc = authorize.parse_access("access:\n  users: [bob]\n  deny: [bob]\n")
        self.assertFalse(authorize.decide(acc, "bob", "OWNER")[0])

    def test_inline_associations(self):
        acc = authorize.parse_access("access:\n  associations: [MEMBER]\n")
        self.assertTrue(authorize.decide(acc, "x", "MEMBER")[0])
        self.assertFalse(authorize.decide(acc, "x", "COLLABORATOR")[0])


class AgentGuards(unittest.TestCase):
    def test_harden_strips_images_and_defangs_offsite_links(self):
        import agent
        t = ("img ![x](http://evil.test/leak.png) · phish [click](http://evil.test/p) · "
             "ref [nvd](https://nvd.nist.gov/vuln/detail/CVE-1)")
        h = agent.harden_output(t)
        self.assertNotIn("evil.test/leak.png", h)            # image gone
        self.assertIn("`[link removed]`", h)                 # offsite link defanged
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-1", h)  # allowlisted kept

    def test_harden_caps_length(self):
        import agent
        self.assertLessEqual(len(agent.harden_output("a" * 50000, max_chars=100)), 100)

    def test_run_agent_terminates_within_turn_bound(self):
        import agent
        seen = {"n": 0}

        def fake(cfg, messages, spec, max_tokens):  # always asks for a tool -> would loop forever
            seen["n"] += 1
            return {"choices": [{"message": {"tool_calls": [
                {"id": str(seen["n"]), "function": {"name": "posture", "arguments": "{}"}}]}}],
                "usage": {"total_tokens": 10}}

        rep = {"graph": {"nodes": {}, "findings": []}}
        with mock.patch.dict(os.environ, {"DEPH_LLM_MODEL": "x", "DEPH_MAX_TURNS": "3", "DEPH_MAX_TOOL_CALLS": "2"}):
            out = agent.run_agent(rep, "t", _call=fake)
        self.assertIsInstance(out, str)        # terminates, no infinite loop
        self.assertLessEqual(seen["n"], 3)     # bounded by DEPH_MAX_TURNS

    def test_run_agent_stops_on_token_budget(self):
        import agent

        def fake(cfg, messages, spec, max_tokens):
            return {"choices": [{"message": {"tool_calls": [
                {"id": "1", "function": {"name": "posture", "arguments": "{}"}}]}}],
                "usage": {"total_tokens": 100}}

        rep = {"graph": {"nodes": {}, "findings": []}}
        with mock.patch.dict(os.environ, {"DEPH_LLM_MODEL": "x", "DEPH_TOKEN_BUDGET": "50"}):
            out = agent.run_agent(rep, "t", _call=fake)
        self.assertIn("budget", out.lower())


class History(unittest.TestCase):
    def test_valid_turns_kept(self):
        import agent
        raw = json.dumps([{"role": "user", "content": "q1"}, {"role": "assistant", "content": "a1"}])
        h = agent.parse_history(raw)
        self.assertEqual([t["role"] for t in h], ["user", "assistant"])

    def test_garbage_is_dropped_never_raised(self):
        import agent
        self.assertEqual(agent.parse_history(None), [])
        self.assertEqual(agent.parse_history("not json"), [])
        self.assertEqual(agent.parse_history(json.dumps({"role": "user"})), [])  # not a list
        # bad roles / non-string content dropped
        raw = json.dumps([{"role": "system", "content": "x"}, {"role": "user", "content": 5},
                          {"role": "tool", "content": "y"}, {"role": "user", "content": "ok"}])
        self.assertEqual(agent.parse_history(raw), [{"role": "user", "content": "ok"}])

    def test_caps_count_and_length(self):
        import agent
        raw = json.dumps([{"role": "user", "content": "x"} for _ in range(50)])
        self.assertEqual(len(agent.parse_history(raw, max_turns=8)), 8)
        long = json.dumps([{"role": "user", "content": "a" * 9000}])
        self.assertEqual(len(agent.parse_history(long, max_chars=4000)[0]["content"]), 4000)


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
