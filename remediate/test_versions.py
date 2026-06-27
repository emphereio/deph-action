#!/usr/bin/env python3
"""Version-comparison fuzz + cross-ecosystem correctness.

The comparator is load-bearing (fix-path + cves_cleared). It must: order common
ecosystem formats correctly, never crash on garbage, and — when `packaging` is
present — be PEP 440-correct including pre-releases.

Run:  python3 -m unittest -q   (from this directory)
"""
import unittest

import plan
import tools

# (cur, target, is_downgrade) — cases the loose fallback must get right.
DOWNGRADE_CASES = [
    ("2.36-9+deb12u13", "2.36-9+deb12u14", False),  # deb revision up
    ("2.36-9+deb12u14", "2.36-9+deb12u13", True),   # deb revision down
    ("1.2.3-r0", "1.2.3-r1", False),                # alpine -r up
    ("1.2.3-r2", "1.2.3-r1", True),                 # alpine -r down
    ("go1.25.7", "1.25.11", False),                 # go prefix, real upgrade
    ("go1.26.3", "1.25.11", True),                  # go ahead of fix
    ("v1.44.0", "v1.41.0", True),                   # semver v-prefix down
    ("1.2.3", "1.2.4", False),                      # semver up
    ("2.0", "1.0", True),                           # simple down
    ("1.0", "1.0", True),                           # equal -> treated as no-op (downgrade-ish)
    ("3.1.4-1.el8", "3.1.4-2.el8", False),          # rpm release up
]

GARBAGE = ["", "   ", ".", "-", "1.", "..1", "∞", "1.0\n", "🚀", "a" * 500,
           "1:2:3", "x.y.z", "NaN", "-1", None]


class VersionCompare(unittest.TestCase):
    def test_cross_ecosystem_downgrade_detection(self):
        for cur, target, expected in DOWNGRADE_CASES:
            self.assertEqual(plan.is_downgrade(cur, target), expected, f"{cur} -> {target}")

    def test_max_version_returns_member(self):
        self.assertEqual(plan.max_version(["1.0", "2.0", "1.5"]), "2.0")
        self.assertEqual(plan.max_version(["2.36-9+deb12u13", "2.36-9+deb12u14"]), "2.36-9+deb12u14")

    def test_version_le(self):
        self.assertTrue(tools.version_le("1.0.0", "1.0.1"))
        self.assertFalse(tools.version_le("2.0", "1.0"))
        self.assertTrue(tools.version_le("1.0", "1.0"))

    def test_never_crashes_on_garbage(self):
        for v in GARBAGE:
            for other in ("1.0", v):
                try:
                    plan.is_downgrade(v, other)
                    tools.version_le(v, other)
                    plan.max_version([x for x in (v, other) if x is not None] or ["1.0"])
                except Exception as e:  # noqa: BLE001
                    self.fail(f"crashed comparing {v!r}/{other!r}: {type(e).__name__}: {e}")

    @unittest.skipUnless(_HAVE_PACKAGING := __import__("importlib").util.find_spec("packaging"),
                         "packaging not installed")
    def test_pep440_prerelease_when_packaging_present(self):
        # pre-release precedes its release: 1.0a1 -> 1.0 is an UPGRADE (not a downgrade)
        self.assertFalse(plan.is_downgrade("1.0a1", "1.0"))
        self.assertTrue(plan.is_downgrade("1.0", "1.0a1"))


if __name__ == "__main__":
    unittest.main()
