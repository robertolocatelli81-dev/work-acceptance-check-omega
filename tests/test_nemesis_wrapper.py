"""Runs NEMESIS round-1 tests (tests/nemesis_r1_check.py, 14 mutant kills + finding regressions) on this tree.
The checks were written for profile 1.2.1 and are kept unchanged: they run against a shim that makes this
verifier's 1.2.1 readings (PROFILE_1_2_1) the defaults, and must all pass. Under the 1.3 defaults exactly the six
checks that encode a 1.2.1 reading fail, each for a 1.3 sentence (listed below)."""
import os
import subprocess
import sys
import tempfile
import unittest

import _paths

SHIM = '''import importlib.util, sys
_s = importlib.util.spec_from_file_location("_war_verify_real", %r)
_m = importlib.util.module_from_spec(_s); _s.loader.exec_module(_m)
_m.DEFAULT_OPTIONS.update(_m.PROFILE_1_2_1)
globals().update({k: v for k, v in vars(_m).items() if not k.startswith("__")})
if __name__ == "__main__":
    sys.exit(_m.main(sys.argv))
'''
EXPECTED_1_3_FAILS = {
    "vector 12-signer-is-not-the-checker.json",   # old 12: envelope key_id differs -> SIGNATURE_INVALID (12b replaces)
    "vector 20-producer-undeclared.json",         # 1.3 amended 20: INDEPENDENCE_INCONSISTENT as well
    "M41 producer = signing key id -> KEY_COLLISION",  # the unsigned signature.key_id no longer names the signer
    "M59 x=0 with sign bit refused in rfc8032",   # 1.3 key rule: KEY_REJECTED, not a refusal
    "M60 y>=p refused in rfc8032",                # idem
    "F11 X_WEAK_KEY in extension codes",          # idem: the weak key is rejected, not accepted with a note
}
# Profile 1.4.2 (85a310d, 0.6.0) fixes three cases the checks pinned as refusals while the profile was silent:
# R1 a non-canonical public key is KEY_REJECTED (69), R3 a repeated key_id is KEY_REJECTED (75, 79), R2 an upper-case
# digest matches nothing (67). Under the 1.2.1 readings (--key-rule refuse) M30 and M36 are still refusals; M53 is not:
# no 1.2.1 switch covers the digest form.
EXPECTED_1_4_2_FAILS = {"M30 non-canonical base64 refused", "M36 duplicate key_id refused",
                        "M53 upper-case hex refused"}
EXPECTED_1_2_1_SHIM_FAILS = {"M53 upper-case hex refused"}


def run(d):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    return subprocess.run([sys.executable, "-B", os.path.join(_paths.TESTS, "nemesis_r1_check.py"), d,
                           os.path.join(_paths.ROOT, "fonti")], capture_output=True, text=True, env=env)


class NemesisRound1(unittest.TestCase):
    def test_all_checks_pass_under_the_1_2_1_readings(self):
        with tempfile.TemporaryDirectory() as t:
            with open(os.path.join(t, "war_verify.py"), "w") as fh:
                fh.write(SHIM % os.path.join(_paths.ROOT, "war_verify.py"))
            p = run(t)
        fails = {ln[5:] for ln in p.stdout.splitlines() if ln.startswith("FAIL ")}
        self.assertEqual(fails, EXPECTED_1_2_1_SHIM_FAILS, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("FAILED: %d" % len(EXPECTED_1_2_1_SHIM_FAILS), p.stdout)

    def test_under_1_3_only_the_1_2_1_readings_fail(self):
        p = run(_paths.ROOT)
        fails = {ln[5:] for ln in p.stdout.splitlines() if ln.startswith("FAIL ")}
        self.assertEqual(fails, EXPECTED_1_3_FAILS | EXPECTED_1_4_2_FAILS, p.stdout[-2000:] + p.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
