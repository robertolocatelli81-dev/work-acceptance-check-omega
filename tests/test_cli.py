"""Exit codes, including 74 when `cryptography` cannot be imported."""
import json
import os
import subprocess
import sys
import unittest

import _paths

V = os.path.join(_paths.ROOT, "fonti", "upstream_f7d8984", "vectors")
T = os.path.join(_paths.ROOT, "fonti", "tetsurohhori_4f6cf49")
B = os.path.join(_paths.ROOT, "fonti", "babyblueviper1_431525f")
WV = os.path.join(_paths.ROOT, "war_verify.py")


def run(*args, pre=None):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    if pre is None:
        cmd = [sys.executable, "-B", WV] + list(args)
    else:
        code = pre + "; import runpy, sys; sys.argv = %r; runpy.run_path(%r, run_name='__main__')" % ([WV] + list(args), WV)
        cmd = [sys.executable, "-B", "-c", code]
    p = subprocess.run(cmd, capture_output=True, text=True, env=env)
    return p.returncode, p.stdout


class CLI(unittest.TestCase):
    def test_exit_codes(self):
        rc, out = run(os.path.join(V, "01-valid.json"))           # accepted as stated, but local blocks apply
        self.assertEqual(rc, 1)
        rep = json.loads(out)["report"]
        self.assertTrue(rep["accepted_as_stated"])
        self.assertEqual(rep["local_blocks"], ["X_KEY_FROM_INPUT", "X_TEST_KEY", "X_TSA_NOT_VERIFIED"])
        live = os.path.join(_paths.ROOT, "fonti", "issuer_274159c")
        self.assertEqual(run("--keys", os.path.join(live, "checker-keys-live.json"), "--tokens", "pkix", "--tsa-roots",
                             os.path.join(_paths.ROOT, "roots", "freetsa_cacert.pem"),
                             os.path.join(live, "selftest-pass.json"))[0], 0)
        self.assertEqual(run("--keys", "", os.path.join(V, "01-valid.json"))[0], 64)
        self.assertEqual(run("--tokens", "structural", "--tokens", "structural", os.path.join(V, "01-valid.json"))[0], 64)
        self.assertEqual(run("--tsa-roots", "roots", os.path.join(V, "01-valid.json"))[0], 64)
        self.assertEqual(run(os.path.join(V, "02-criteria-committed-after-issue.json"))[0], 1)
        self.assertEqual(run(os.path.join(T, "21-unknown-schema.json"))[0], 2)
        self.assertEqual(run("--vector", os.path.join(V, "01-valid.json"))[0], 0)
        self.assertEqual(run("--vector", os.path.join(B, "22-matching-record-token-later-than-issued.json"))[0], 3)
        self.assertEqual(run("--vector", "--reference-time", "earlier",
                             os.path.join(B, "22-matching-record-token-later-than-issued.json"))[0], 0)
        self.assertEqual(run()[0], 64)
        self.assertEqual(run("--tokens", "pkix", os.path.join(V, "01-valid.json"))[0], 64)
        self.assertEqual(run("--bogus", os.path.join(V, "01-valid.json"))[0], 64)
        self.assertEqual(run("/nonexistent.json")[0], 74)

    def test_exit_74_without_cryptography_full_report(self):
        rc, out = run(os.path.join(V, "02-criteria-committed-after-issue.json"),
                      pre="import sys; sys.modules['cryptography'] = None")
        self.assertEqual(rc, 74)
        rep = json.loads(out)["report"]
        self.assertTrue(rep["cannot_run"])
        self.assertIsNone(rep["signature_valid"])
        self.assertFalse(rep["accepted_as_stated"])
        self.assertEqual(rep["problem_codes"], ["CRITERIA_COMMITTED_AFTER_CHECK"])   # the other checks still ran

    def test_exit_74_unreadable_roots_full_report(self):
        rc, out = run("--tokens", "pkix", "--tsa-roots", "/nonexistent",
                      os.path.join(_paths.ROOT, "fonti", "issuer_274159c", "selftest-pass.json"))
        self.assertEqual(rc, 74)
        rep = json.loads(out)["report"]
        self.assertIn("CRITERIA_COMMITMENT_UNVERIFIED", rep["warning_codes"])
        self.assertTrue(rep["signature_valid"])

    def test_refused_before_crypto_needs_no_crypto(self):
        rc, _ = run(os.path.join(T, "21-unknown-schema.json"), pre="import sys; sys.modules['cryptography'] = None")
        self.assertEqual(rc, 2)

    def test_refusal_report(self):
        rc, out = run(os.path.join(T, "21-unknown-schema.json"))
        rep = json.loads(out)["report"]
        self.assertEqual(rep["reason"], "unknown schema, canonicalization or suite")


if __name__ == "__main__":
    unittest.main()
