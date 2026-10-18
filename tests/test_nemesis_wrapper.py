"""Runs NEMESIS round-1 tests (tests/nemesis_r1_check.py, 14 mutant kills + finding regressions) on this tree."""
import os
import subprocess
import sys
import unittest

import _paths


class NemesisRound1(unittest.TestCase):
    def test_all_checks_pass(self):
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        p = subprocess.run([sys.executable, "-B", os.path.join(_paths.TESTS, "nemesis_r1_check.py"), _paths.ROOT,
                            os.path.join(_paths.ROOT, "fonti")], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0, p.stdout[-2000:] + p.stderr[-2000:])
        self.assertIn("FAILED: 0", p.stdout)


if __name__ == "__main__":
    unittest.main()
