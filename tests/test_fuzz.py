"""Generative attack: ours meets every expectation; the lax control is caught in every family."""
import unittest

import _paths  # noqa: F401
import fuzz


class Fuzz(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = fuzz.run()

    def test_ours_meets_all(self):
        bad = [(r["family"], r["case"]) for r in self.rows if not r["ours_ok"]]
        self.assertEqual(bad, [])
        self.assertGreaterEqual(len(self.rows), 500)

    def test_positive_control_lax_caught_in_every_family(self):
        for fam, _ in fuzz.FAMILIES:
            rs = [r for r in self.rows if r["family"] == fam]
            self.assertTrue(rs, fam)
            self.assertGreater(sum(not r["lax_ok"] for r in rs), 0, fam)


if __name__ == "__main__":
    unittest.main()
