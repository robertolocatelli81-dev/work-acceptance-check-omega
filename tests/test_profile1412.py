"""Profile 1.4.12 (maximusrufus/work-acceptance-record@5f7517a, step 4, vectors 127-128): text only, no change of code in 0.12.0.
Oracle: the vectors and the sentences of step 4 at 5f7517a (README of this project, "Profile 1.4.12"); never the verifier's own
output. Positive control: on a copy of 0.12.0 whose default of --criteria-noncharacters is `unreadable`, the tests of 127 and 128
fail (README, "Tests")."""
import inspect
import os
import subprocess
import sys
import unittest

import _paths  # noqa: F401
import score
import test_profile147 as v
import test_profile1411 as y
import war_verify as wv

SET = "5f7517a"
UNREADABLE, NOTE = y.UNREADABLE, y.NOTE
PROBLEMS_OF_01 = ([], [], "match", True, "pass", "pass")     # the `expected` of 127 and 128: "readable, no problems"


def outcome(rep):
    return (rep["problem_codes"], rep["warning_codes"], rep["criteria_hash"], rep["signature_valid"], rep["verdict_recomputed"],
            rep["verdict_stated"])


class Vectors5f7517a(unittest.TestCase):
    def test_129_of_129(self):
        rows = score.score(which=SET)
        self.assertEqual((len(rows), sum(r["agree"] for r in rows)), (129, 129), v.nums(rows))
        self.assertEqual((sum(r["fields_agree"] for r in rows), sum(r["fields"] for r in rows)), (1175, 1175))

    def test_the_default_set_is_5f7517a(self):
        self.assertEqual(score.vector_files(), score.vector_files(SET))
        files = score.vector_files(SET)
        self.assertEqual(len(files), 129)
        self.assertEqual([y.num(f) for f in files[126:128]], [127, 128])
        self.assertTrue(all("upstream_5f7517a" in f for f in files[126:128]))
        self.assertEqual(files[:126] + files[128:], score.vector_files("8ce7f42"))
        self.assertEqual(inspect.signature(score.score).parameters["which"].default, SET)      # the library default
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        p = subprocess.run([sys.executable, "-B", os.path.join(score.ROOT, "tools", "score.py")], capture_output=True, text=True,
                           env=env)                                                          # the command-line default
        self.assertRegex(p.stdout.splitlines()[-1], r"^TOTAL set 5f7517a: documents [0-9]+/129 agree", p.stderr[-300:])

    def test_the_8ce7f42_set_unchanged(self):
        rows = score.score(which="8ce7f42")
        self.assertEqual((len(rows), sum(r["agree"] for r in rows)), (127, 127), v.nums(rows))

    def test_each_reading_alone(self):
        for opts, bad in (({}, []), (dict(wv.PROFILE_1_4_8), []), ({"criteria_noncharacters": "readable"}, []),
                          ({"criteria_noncharacters": "report"}, []),
                          ({"criteria_noncharacters": "unreadable"}, ["127", "128"]),        # Q36: outside 1.4.12
                          ({"criteria_limits": "readable"}, ["121", "122", "123", "124", "126"]),
                          ({"rp_point": "always"}, ["119", "120"])):
            self.assertEqual(v.nums(score.score(opts, which=SET)), bad, opts)

    def test_127_and_128(self):
        """Step 4 at 5f7517a: "a noncharacter in a member name or a string value does not make the file unreadable (127, 128)"."""
        files = score.vector_files(SET)
        for n, cp in ((127, "U+FFFE"), (128, "U+FDD0")):
            raw = v.read(files[n - 1])
            rep = wv.run_vector_bytes(raw)[0]                                             # the defaults: read, with the note
            self.assertEqual(outcome(rep), PROBLEMS_OF_01, n)
            self.assertNotIn("criteria_unreadable", rep["details"], n)
            self.assertEqual([x for x in rep["notes"] if x.startswith(NOTE)],
                             [x for x in rep["notes"] if x.startswith(NOTE + ": the criteria document holds the noncharacter " + cp)], n)
            self.assertEqual(sum(x.startswith(NOTE) for x in rep["notes"]), 1, n)
            for opts in ({"criteria_noncharacters": "readable"}, dict(wv.PROFILE_1_4_8)):  # the 0.11.0 reading: read, no note
                rep = wv.run_vector_bytes(raw, opts)[0]
                self.assertEqual(outcome(rep), PROBLEMS_OF_01, (n, opts))
                self.assertFalse(any(x.startswith(NOTE) for x in rep["notes"]), (n, opts))
            rep = wv.run_vector_bytes(raw, {"criteria_noncharacters": "unreadable"})[0]   # the other reading of Q36
            self.assertEqual((rep["problem_codes"], rep["criteria_hash"]), ([UNREADABLE], "match"), n)
            self.assertIn("noncharacter " + cp, rep["details"]["criteria_unreadable"], n)


class Step4Numbers(unittest.TestCase):
    """Step 4 at 5f7517a: "An integer is a number written without fraction or exponent, so `9007199254740992.0`,
    `9.007199254740992e15` and `1e16` are readable; a number overflows only when it rounds to an infinite double, so underflow
    (`1e-400`) and digits beyond what a double holds are readable." With the edges the same step names unreadable (122, 123)."""
    TABLE = (("9007199254740992.0", []), ("9.007199254740992e15", []), ("1e16", []), ("1e-400", []),
             ("3.141592653589793238462643383279", []), ("9007199254740991.000000000000000000001", []),
             ("9007199254740991", []),
             ("9007199254740992", [UNREADABLE]), ("-9007199254740992", [UNREADABLE]), ("1e400", [UNREADABLE]),
             ("-1e400", [UNREADABLE]), ("1.8e308", [UNREADABLE]))

    def test_the_sentence(self):
        for txt, want in self.TABLE:
            self.assertEqual(y.codes(y.extra(b'"x":' + txt.encode())), want, txt)

    def test_under_criteria_limits_readable(self):
        for txt, _want in self.TABLE:
            self.assertEqual(y.codes(y.extra(b'"x":' + txt.encode()), {"criteria_limits": "readable"}), [], txt)


if __name__ == "__main__":
    unittest.main()
