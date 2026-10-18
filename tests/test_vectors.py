"""Score on the published vector sets + the live record, with the bench's positive controls.
Profile 1.3 (42b4ed0, 27 vectors) is the default; the 1.2.1 round (26 documents) is kept under --profile 1.2.1."""
import copy
import glob
import json
import os
import unittest

import _paths  # noqa: F401
import score
import war_verify as wv

V20 = "fonti/upstream_42b4ed0/vectors/20-producer-undeclared.json"


def short(rows):
    return [r["file"].split("/")[-1][:2] for r in rows if not r["agree"]]


class Vectors13(unittest.TestCase):
    def test_defaults_28_of_28(self):
        rows = score.score()
        self.assertEqual(len(rows), 28)              # 27 vectors of 42b4ed0 + live record
        self.assertEqual(short(rows), [])
        self.assertEqual(sum(r["fields"] for r in rows), 245)

    def test_each_1_2_1_reading_breaks_exactly_its_vectors(self):
        for opt, bad in ((("reference_time", "covering-token"), ["22"]), (("key_rule", "refuse"), ["26", "27"]),
                         (("independence_rule", "stated-independent"), ["20"])):
            self.assertEqual(short(score.score(dict([opt]))), bad, opt)
        self.assertEqual(short(score.score(dict(wv.PROFILE_1_2_1))), ["20", "22", "26", "27"])

    def test_vector_20_contributor_expectation_reported(self):
        row = [r for r in score.score() if r["file"] == V20][0]
        self.assertTrue(row["agree"])
        self.assertFalse(row["contributor_expectation"]["agree"])
        alt = [r for r in score.score({"independence_rule": "stated-independent"}) if r["file"] == V20][0]
        self.assertFalse(alt["agree"])
        self.assertTrue(alt["contributor_expectation"]["agree"])

    def test_positive_control_accept_always_bench_fails(self):
        def always(doc):
            rep = {"signature_valid": True, "criteria_hash": "match", "independence": "independent",
                   "problem_codes": [], "warning_codes": [], "receipt_timestamp": "none",
                   "verdict_recomputed": "pass", "verdict_stated": "pass", "criteria_committed_before_check": "yes"}
            return rep, wv.compare(rep, doc["expected"])
        self.assertEqual(sum(r["agree"] for r in score.score(verify_fn=always)), 0)

    def test_positive_control_corrupted_expectation_is_caught(self):
        def corrupt(doc):
            d = copy.deepcopy(doc)
            d["expected"]["problem_codes"] = list(d["expected"].get("problem_codes", [])) + ["KEY_COLLISION"]
            return wv.run_vector(d)
        self.assertEqual(sum(r["agree"] for r in score.score(verify_fn=corrupt)), 0)

    def test_code_lists_compared_as_sets(self):
        c = wv.compare({"problem_codes": ["B", "A"]}, {"problem_codes": ["A", "B"]})
        self.assertTrue(c["agree"])
        self.assertFalse(wv.compare({"problem_codes": ["A"]}, {"problem_codes": ["A", "B"]})["agree"])
        self.assertFalse(wv.compare({"signature_valid": 1}, {"signature_valid": True})["agree"])


class Vectors121(unittest.TestCase):
    def test_profile_1_2_1_on_the_1_2_1_round_unchanged(self):     # = war_verify 0.1.0: 25/26, only 22
        rows = score.score(dict(wv.PROFILE_1_2_1), which="1.2.1")
        self.assertEqual(len(rows), 26)
        self.assertEqual([r["file"].split("/")[-1] for r in rows if not r["agree"]],
                         ["22-matching-record-token-later-than-issued.json"])
        self.assertEqual(sum(r["fields_agree"] for r in rows), 225)

    def test_1_3_defaults_on_the_1_2_1_round(self):     # superseded expectations: old 12 (12b replaces it), old 20
        self.assertEqual(short(score.score(which="1.2.1")), ["12", "20"])


class OwnVectors(unittest.TestCase):
    def test_own_vectors_both_profiles(self):
        files = sorted(glob.glob(os.path.join(_paths.ROOT, "vectors", "*.json")))
        self.assertEqual(len(files), 52)
        changed = 0
        for f in files:
            raw = open(f, "rb").read()
            rep, c = wv.run_vector_bytes(raw)
            self.assertTrue(c["agree"], f)
            doc = json.loads(raw.decode("utf-8", "surrogatepass"))
            old = doc.get("expected_1_2_1", doc["expected"])
            changed += "expected_1_2_1" in doc
            r2, _ = wv.run_vector_bytes(raw, dict(wv.PROFILE_1_2_1))
            self.assertTrue(wv.compare(r2, old)["agree"], f)
            if "expected_1_2_1" in doc:                     # positive control: the two readings really differ
                self.assertFalse(wv.compare(rep, old)["agree"], f)
                self.assertFalse(wv.compare(r2, doc["expected"])["agree"], f)
        self.assertEqual(changed, 14)


if __name__ == "__main__":
    unittest.main()
