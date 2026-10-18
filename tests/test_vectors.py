"""Score on the 23 vectors + the live record, with the bench's positive controls."""
import copy
import unittest

import _paths  # noqa: F401
import score
import war_verify as wv


class Vectors(unittest.TestCase):
    def test_defaults_25_of_26_only_vector_22_differs(self):
        rows = score.score()
        self.assertEqual(len(rows), 26)          # 23 + 12b + 22-sha1 (Tetsurohhori 8ff69f4) + live record
        bad = [r["file"] for r in rows if not r["agree"]]
        self.assertEqual(bad, ["fonti/babyblueviper1_431525f/22-matching-record-token-later-than-issued.json"])
        self.assertEqual(sorted(d["field"] for d in [r for r in rows if not r["agree"]][0]["disagreements"]),
                         ["criteria_committed_before_check", "problem_codes"])

    def test_reference_time_earlier_reading_26_of_26(self):
        self.assertTrue(all(r["agree"] for r in score.score({"reference_time": "earlier"})))

    def test_key_id_from_receipt_reading_breaks_vector_12(self):
        bad = [r["file"].split("/")[-1][:2] for r in score.score({"key_id_source": "receipt"}) if not r["agree"]]
        self.assertEqual(bad, ["12", "22"])

    def test_positive_control_accept_always_bench_fails(self):
        def always(doc):
            rep = {"signature_valid": True, "criteria_hash": "match", "independence": "independent",
                   "problem_codes": [], "warning_codes": [], "receipt_timestamp": "none",
                   "verdict_recomputed": "pass", "verdict_stated": "pass", "criteria_committed_before_check": "yes"}
            return rep, wv.compare(rep, doc["expected"])
        self.assertEqual(sum(r["agree"] for r in score.score(verify_fn=always)), 0)

    def test_12b_agrees_under_both_key_id_readings(self):
        for o in (None, {"key_id_source": "receipt"}):
            rows = {r["file"].split("/")[-1][:3]: r["agree"] for r in score.score(o)}
            self.assertTrue(rows["12b"], o)

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


if __name__ == "__main__":
    unittest.main()
