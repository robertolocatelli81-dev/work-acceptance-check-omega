"""The exit-0 guards (local_blocks), accepted_as_stated and token_authentication: expectations written from the
README rules ("Usage", "Switches"), not from a run of the verifier."""
import base64
import copy
import hashlib
import json
import os
import unittest

import _paths
import build
import war_verify as wv

LIVE = os.path.join(_paths.ROOT, "fonti", "issuer_274159c")
ROOTS = os.path.join(_paths.ROOT, "roots", "freetsa_cacert.pem")


def load(p):
    with open(p, "rb") as fh:
        return wv.strict_json_loads(fh.read())


def v01():
    return load(os.path.join(_paths.ROOT, "fonti/upstream_f7d8984/vectors/01-valid.json"))["inputs"]


def active_keys():
    kf = build.keyfile()
    for k in kf["keys"]:
        k["status"] = "active"
    return kf


class Blocks(unittest.TestCase):
    def test_vector01_blocks(self):
        rep = wv.verify(v01())
        self.assertTrue(rep["accepted_as_stated"])
        self.assertEqual(rep["local_blocks"], ["X_KEY_FROM_INPUT", "X_TEST_KEY", "X_TSA_NOT_VERIFIED"])
        self.assertTrue(rep["details"]["key_source"].startswith("inputs.keys"))
        self.assertEqual(rep["details"]["signer_key_status"], "test")
        for v in rep["details"]["token_authentication"].values():
            self.assertTrue(v.startswith("unauthenticated"))

    def test_live_record_clean_only_with_keys_and_pkix(self):
        doc = load(os.path.join(LIVE, "selftest-pass.json"))
        keys = load(os.path.join(LIVE, "checker-keys-live.json"))
        rep = wv.verify(doc["inputs"], {"tokens": "pkix", "tsa_roots": ROOTS}, keys)
        self.assertTrue(rep["accepted_as_stated"])
        self.assertEqual(rep["local_blocks"], [])
        self.assertEqual(rep["details"]["token_authentication"], {"criteria_token": "valid", "record_token": "valid"})
        self.assertTrue(rep["details"]["key_source"].startswith("--keys"))
        rep = wv.verify(doc["inputs"], None, keys)
        self.assertEqual(rep["local_blocks"], ["X_TSA_NOT_VERIFIED"])

    def test_pkix_roots_unreadable(self):
        doc = load(os.path.join(LIVE, "selftest-pass.json"))
        rep = wv.verify(doc["inputs"], {"tokens": "pkix", "tsa_roots": "/nonexistent"})
        self.assertTrue(rep["cannot_run"])
        self.assertIn("X_TSA_UNVERIFIED", rep["extension_codes"])
        self.assertNotIn("X_TSA_NOT_VERIFIED", rep["extension_codes"])
        self.assertFalse(rep["accepted_as_stated"])

    def test_no_token_used_no_tsa_block(self):
        i = build.base(token=False)
        i["criteria_tsr_base64"] = None
        rep = wv.verify(i, None, active_keys())
        self.assertEqual(rep["local_blocks"], [])
        self.assertEqual(rep["details"]["token_authentication"],
                         {"criteria_token": "not supplied", "record_token": "not supplied"})
        self.assertTrue(rep["accepted_as_stated"])

    def test_key_id_agreement(self):
        i = build.base(token=False)
        i["criteria_tsr_base64"] = None
        i["receipt"]["receipt"]["key_id"] = "omega-test-2"
        build.sign(i)
        old = dict(wv.PROFILE_1_2_1)                       # this verifier's 1.2.1 reading: a local block only
        rep = wv.verify(copy.deepcopy(i), old, active_keys())
        self.assertEqual(rep["local_blocks"], ["X_KEY_ID_SPLIT", "X_RECEIPT_KEY_ID_NOT_SIGNER"])
        self.assertTrue(rep["signature_valid"])
        rep = wv.verify(copy.deepcopy(i), dict(old, key_id_agreement="ignore"), active_keys())
        self.assertEqual(rep["local_blocks"], [])
        self.assertIn("X_KEY_ID_SPLIT", rep["extension_codes"])
        rep = wv.verify(copy.deepcopy(i), None, active_keys())    # 1.3: the signed receipt.key_id names the key
        self.assertIs(rep["signature_valid"], False)
        self.assertEqual(rep["problem_codes"], ["CHECKER_NOT_SIGNER", "SIGNATURE_INVALID"])
        self.assertIn("X_KEY_ID_SPLIT", rep["local_blocks"])

    def test_files(self):
        i = build.base(token=False)
        i["criteria_tsr_base64"] = None
        data = b"the delivered file"
        r = i["receipt"]["receipt"]
        r["files"]["remediated"]["sha256"] = hashlib.sha256(data).hexdigest()
        r["files"]["remediated"]["bytes"] = len(data) + 1
        build.sign(i)
        i["delivered_file_base64"] = base64.b64encode(data).decode()
        rep = wv.verify(copy.deepcopy(i), None, active_keys())
        self.assertEqual(rep["files"]["remediated"], "mismatch")
        self.assertEqual(rep["local_blocks"], ["X_REMEDIATED_FILE_BYTES_MISMATCH"])
        self.assertTrue(rep["accepted_as_stated"])                 # the profile has no code for step 3
        r["files"]["remediated"]["bytes"] = len(data)
        del r["files"]["original"]
        build.sign(i)
        i["original_file_base64"] = base64.b64encode(b"x").decode()
        rep = wv.verify(copy.deepcopy(i), None, active_keys())
        self.assertEqual(rep["files"], {"remediated": "match", "original": "not-in-record"})
        self.assertEqual(rep["local_blocks"], ["X_FILE_NOT_IN_RECORD"])

    def test_accepted_as_stated_conditions(self):
        rep = wv.verify(v01(), {"accuracy": "interval"})
        self.assertEqual(rep["problem_codes"], [])
        self.assertEqual(rep["criteria_committed_before_check"], "undetermined")
        self.assertFalse(rep["accepted_as_stated"])
        d6 = load(os.path.join(_paths.ROOT, "fonti/upstream_f7d8984/vectors/06-receipt-edited-after-signing.json"))
        rep = wv.verify(d6["inputs"])
        self.assertFalse(rep["accepted_as_stated"])
        self.assertFalse(rep["results_presented"])

    def test_metadata_compared_only(self):
        i = build.base()
        i["receipt"]["timestamp"]["digest_sha256"] = "ab" * 32
        rep = wv.verify(i)
        self.assertIn("X_TIMESTAMP_METADATA_DISAGREES", rep["extension_codes"])
        self.assertEqual(rep["receipt_timestamp"], "imprint_match")
        i = build.base()
        i["receipt"]["timestamp"]["gen_time"] = "20260601120006Z"
        self.assertIn("X_TIMESTAMP_METADATA_DISAGREES", wv.verify(i)["extension_codes"])

    def test_inputs_shape_and_options(self):
        with self.assertRaises(wv.Refusal):
            wv.verify([])
        i = v01()
        i["receipt"] = []
        with self.assertRaises(wv.Refusal):
            wv.verify(i)
        with self.assertRaises(ValueError):
            wv.verify(v01(), {"tokens": "bogus"})
        rep = wv.verify(v01())
        self.assertNotIn("tsa_roots", rep["options"])
        self.assertEqual(rep["options"]["key_id_agreement"], "signature-invalid")      # profile 1.3 default
        self.assertEqual(rep["options"]["key_rule"], "signer")

    def test_keys_override_note(self):
        rep = wv.verify(v01(), None, json.loads(json.dumps(v01()["keys"])))
        self.assertIn("inputs.keys not used: the key file was supplied with --keys", rep["notes"])
        self.assertNotIn("X_KEY_FROM_INPUT", rep["extension_codes"])


if __name__ == "__main__":
    unittest.main()
