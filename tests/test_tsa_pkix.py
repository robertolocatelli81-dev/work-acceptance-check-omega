"""--tokens pkix: the live FreeTSA tokens against the fetched root, a throw-away TEST TSA for every negative case,
and a differential against `openssl ts -verify` where openssl is installed."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import _paths
import testpki as tp
import war_verify as wv

ROOTS = os.path.join(_paths.ROOT, "roots", "freetsa_cacert.pem")
SELFTEST = os.path.join(_paths.ROOT, "fonti", "issuer_274159c", "selftest-pass.json")
PKIX = dict(wv.DEFAULT_OPTIONS, tokens="pkix")


def doc():
    with open(SELFTEST, "rb") as fh:
        return wv.strict_json_loads(fh.read())


class Live(unittest.TestCase):
    def test_live_tokens_valid_against_fetched_root(self):
        rep, cmp_ = wv.run_vector(doc(), {"tokens": "pkix", "tsa_roots": ROOTS})
        self.assertTrue(cmp_["agree"])
        for k in ("criteria_token_tsa", "record_token_tsa"):
            self.assertEqual(rep["details"][k]["status"], "valid", rep["details"][k])
            self.assertEqual(rep["details"][k]["ess"], "ESSCertID")
        self.assertEqual(rep["details"]["ordering_provable_under_accuracy"], "yes")

    def test_live_tokens_invalid_against_another_root(self):
        ca = tp.make_ca("unrelated root")
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "r.pem")
            with open(p, "wb") as fh:
                fh.write(tp.pem(ca[1]))
            rep, cmp_ = wv.run_vector(doc(), {"tokens": "pkix", "tsa_roots": p})
            self.assertEqual(rep["details"]["criteria_token_tsa"]["status"], "invalid")
            self.assertIn("CRITERIA_COMMITMENT_UNVERIFIED", rep["warning_codes"])
            self.assertFalse(cmp_["agree"])
        finally:
            shutil.rmtree(d)

    def test_live_token_one_flipped_byte(self):
        dd = doc()
        raw = bytearray(base64.b64decode(dd["inputs"]["criteria_tsr_base64"]))
        raw[-5] ^= 1                                           # inside the signature value
        tok = wv.parse_tsr(bytes(raw), PKIX)["token"]
        self.assertEqual(wv.verify_tsa(tok, wv.load_roots(ROOTS))["status"], "invalid")

    def test_vector_tokens_are_refused_in_pkix(self):
        with open(os.path.join(_paths.ROOT, "fonti/upstream_f7d8984/vectors/01-valid.json"), "rb") as fh:
            d = wv.strict_json_loads(fh.read())
        rep, _ = wv.run_vector(d, {"tokens": "pkix", "tsa_roots": ROOTS})
        self.assertTrue(rep.get("refused"))

    def test_missing_roots_is_cannot_run(self):
        with self.assertRaises(wv.CannotRun):
            wv.load_roots("/nonexistent/roots")


class TestTSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        cls.ca = tp.make_ca()
        cls.good = tp.make_tsa(cls.ca)
        cls.capem = os.path.join(cls.dir, "ca.pem")
        with open(cls.capem, "wb") as fh:
            fh.write(tp.pem(cls.ca[1]))
        cls.dg = hashlib.sha256(b"x").digest()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def tst(self, gen="20260601120000Z"):
        return tp.tstinfo(self.dg, gen=gen)

    def ours(self, raw):
        return wv.verify_tsa(wv.parse_tsr(raw, PKIX)["token"], wv.load_roots(self.capem))

    def openssl(self, raw):
        if not shutil.which("openssl"):
            return None
        p = os.path.join(self.dir, "t.tsr")
        with open(p, "wb") as fh:
            fh.write(raw)
        r = subprocess.run(["openssl", "ts", "-verify", "-digest", self.dg.hex(), "-in", p, "-CAfile", self.capem],
                           capture_output=True)
        return r.returncode == 0

    def cases(self):
        ca, good, tst = self.ca, self.good, self.tst
        return [  # name, raw, ours valid?, openssl valid? (None = not compared)
            ("good v2", tp.signed_tsr(tst(), good, ca[1]), True, True),
            ("good v1", tp.signed_tsr(tst(), good, ca[1], ess="v1"), True, True),
            ("flipped signature", tp.signed_tsr(tst(), good, ca[1], flip_sig=True), False, False),
            ("message-digest wrong", tp.signed_tsr(tst(), good, ca[1], md_override=b"\0" * 32), False, False),
            ("no ESS attribute", tp.signed_tsr(tst(), good, ca[1], ess=None), False, False),
            ("ESS hash of another cert", tp.signed_tsr(tst(), good, ca[1], ess_hash_override=b"\1" * 32), False, False),
            ("two SignerInfos", tp.signed_tsr(tst(), good, ca[1], extra_signer=True), False, False),
            ("EKU not critical", tp.signed_tsr(tst(), tp.make_tsa(ca, eku_critical=False), ca[1]), False, False),
            ("EKU serverAuth", tp.signed_tsr(tst(), tp.make_tsa(ca, eku=("server",)), ca[1]), False, False),
            ("EKU timeStamping + codeSigning", tp.signed_tsr(tst(), tp.make_tsa(ca, eku=("ts", "code")), ca[1]), False, False),
            ("no EKU", tp.signed_tsr(tst(), tp.make_tsa(ca, eku=()), ca[1]), False, False),
            ("signed by another key", tp.signed_tsr(tst(), good, ca[1], sign_key=tp.make_tsa(ca)[0]), False, False),
            # the differential: openssl ts -verify checks the certificate at the current time, not at genTime,
            # and does not compare the content-type attribute with eContentType
            ("TSA cert expired at genTime", tp.signed_tsr(tst("20410101000000Z"), tp.make_tsa(ca, na="20400101000000Z"), ca[1]), False, True),
            ("TSA cert not yet valid at genTime", tp.signed_tsr(tst("20190101000000Z"), good, ca[1]), False, True),
            ("content-type attribute id-data", tp.signed_tsr(tst(), good, ca[1], content_type_oid="1.2.840.113549.1.7.1"), False, True),
        ]

    def test_cases_and_openssl_differential(self):
        for name, raw, want, want_ossl in self.cases():
            v = self.ours(raw)
            self.assertEqual(v["status"] == "valid", want, (name, v["reasons"]))
            o = self.openssl(raw)
            if o is not None:
                self.assertEqual(o, want_ossl, name)


if __name__ == "__main__":
    unittest.main()
