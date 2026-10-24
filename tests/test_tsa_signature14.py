"""Profile 1.4 step 9 (`tsa_signature`), written from the README at maximusrufus/work-acceptance-record@eb0f30b:
"Without relying-party anchors it is `not_evaluated`, and an absent field reads the same. With anchors it is
`verified` (CMS signature, ESS signing-certificate binding, `id-kp-timeStamping`, validity at genTime, and a chain of
CA issuers reaching a supplied anchor; a root inside the token is not an anchor), `failed`, `untrusted`, `unsupported`
(e.g. RSASSA-PSS) or `no_signer`. It never changes any other outcome member."

The six upstream vectors (31-36) use live FreeTSA and DigiCert tokens. The cases here are the ones they do not reach,
built with the throw-away TEST TSA of tools/testpki.py on top of vector 31: RSASSA-PSS, RSA PKCS#1 v1.5, ECDSA P-256,
an intermediate CA, certificates outside their validity at genTime, a root carried in the token, a token without
SignerInfo, and tokens with two defects at once (the order between the values is not in the text: --tsa-precedence)."""
import base64
import copy
import glob
import json
import os
import subprocess
import sys
import unittest

import _paths
import testpki as tp
import war_verify as wv

UP = os.path.join(_paths.ROOT, "fonti", "upstream_eb0f30b", "vectors")
V31 = os.path.join(UP, "31-tsa-freetsa-verified.json")
GEN = "20261020153825Z"              # vector 31's criteria.committed_at, so no other member moves
OTHER = ("criteria_committed_before_check", "criteria_hash", "independence", "problem_codes", "receipt_timestamp",
         "signature_valid", "verdict_recomputed", "verdict_stated", "warning_codes")


def load(path):
    with open(path, "rb") as fh:
        return wv.strict_json_loads(fh.read())


def b64(b):
    return base64.b64encode(b).decode()


class Built(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v31 = load(V31)
        cls.digest = bytes.fromhex(cls.v31["inputs"]["receipt"]["receipt"]["criteria"]["sha256"])
        cls.root = tp.make_ca("war-verify TEST root 1.4")
        cls.other_root = tp.make_ca("war-verify TEST unrelated root")
        cls.inter = tp.make_intermediate(cls.root)
        cls.inter_expired = tp.make_intermediate(cls.root, cn="war-verify TEST expired intermediate",
                                                 na="20260101000000Z")
        cls.inter_not_ca = tp.make_intermediate(cls.root, cn="war-verify TEST non-CA intermediate", ca_flag=False)
        cls.tsa = tp.make_tsa(cls.root)
        cls.tsa_rsa = tp.make_tsa(cls.root, cn="war-verify TEST RSA TSA", key_type="rsa")
        cls.tsa_expired = tp.make_tsa(cls.root, cn="war-verify TEST expired TSA", na="20260101000000Z")
        cls.tsa_server = tp.make_tsa(cls.root, cn="war-verify TEST serverAuth TSA", eku=("server",))
        cls.tsa_under_inter = tp.make_tsa(cls.inter, cn="war-verify TEST TSA under intermediate")
        cls.tsa_under_expired = tp.make_tsa(cls.inter_expired, cn="war-verify TEST TSA under expired intermediate")
        cls.tsa_under_not_ca = tp.make_tsa(cls.inter_not_ca, cn="war-verify TEST TSA under non-CA")
        cls.tsa_p384 = tp.make_tsa(cls.root, cn="war-verify TEST P-384 TSA", key_type="ec-p384")
        cls.tsa_p521 = tp.make_tsa(cls.root, cn="war-verify TEST P-521 TSA", key_type="ec-p521")
        cls.tsa_ed25519 = tp.make_tsa(cls.root, cn="war-verify TEST Ed25519 TSA", key_type="ed25519")
        cls.root_expired = tp.make_ca("war-verify TEST root expired before genTime", na="20260101000000Z")
        cls.tsa_under_expired_root = tp.make_tsa(cls.root_expired, cn="war-verify TEST TSA under expired root")

    def tst(self):
        return tp.tstinfo(self.digest, gen=GEN)

    def cases(self):
        r, t = self.root[1], self.tst
        bad_md = b"\0" * 32
        return [  # name, token, anchors, failed-first, evaluability-first
            ("ECDSA P-256 under the anchor", tp.signed_tsr(t(), self.tsa, r), [r], "verified", "verified"),
            ("RSA PKCS#1 v1.5 SHA-256", tp.signed_tsr(t(), self.tsa_rsa, r, sig_alg="rsa-pkcs1-sha256"), [r],
             "verified", "verified"),
            ("RSASSA-PSS", tp.signed_tsr(t(), self.tsa_rsa, r, sig_alg="rsa-pss-sha256"), [r],
             "unsupported", "unsupported"),
            ("RSASSA-PSS and a wrong message-digest", tp.signed_tsr(t(), self.tsa_rsa, r, sig_alg="rsa-pss-sha256",
                                                                   md_override=bad_md), [r], "failed", "unsupported"),
            ("one signature bit", tp.signed_tsr(t(), self.tsa, r, flip_sig=True), [r], "failed", "failed"),
            ("message-digest of other bytes", tp.signed_tsr(t(), self.tsa, r, md_override=bad_md), [r],
             "failed", "failed"),
            ("no ESS attribute", tp.signed_tsr(t(), self.tsa, r, ess=None), [r], "failed", "failed"),
            ("ESS hash of another certificate", tp.signed_tsr(t(), self.tsa, r, ess_hash_override=b"\1" * 32), [r],
             "failed", "failed"),
            ("EKU serverAuth", tp.signed_tsr(t(), self.tsa_server, r), [r], "failed", "failed"),
            ("TSA certificate expired before genTime", tp.signed_tsr(t(), self.tsa_expired, r), [r],
             "failed", "failed"),
            ("chain through an intermediate", tp.signed_tsr(t(), self.tsa_under_inter, r,
                                                            certs=[self.inter[1], r]), [r], "verified", "verified"),
            # 1.4.1: "a chain that reaches the anchor but fails a check is `failed`" (vector 38)
            ("intermediate expired before genTime", tp.signed_tsr(t(), self.tsa_under_expired, r,
                                                                  certs=[self.inter_expired[1], r]), [r],
             "failed", "failed"),
            # 1.4.1 step 9 (bc5a138): "An issuer in the token that fails a check is `failed` whether or not the chain
            # reaches a supplied anchor" (vector 54); untrusted until 0.4.1
            ("intermediate expired, chain not reaching the anchor", tp.signed_tsr(
                t(), self.tsa_under_expired, r, certs=[self.inter_expired[1], r]), [self.other_root[1]],
             "failed", "failed"),
            # 1.4.1: "the signer and every issuer other than the anchor valid at genTime"
            ("anchor expired before genTime", tp.signed_tsr(t(), self.tsa_under_expired_root, self.root_expired[1]),
             [self.root_expired[1]], "verified", "verified"),
            ("signer certificate itself the anchor, expired", tp.signed_tsr(t(), self.tsa_expired, r),
             [self.tsa_expired[1]], "failed", "failed"),
            # 1.4.1: "RSA PKCS#1 v1.5 and ECDSA P-256/P-384 are required"; other curves `unsupported`
            ("ECDSA P-384", tp.signed_tsr(t(), self.tsa_p384, r), [r], "verified", "verified"),
            ("ECDSA P-521", tp.signed_tsr(t(), self.tsa_p521, r), [r], "unsupported", "unsupported"),
            ("ECDSA P-521 and a wrong message-digest", tp.signed_tsr(t(), self.tsa_p521, r, md_override=bad_md),
             [r], "failed", "unsupported"),
            ("Ed25519 TSA key", tp.signed_tsr(t(), self.tsa_ed25519, r, sig_alg="ed25519"), [r],
             "unsupported", "unsupported"),
            ("intermediate not in the token", tp.signed_tsr(t(), self.tsa_under_inter, r, certs=[r]), [r],
             "untrusted", "untrusted"),
            ("issuer without the CA flag", tp.signed_tsr(t(), self.tsa_under_not_ca, r,
                                                         certs=[self.inter_not_ca[1], r]), [r],
             "failed", "failed"),
            ("root carried in the token, another anchor", tp.signed_tsr(t(), self.tsa, r), [self.other_root[1]],
             "untrusted", "untrusted"),
            ("certReq=false shape (no certificates)", tp.signed_tsr(t(), self.tsa, r, include_certs=False), [r],
             "no_signer", "no_signer"),
            ("no certificates and a wrong message-digest", tp.signed_tsr(t(), self.tsa, r, include_certs=False,
                                                                         md_override=bad_md), [r],
             "failed", "no_signer"),
            ("no SignerInfo (the shape of vectors 01-30)", tp.unsigned_tsr(t()), [r], "no_signer", "no_signer"),
        ]

    def doc(self, token, anchors):
        d = copy.deepcopy(self.v31)
        d["inputs"]["criteria_tsr_base64"] = b64(token)
        if anchors is None:
            del d["inputs"]["tsa_roots_base64"]
        else:
            d["inputs"]["tsa_roots_base64"] = [b64(tp.der(c)) for c in anchors]
        return d

    def test_values_and_no_other_member_moves(self):
        base = wv.verify(self.v31["inputs"])
        n = 0
        for name, token, anchors, ff, ef in self.cases():
            for prec, want in (("failed-first", ff), ("evaluability-first", ef)):
                rep = wv.verify(self.doc(token, anchors)["inputs"], {"tsa_precedence": prec})
                self.assertEqual(rep["tsa_signature"]["criteria"], want, (name, prec, rep["details"]))
                # the record token is FreeTSA's, and FreeTSA's root is not among these anchors
                self.assertEqual(rep["tsa_signature"]["receipt"], "untrusted", name)
                no_anchor = wv.verify(self.doc(token, None)["inputs"])
                self.assertEqual(no_anchor["tsa_signature"], {"criteria": "not_evaluated",
                                                              "receipt": "not_evaluated"}, name)
                for k in OTHER:
                    self.assertEqual(rep[k], no_anchor[k], (name, prec, k))
                    self.assertEqual(rep[k], base[k], (name, prec, k))
                n += 1
        self.assertEqual(n, 2 * len(self.cases()))

    def test_empty_anchor_list_reads_as_no_anchors(self):
        d = self.doc(tp.signed_tsr(self.tst(), self.tsa, self.root[1]), [])
        rep = wv.verify(d["inputs"])
        self.assertEqual(rep["tsa_signature"], {"criteria": "not_evaluated", "receipt": "not_evaluated"})
        self.assertTrue(any("tsa_roots_base64 is empty" in n for n in rep["notes"]))

    def test_cli_roots_replace_the_vector_anchors(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "r.pem")
            with open(p, "wb") as fh:
                fh.write(tp.pem(self.other_root[1]))
            rep = wv.verify(self.v31["inputs"], {"tsa_roots": p})
        self.assertEqual(rep["tsa_signature"], {"criteria": "untrusted", "receipt": "untrusted"})
        self.assertTrue(any("not used: anchors were supplied with --tsa-roots" in n for n in rep["notes"]))


class Grammar(unittest.TestCase):
    def setUp(self):
        self.v31 = load(V31)

    def refused(self, value):
        d = copy.deepcopy(self.v31)
        d["inputs"]["tsa_roots_base64"] = value
        rep, _ = wv.run_vector(d)
        return rep.get("refused") is True

    def test_anchor_list_is_closed(self):
        for v in ("MIIB", {"a": 1}, 7, None, [7], [None], ["@@@@"], ["QUJD"], [b64(b"\x30\x03\x02\x01\x01")]):
            self.assertTrue(self.refused(v), v)
        self.assertFalse(self.refused(self.v31["inputs"]["tsa_roots_base64"]))
        self.assertFalse(self.refused([]))


class Corrupted(unittest.TestCase):
    def test_every_other_value_of_31_to_36_is_caught(self):
        n = 0
        for f in sorted(glob.glob(os.path.join(UP, "3[1-6]-*.json"))):
            d = load(f)
            rep, _ = wv.run_vector(d)
            for k, v in d["expected"]["tsa_signature"].items():
                for alt in wv.TSA_VALUES:
                    if alt != v:
                        e = dict(d["expected"], tsa_signature=dict(d["expected"]["tsa_signature"], **{k: alt}))
                        self.assertFalse(wv.compare(rep, e)["agree"], (f, k, alt))
                        n += 1
        self.assertEqual(n, 55)


class Compare(unittest.TestCase):
    def test_absent_reads_as_not_evaluated_key_by_key(self):
        c = lambda ours, theirs: wv.compare(ours, {"tsa_signature": theirs})["agree"]  # noqa: E731
        self.assertTrue(c({}, {"criteria": "not_evaluated", "receipt": "not_evaluated"}))
        self.assertTrue(c({"tsa_signature": {"criteria": "not_evaluated"}}, {"criteria": "not_evaluated"}))
        self.assertTrue(c({"tsa_signature": {"criteria": "verified", "receipt": "not_evaluated"}},
                          {"criteria": "verified"}))
        self.assertFalse(c({}, {"criteria": "verified"}))
        self.assertFalse(c({"tsa_signature": {"criteria": "verified", "receipt": "verified"}},
                           {"criteria": "verified"}))
        self.assertFalse(c({"tsa_signature": {"criteria": "failed"}}, {"criteria": "verified"}))
        self.assertFalse(c({"tsa_signature": {"criteria": "verified"}}, {"criteria": "verified", "record": "x"}))
        self.assertFalse(c({"tsa_signature": {"criteria": "bogus"}}, {"criteria": "bogus"}))
        self.assertFalse(c({"refused": True}, {"criteria": "not_evaluated"}))


class Upstream(unittest.TestCase):
    def test_all_36_agree_under_both_precedences(self):
        files = sorted(glob.glob(os.path.join(UP, "*.json")))
        self.assertEqual(len(files), 36)
        for prec in ("failed-first", "evaluability-first"):
            for f in files:
                with open(f, "rb") as fh:
                    rep, cmp_ = wv.run_vector_bytes(fh.read(), {"tsa_precedence": prec})
                self.assertTrue(cmp_["agree"], (prec, os.path.basename(f), cmp_))

    def test_cli_exit_codes(self):
        for f, rc in ((V31, 0), (os.path.join(UP, "33-tsa-unrelated-root-untrusted.json"), 0)):
            p = subprocess.run([sys.executable, "-B", os.path.join(_paths.ROOT, "war_verify.py"), "--vector", f],
                               capture_output=True, env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
            self.assertEqual(p.returncode, rc, p.stderr)
            self.assertIn("tsa_signature", json.loads(p.stdout)["report"])

    def run_pre(self, pre):
        wvp = os.path.join(_paths.ROOT, "war_verify.py")
        code = pre + "; import runpy, sys; sys.argv = %r; runpy.run_path(%r, run_name='__main__')" % (
            [wvp, "--vector", V31], wvp)
        p = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True,
                           env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
        return p.returncode, json.loads(p.stdout)["report"]

    def test_cryptography_without_the_chain_api_is_exit_74_not_untrusted(self):
        # cryptography < 40 has no Certificate.verify_directly_issued_by; measured with 39.0.2 before the guard:
        # 31, 32 and 34 read untrusted and the bench gave 34/37. Simulated here by hiding the class's method.
        rc, rep = self.run_pre("import cryptography.x509 as x; x.Certificate = type('C', (), {})")
        self.assertEqual(rc, 74)
        self.assertEqual(rep["tsa_signature"], {"criteria": "not_evaluated", "receipt": "not_evaluated"})
        self.assertTrue(any("verify_directly_issued_by" in c for c in rep["cannot_run"]))

    def test_without_cryptography_anchors_are_not_evaluated(self):
        rc, rep = self.run_pre("import sys; sys.modules['cryptography'] = None")
        self.assertEqual(rc, 74)
        self.assertEqual(rep["tsa_signature"], {"criteria": "not_evaluated", "receipt": "not_evaluated"})


if __name__ == "__main__":
    unittest.main()
