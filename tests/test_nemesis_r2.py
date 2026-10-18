"""NEMESIS round 2: kills for surviving mutants on the signature, certificate-time, TSA-name, key-collision and
key-decoding paths (each test was run against the mutant it targets and against b1d7e2b)."""
import copy
import hashlib
import os
import shutil
import tempfile
import unittest

import _paths  # noqa: F401
import build
import testpki as tp
import war_verify as wv

PKIX = dict(wv.DEFAULT_OPTIONS, tokens="pkix")


class TSA(unittest.TestCase):
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

    def status(self, raw):
        return wv.verify_tsa(wv.parse_tsr(raw, PKIX)["token"], wv.load_roots(self.capem))

    def test_unimplemented_signature_algorithm_is_invalid(self):
        raw = tp.signed_tsr(tp.tstinfo(self.dg, gen="20260601120000Z"), self.good, self.ca[1])
        ecdsa_sha256 = tp.oid("1.2.840.10045.4.3.2")
        i = raw.rfind(ecdsa_sha256)                         # the last one is SignerInfo.signatureAlgorithm
        self.assertGreater(i, 0)
        other = ecdsa_sha256[:-1] + bytes([0x7F])          # same length, an OID _verify_sig does not implement
        v = self.status(raw[:i] + other + raw[i + len(other):])
        self.assertEqual(v["status"], "invalid", v)
        self.assertTrue(any("not implemented" in r for r in v["reasons"]), v)
        self.assertEqual(self.status(raw)["status"], "valid")   # control: the untouched token is valid

    def test_certificate_validity_bounds_are_inclusive(self):
        # RFC 5280 4.1.2.5: the validity period is notBefore through notAfter, inclusive
        tsa = tp.make_tsa(self.ca, nb="20250101000000Z", na="20300101000000Z")
        for gen, want in (("20250101000000Z", "valid"), ("20300101000000Z", "valid"),
                          ("20241231235959Z", "invalid"), ("20300101000001Z", "invalid")):
            v = self.status(tp.signed_tsr(tp.tstinfo(self.dg, gen=gen), tsa, self.ca[1]))
            self.assertEqual(v["status"], want, (gen, v["reasons"]))

    def test_tsa_name_must_name_the_signer(self):
        other = tp._name("someone else").public_bytes()
        v = self.status(tp.signed_tsr(tp.tstinfo(self.dg, gen="20260601120000Z", tsa_name_der=other),
                                      self.good, self.ca[1]))
        self.assertEqual(v["status"], "invalid", v)
        same = self.good[1].subject.public_bytes()
        v = self.status(tp.signed_tsr(tp.tstinfo(self.dg, gen="20260601120000Z", tsa_name_der=same),
                                      self.good, self.ca[1]))
        self.assertEqual(v["status"], "valid", v)

    def test_empty_signerinfos_is_unsigned(self):
        raw = tp.unsigned_tsr(tp.tstinfo(self.dg), with_signerinfos=True)     # present but empty SET
        self.assertEqual(self.status(raw)["status"], "unsigned")


class Order(unittest.TestCase):
    def test_tie_with_ordering_true_same_tsa_is_not_before(self):
        name = tp._name("war-verify TEST TSA").public_bytes()
        inp = build.base()
        inp["receipt"]["receipt"]["criteria"]["committed_at"] = "2026-06-01T12:00:05Z"
        build.criteria_token(inp, gen="20260601120005Z", ordering=True, tsa_name_der=name)
        build.sign(inp)
        build.record_token(inp, gen="20260601120005Z", ordering=True, tsa_name_der=name)
        rep = wv.verify(copy.deepcopy(inp), dict(wv.DEFAULT_OPTIONS, accuracy="interval"))
        self.assertEqual(rep["criteria_committed_before_check"], "no")
        self.assertEqual(rep["details"]["ordering_provable_under_accuracy"], "no")
        self.assertIn("CRITERIA_COMMITTED_AFTER_CHECK", rep["problem_codes"])


class Keys(unittest.TestCase):
    def test_distinct_producer_key_in_key_file_is_not_a_collision(self):
        inp = build.base()
        inp["receipt"]["receipt"]["parties"]["producer"]["key_id"] = "omega-test-2"
        build.refresh(inp)
        rep = wv.verify(copy.deepcopy(inp))
        self.assertNotIn("KEY_COLLISION", rep["problem_codes"])
        self.assertNotIn("INDEPENDENCE_INCONSISTENT", rep["problem_codes"])
        # control: the same producer key id as the checker is a collision
        inp2 = build.base()
        inp2["receipt"]["receipt"]["parties"]["producer"]["key_id"] = "omega-test-1"
        build.refresh(inp2)
        self.assertIn("KEY_COLLISION", wv.verify(copy.deepcopy(inp2))["problem_codes"])

    def test_y_equal_p_encoding_is_not_decoded(self):
        # RFC 8032 5.1.3 step 1: y >= p fails decoding; y = p is the boundary
        self.assertIsInstance(wv.ed_decode(wv._P.to_bytes(32, "little")), str)
        self.assertNotIsInstance(wv.ed_decode((wv._P - 1).to_bytes(32, "little")), str)   # control: y = p - 1


if __name__ == "__main__":
    unittest.main()
