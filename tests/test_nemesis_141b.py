"""Profile 1.4.1 at d79a737 (2026-10-21T16:45:33Z): "a chain of CA issuers reaching a supplied anchor (matched by subject
name and public key, RFC 5280 6.1.1, not by certificate bytes)". This verifier walks from the signer with the supplied
anchors among the issuer candidates and stops at the first anchor: a cross-signed copy of the anchor inside the token
reaches it, and a certificate with the anchor's name but another key does not. Vectors 48 and 49 of d79a737 (EKU and
CA-flag rules), fetched by SHA-256 into fonti/upstream_d79a737/."""
import copy
import os
import unittest

import _paths  # noqa: F401
import test_nemesis_14 as n14
import testpki as tp
import war_verify as wv
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V48 = os.path.join(ROOT, "fonti/upstream_d79a737/vectors/48-tsa-signer-without-timestamping-eku-failed.json")
V49 = os.path.join(ROOT, "fonti/upstream_d79a737/vectors/49-tsa-issuer-not-a-ca-failed.json")


def same_name_cert(subject_cert, key_public, issuer):
    """A CA certificate with `subject_cert`'s subject name and `key_public`, issued and signed by `issuer`."""
    ikey, icert = issuer
    return (x509.CertificateBuilder().subject_name(subject_cert.subject).issuer_name(icert.subject)
            .public_key(key_public).serial_number(x509.random_serial_number())
            .not_valid_before(tp._dt("20200101000000Z")).not_valid_after(tp._dt("20400101000000Z"))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .sign(ikey, hashes.SHA256()))


class AnchorByNameAndKey(n14.Base):
    @classmethod
    def setUpClass(cls):
        n14.Base.setUpClass()
        cls.root_b = tp.make_ca("war-verify TEST root B (nemesis 141b)")
        # the anchor's name and key, cross-signed by root B (other bytes, other issuer)
        cls.cross = same_name_cert(cls.root[1], cls.root[0].public_key(), cls.root_b)
        # an impostor: the anchor's name, another key, self-signed
        ikey = ec.generate_private_key(ec.SECP256R1())
        cls.impostor = same_name_cert(cls.root[1], ikey.public_key(), (ikey, cls.root[1]))

    def rep(self, token, anchors, prec):
        return wv.verify(self.doc(token, anchors), {"tsa_precedence": prec})

    def test_cross_signed_copy_of_the_anchor_in_the_token_reaches_the_anchor(self):
        tok = tp.signed_tsr(self.tst(), self.tsa, self.cross)           # token carries the signer and the cross-signed copy
        for prec in n14.BOTH:
            self.assertEqual(self.criteria(tok, [self.R], prec), "verified", prec)                 # anchor: self-signed
            self.assertEqual(self.criteria(tok, [n14.b64(tp.der(self.root_b[1]))], prec), "verified", prec)  # anchor: B
            self.assertEqual(self.criteria(tok, [n14.b64(tp.der(self.other_root[1]))], prec), "untrusted", prec)

    def test_cross_signed_copy_as_the_anchor_reaches_the_self_signed_root_in_the_token(self):
        tok = tp.signed_tsr(self.tst(), self.tsa, self.root[1])
        for prec in n14.BOTH:
            self.assertEqual(self.criteria(tok, [n14.b64(tp.der(self.cross))], prec), "verified", prec)

    def test_the_anchors_name_with_another_key_is_not_the_anchor(self):
        tok = tp.signed_tsr(self.tst(), self.tsa, self.root[1])
        for prec in n14.BOTH:
            self.assertEqual(self.criteria(tok, [n14.b64(tp.der(self.impostor))], prec), "untrusted", prec)

    def test_other_outcome_members_unchanged(self):
        tok = tp.signed_tsr(self.tst(), self.tsa, self.cross)
        with_anchor = self.rep(tok, [self.R], "failed-first")
        without = self.rep(tok, None, "failed-first")
        for k in without:
            if k not in ("tsa_signature", "details", "notes"):
                self.assertEqual(with_anchor[k], without[k], k)


class VectorsD79a737(unittest.TestCase):
    def test_48_and_49_agree_and_read_failed(self):
        for path in (V48, V49):
            with open(path, "rb") as fh:
                d = wv.strict_json_loads(fh.read())
            rep, cmp_ = wv.run_vector(d)
            self.assertTrue(cmp_["agree"], (path, cmp_))
            self.assertEqual(rep["tsa_signature"], {"criteria": "failed"}, path)

    def test_48_without_the_eku_rule_and_49_without_the_ca_rule_stop_agreeing(self):
        # positive control: each vector pins one rule (its reason names it)
        for path, needle in ((V48, "EKU"), (V49, "is not a CA")):
            with open(path, "rb") as fh:
                rep, _ = wv.run_vector(wv.strict_json_loads(fh.read()))
            self.assertTrue(any(needle in r for r in rep["details"]["criteria_token_tsa_signature"]["reasons"]), (path, rep["details"]["criteria_token_tsa_signature"]["reasons"]))


if __name__ == "__main__":
    unittest.main()
