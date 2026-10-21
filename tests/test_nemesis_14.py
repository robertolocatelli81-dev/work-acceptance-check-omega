"""NEMESIS review of 0.3.0 (profile 1.4 step 9): inputs that raised an uncaught exception once anchors were supplied,
and the survivors of a mutation run on the changed lines that tools/mutate14.py did not reach. Each test names the
sentence of the README it pins. Built with the throw-away TEST TSA of tools/testpki.py on top of vector 31."""
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

import _paths
import testpki as tp
import war_verify as wv
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

UP = os.path.join(_paths.ROOT, "fonti", "upstream_eb0f30b", "vectors")
V31 = os.path.join(UP, "31-tsa-freetsa-verified.json")
V16 = os.path.join(UP, "16-no-criteria-token.json")
GEN = "20261020153825Z"
OID_SHA256 = tp.oid("2.16.840.1.101.3.4.2.1")
OID_SHA3_256 = tp.oid("2.16.840.1.101.3.4.2.8")
BOTH = ("failed-first", "evaluability-first")


def load(path):
    with open(path, "rb") as fh:
        return wv.strict_json_loads(fh.read())


def b64(b):
    return base64.b64encode(b).decode()


def resign(ca_key, cert, rewrite_exts):
    """Re-encode `cert` with its extension list rewritten by `rewrite_exts(list_of_der)` and re-sign it (ECDSA)."""
    parts = wv.der_parse_one(tp.der(cert), "cert").kids()[0].kids()
    items = rewrite_exts([e.raw for e in parts[-1].kids()[0].kids()])
    tbs = tp.seq(*([p.raw for p in parts[:-1]] + [tp.tlv(0xA3, tp.seq(*items))]))
    sig = ca_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    return tp.seq(tbs, tp.seq(tp.oid("1.2.840.10045.4.3.2")), tp.tlv(0x03, b"\0" + sig))


def issuer_cert(root, cn, key_usage=None, basic_constraints=True):
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(tp._name(cn)).issuer_name(root[1].subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(tp._dt("20200101000000Z"))
         .not_valid_after(tp._dt("20400101000000Z")))
    if basic_constraints:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if key_usage is not None:
        b = b.add_extension(key_usage, critical=True)
    return key, b.sign(root[0], hashes.SHA256())


def token_with_attrs(tst_der, tsa, ca_cert, attrs):
    """A signed token (ECDSA P-256) with the given signed attributes, in the shape of testpki.signed_tsr."""
    key, cert = tsa
    sattrs = tp.set_of(*attrs)
    sig = key.sign(sattrs, ec.ECDSA(hashes.SHA256()))
    sid = tp.seq(cert.issuer.public_bytes(), tp.integer(cert.serial_number))
    si = tp.seq(tp.integer(1), sid, tp.alg(tp.SHA["sha256"]), b"\xa0" + sattrs[1:],
                tp.seq(tp.oid("1.2.840.10045.4.3.2")), tp.octets(sig))
    eci = tp.seq(tp.oid("1.2.840.113549.1.9.16.1.4"), tp.explicit(0, tp.octets(tst_der)))
    cd = tp.der(cert)
    body = (tp.integer(3) + tp.set_of(tp.alg(tp.SHA["sha256"])) + eci
            + tp.tlv(0xA0, b"".join(sorted([cd, tp.der(ca_cert)], key=lambda e: e.ljust(4096, b"\x00"))))
            + tp.set_of(si))
    return tp.seq(tp.seq(tp.integer(0)), tp.seq(tp.oid("1.2.840.113549.1.7.2"), tp.explicit(0, tp.tlv(0x30, body))))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v31 = load(V31)
        cls.digest = bytes.fromhex(cls.v31["inputs"]["receipt"]["receipt"]["criteria"]["sha256"])
        cls.root = tp.make_ca("war-verify TEST root (nemesis 14)")
        cls.other_root = tp.make_ca("war-verify TEST other root (nemesis 14)")
        cls.tsa = tp.make_tsa(cls.root)
        cls.R = b64(tp.der(cls.root[1]))

    def tst(self, **kw):
        return tp.tstinfo(self.digest, gen=GEN, **kw)

    def doc(self, token, anchors):
        d = copy.deepcopy(self.v31["inputs"])
        d["criteria_tsr_base64"] = b64(token)
        if anchors is None:
            d.pop("tsa_roots_base64", None)
        else:
            d["tsa_roots_base64"] = anchors
        return d

    def criteria(self, token, anchors, prec="failed-first"):
        return wv.verify(self.doc(token, anchors), {"tsa_precedence": prec})["tsa_signature"]["criteria"]


class NoUncaughtException(Base):
    """Every malformed token or anchor is a value or a refusal, never a traceback (closed by construction)."""

    def test_tstinfo_tsa_with_an_empty_directoryName_is_failed(self):
        for prec in BOTH:
            self.assertEqual(self.criteria(tp.signed_tsr(self.tst(tsa_name_der=b""), self.tsa, self.root[1]),
                                           [self.R], prec), "failed")

    def dup_last_extension(self, ca_key, cert):
        return resign(ca_key, cert, lambda items: items + [items[-1]])

    def garbage_eku(self, ca_key, cert):
        def rw(items):
            out = []
            for raw in items:
                k = wv.der_parse_one(raw, "ext").kids()
                if wv.der_oid(k[0], "extnID") == "2.5.29.37":
                    raw = tp.seq(k[0].raw, tp.boolean(True), tp.octets(b"\xff\xff\xff"))
                out.append(raw)
            return out
        return resign(ca_key, cert, rw)

    def test_signer_certificate_with_duplicate_or_unparsable_extension_is_failed(self):
        for name, der in (("duplicate", self.dup_last_extension(self.root[0], self.tsa[1])),
                          ("garbage EKU", self.garbage_eku(self.root[0], self.tsa[1]))):
            bad = (self.tsa[0], x509.load_der_x509_certificate(der))
            tok = tp.signed_tsr(self.tst(), bad, self.root[1])
            # failed-first: the certificate is not usable (failed); evaluability-first: no usable signer certificate
            self.assertEqual(self.criteria(tok, [self.R], "failed-first"), "failed", name)
            self.assertEqual(self.criteria(tok, [self.R], "evaluability-first"), "no_signer", name)

    def test_anchor_with_duplicate_extension_is_refused_in_inputs_and_skipped_on_the_cli(self):
        der = self.dup_last_extension(self.root[0], self.root[1])
        d = copy.deepcopy(self.v31)
        d["inputs"]["criteria_tsr_base64"] = b64(tp.signed_tsr(self.tst(), self.tsa, self.root[1], certs=[]))
        d["inputs"]["tsa_roots_base64"] = [b64(der)]
        rep, _ = wv.run_vector(d)
        self.assertTrue(rep.get("refused"), rep)
        self.assertIn("tsa_roots_base64[0]", rep["reason_detail"] if rep.get("reason_detail") else rep["reason"])
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "r.der")
            with open(p, "wb") as fh:
                fh.write(der)
            with self.assertRaises(wv.CannotRun):
                wv.load_roots(p)

    def test_signer_with_an_unknown_key_algorithm_is_unsupported(self):
        # the SubjectPublicKeyInfo algorithm OID is rewritten to one no engine knows: a value, never a traceback
        # (0.4.0 as first written raised UnsupportedAlgorithm / ValueError here)
        der = tp.der(self.tsa[1])
        ecoid = bytes.fromhex("06072a8648ce3d0201")                     # id-ecPublicKey
        self.assertEqual(der.count(ecoid), 1)
        bogus = x509.load_der_x509_certificate(der.replace(ecoid, bytes.fromhex("06072a8648ce3d0209")))
        tok = tp.signed_tsr(self.tst(), (self.tsa[0], bogus), self.root[1])
        for prec in BOTH:
            rep = wv.verify(self.doc(tok, [self.R]), {"tsa_precedence": prec})
            self.assertEqual(rep["tsa_signature"]["criteria"], "unsupported", prec)
            self.assertTrue(any("key algorithm 1.2.840.10045.2.9" in r
                                for r in rep["details"]["criteria_token_tsa_signature"]["reasons"]), prec)

    def test_signer_key_that_does_not_parse_is_failed(self):
        # a listed algorithm (id-ecPublicKey) whose subjectPublicKey is not a point the engine can load
        der = tp.der(self.tsa[1])
        head = bytes.fromhex("03420004")                                 # BIT STRING, 65 bytes, uncompressed point
        self.assertEqual(der.count(head), 1)
        bogus = x509.load_der_x509_certificate(der.replace(head, bytes.fromhex("03420009")))
        tok = tp.signed_tsr(self.tst(), (self.tsa[0], bogus), self.root[1])
        self.assertEqual(self.criteria(tok, [self.R], "failed-first"), "failed")
        self.assertIn(self.criteria(tok, [self.R], "evaluability-first"), ("failed", "no_signer"))

    def test_vector_anchors_keep_their_grammar_when_replaced_by_cli_roots(self):
        d = copy.deepcopy(self.v31["inputs"])
        d["tsa_roots_base64"] = 42
        with self.assertRaises(wv.Refusal):
            wv.verify(d, {"tsa_roots": os.path.join(_paths.ROOT, "roots")})


class ValueClasses(Base):
    """README "How the values are assigned": one case per class boundary that mutate14.py did not reach."""

    def test_failed_wins_over_untrusted_under_both_precedences(self):
        # EKU serverAuth (failed) and no path to the only anchor (untrusted) in the same token
        tok = tp.signed_tsr(self.tst(), tp.make_tsa(self.root, cn="serverAuth", eku=("server",)), self.root[1])
        for prec in BOTH:
            self.assertEqual(self.criteria(tok, [b64(tp.der(self.other_root[1]))], prec), "failed", prec)

    def test_two_signerinfos_content_type_tsa_name_eku_critical_ess_serial_are_failed(self):
        cases = [
            ("two SignerInfos", tp.signed_tsr(self.tst(), self.tsa, self.root[1], extra_signer=True)),
            ("content-type other OID", tp.signed_tsr(self.tst(), self.tsa, self.root[1],
                                                     content_type_oid="1.2.840.113549.1.7.1")),
            ("TSTInfo.tsa names another subject", tp.signed_tsr(self.tst(tsa_name_der=self.root[1].subject.public_bytes()),
                                                                self.tsa, self.root[1])),
            ("EKU not critical", tp.signed_tsr(self.tst(), tp.make_tsa(self.root, eku_critical=False), self.root[1])),
        ]
        md = hashlib.sha256(self.tst()).digest()
        cd = tp.der(self.tsa[1])
        issuer_serial = tp.seq(tp.seq(tp.tlv(0xA4, self.tsa[1].issuer.public_bytes())),
                               tp.integer(self.tsa[1].serial_number + 1))
        ess = tp.seq(tp.oid("1.2.840.113549.1.9.16.2.47"),
                     tp.set_of(tp.seq(tp.seq(tp.seq(tp.octets(hashlib.sha256(cd).digest()), issuer_serial)))))
        attrs = [tp.seq(tp.oid("1.2.840.113549.1.9.3"), tp.set_of(tp.oid("1.2.840.113549.1.9.16.1.4"))),
                 tp.seq(tp.oid("1.2.840.113549.1.9.4"), tp.set_of(tp.octets(md))), ess]
        cases.append(("ESS issuerSerial with another serial", token_with_attrs(self.tst(), self.tsa, self.root[1], attrs)))
        for name, tok in cases:
            for prec in BOTH:
                self.assertEqual(self.criteria(tok, [self.R], prec), "failed", (name, prec))

    def test_signerinfo_digest_algorithm_sha3_is_unsupported(self):
        tok = tp.signed_tsr(self.tst(), self.tsa, self.root[1])
        i = tok.rfind(OID_SHA256)                       # the last occurrence is SignerInfo.digestAlgorithm
        tok = tok[:i] + OID_SHA3_256 + tok[i + len(OID_SHA256):]
        for prec in BOTH:
            self.assertEqual(self.criteria(tok, [self.R], prec), "unsupported", prec)

    def test_unsupported_algorithm_raised_by_the_engine_is_unsupported(self):
        tok = tp.signed_tsr(self.tst(), self.tsa, self.root[1])
        orig = wv._verify_sig

        def raising(*a, **k):
            raise UnsupportedAlgorithm("disabled in this build")
        wv._verify_sig = raising
        try:
            for prec in BOTH:
                self.assertEqual(self.criteria(tok, [self.R], prec), "unsupported", prec)
        finally:
            wv._verify_sig = orig

    def test_issuer_without_keyCertSign_or_basicConstraints_is_failed_when_anchored(self):
        # 1.4.1: "a chain that reaches the anchor but fails a check is `failed`"; without the anchor, `untrusted`
        ku = x509.KeyUsage(True, False, False, False, False, False, False, False, False)     # digitalSignature only
        for name, inter in (("no keyCertSign", issuer_cert(self.root, "no keyCertSign", key_usage=ku)),
                            ("no basicConstraints", issuer_cert(self.root, "no basicConstraints",
                                                                basic_constraints=False))):
            tok = tp.signed_tsr(self.tst(), tp.make_tsa(inter, cn="under " + name), self.root[1],
                                certs=[inter[1], self.root[1]])
            for prec in BOTH:
                self.assertEqual(self.criteria(tok, [self.R], prec), "failed", (name, prec))
                self.assertEqual(self.criteria(tok, [b64(tp.der(self.other_root[1]))], prec), "untrusted", (name, prec))


    def test_expired_signer_is_failed_also_when_no_chain_reaches_an_anchor(self):
        # 1.4.1: "the signer ... valid at genTime" is a check that can run whatever the anchors: `failed`, not
        # `untrusted`, when the only anchor is unrelated
        tsa_expired = tp.make_tsa(self.root, cn="war-verify TEST TSA expired (nemesis 141)", na="20260101000000Z")
        tok = tp.signed_tsr(self.tst(), tsa_expired, self.root[1])
        for prec in BOTH:
            self.assertEqual(self.criteria(tok, [b64(tp.der(self.other_root[1]))], prec), "failed", prec)
            self.assertEqual(self.criteria(tok, [self.R], prec), "failed", prec)
        self.assertEqual(self.criteria(tok, None), "not_evaluated")


class Shape(Base):
    def test_no_token_no_tsa_signature_member(self):
        d = load(V16)["inputs"]
        self.assertNotIn("tsa_signature", wv.verify(d))
        d["tsa_roots_base64"] = [self.R]
        self.assertNotIn("tsa_signature", wv.verify(d))

    def test_structural_tokens_keep_token_authentication_and_their_own_details_key(self):
        rep = wv.verify(self.v31["inputs"])
        self.assertTrue(rep["details"]["token_authentication"]["criteria_token"].startswith("unauthenticated"))
        self.assertIn("criteria_token_tsa_signature", rep["details"])
        self.assertNotIn("criteria_token_tsa", rep["details"])

    def test_compare_refuses_a_tsa_signature_expectation_that_is_not_an_object(self):
        ours = {"tsa_signature": {"criteria": "verified", "receipt": "verified"}}
        for theirs in ("", [], 5, None, "verified", {"criteria": "verified", "record": "not_evaluated"},
                       {"record": "not_evaluated"}):
            self.assertFalse(wv.compare(ours, {"tsa_signature": theirs})["agree"], theirs)
            self.assertFalse(wv.compare({}, {"tsa_signature": theirs})["agree"], theirs)


class CLI(unittest.TestCase):
    def run_cli(self, *args, pre=None):
        wvp = os.path.join(_paths.ROOT, "war_verify.py")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        if pre is None:
            p = subprocess.run([sys.executable, "-B", wvp] + list(args), capture_output=True, text=True, env=env)
        else:
            code = pre + "; import runpy, sys; sys.argv = %r; runpy.run_path(%r, run_name='__main__')" % (
                [wvp] + list(args), wvp)
            p = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, env=env)
        return p.returncode, p.stdout

    def test_tsa_precedence_switch_reaches_the_report(self):
        rc, out = self.run_cli("--tsa-precedence", "evaluability-first", "--vector", V31)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["report"]["options"]["tsa_precedence"], "evaluability-first")
        self.assertEqual(self.run_cli("--tsa-precedence", "bogus", "--vector", V31)[0], 64)

    def test_empty_anchor_list_needs_no_chain_api(self):
        # "An empty tsa_roots_base64 array is read as without relying-party anchors": also where the TSA checks
        # could not run (cryptography < 40, simulated by hiding the class), because nothing is evaluated
        d = load(V31)
        d["inputs"]["tsa_roots_base64"] = []
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "v.json")
            with open(p, "w") as fh:
                json.dump(d, fh)
            rc, out = self.run_cli("--vector", p, pre="import cryptography.x509 as x; x.Certificate = type('C', (), {})")
        self.assertEqual(rc, 3, out)        # 31 expects verified: disagree, but no exit 74
        rep = json.loads(out)["report"]
        self.assertEqual(rep["cannot_run"], [])
        self.assertEqual(rep["tsa_signature"], {"criteria": "not_evaluated", "receipt": "not_evaluated"})


if __name__ == "__main__":
    unittest.main()
