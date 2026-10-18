"""Profile 1.3 rulings (maximusrufus/work-acceptance-record@42b4ed0), each with a positive control that fails under
this verifier's 1.2.1 reading or under a deliberately wrong rule."""
import base64
import copy
import unittest

import _paths  # noqa: F401
import build
import testpki as tp
import war_verify as wv

P121 = dict(wv.PROFILE_1_2_1)
T8 = wv.ed_decode((0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7).to_bytes(32, "little"))
ORDER2 = (wv._P - 1).to_bytes(32, "little")          # (0, -1): the point of order 2


def signer_key(enc, sig=None):
    i = build.base()
    i["keys"]["keys"][0]["public_key_base64"] = base64.b64encode(enc).decode()
    if sig is not None:
        i["receipt"]["signature"]["value"] = base64.b64encode(sig).decode()
    return i


class KeyRule(unittest.TestCase):
    def cases(self):
        A1 = wv.ed_decode(base64.b64decode(build.pub_b64("omega-test-1")))
        ident = (1).to_bytes(32, "little")
        return {"identity": ident, "y = p + 1": (1 + wv._P).to_bytes(32, "little"), "order 2": ORDER2,
                "x = 0 with sign bit": (1 | (1 << 255)).to_bytes(32, "little"),
                "mixed order": wv._encode_point(wv._padd(A1, T8)), "31 bytes": bytes(31), "33 bytes": bytes(33),
                "not a point": (2).to_bytes(32, "little")}

    def test_signer_key_rejected_and_no_signature_check(self):
        calls = []
        orig = wv.ed25519_verify
        wv.ed25519_verify = lambda *a: calls.append(a) or orig(*a)
        try:
            for name, enc in self.cases().items():
                ident = (1).to_bytes(32, "little")
                rep = wv.verify(signer_key(enc, ident + bytes(32)))
                self.assertEqual(rep["problem_codes"], ["KEY_REJECTED"], name)
                self.assertIs(rep["signature_valid"], False, name)
                self.assertFalse(rep["accepted_as_stated"], name)
                self.assertTrue(rep["details"]["signature_reason"].startswith("KEY_REJECTED"), name)
            self.assertEqual(calls, [])
            wv.verify(build.base())                                   # control: a good key is checked
            self.assertEqual(len(calls), 1)
        finally:
            wv.ed25519_verify = orig

    def test_1_2_1_reading_refuses(self):
        for name, enc in self.cases().items():
            with self.assertRaises(wv.Refusal, msg=name):
                wv.verify(signer_key(enc), P121)
        with self.assertRaises(wv.Refusal) as cm:
            wv.verify(signer_key(bytes(31)), P121)
        self.assertEqual(cm.exception.reason, "keys.keys[0].public_key_base64 is not 32 bytes")
        # 1.2.1 + --ed25519 rfc8032: a small-order key is accepted with a note, a non-canonical one is refused
        ident = (1).to_bytes(32, "little")
        rep = wv.verify(signer_key(ident, ident + bytes(32)), dict(P121, ed25519="rfc8032"))
        self.assertIn("X_WEAK_KEY", rep["extension_codes"])
        with self.assertRaises(wv.Refusal):
            wv.verify(signer_key((1 + wv._P).to_bytes(32, "little")), dict(P121, ed25519="rfc8032"))

    def test_unused_bad_key_is_a_local_block_or_key_rejected_under_all_keys(self):
        i = build.base()
        i["keys"]["keys"][1]["public_key_base64"] = base64.b64encode(ORDER2).decode()
        rep = wv.verify(copy.deepcopy(i))
        self.assertEqual(rep["problem_codes"], [])
        self.assertIs(rep["signature_valid"], True)
        self.assertIn("X_UNUSED_KEY_REJECTED", rep["local_blocks"])
        self.assertEqual(rep["details"]["rejected_keys"], {"omega-test-2": "small-order"})
        rep = wv.verify(copy.deepcopy(i), {"key_rule": "all-keys"})
        self.assertEqual(rep["problem_codes"], ["KEY_REJECTED"])
        self.assertNotIn("X_UNUSED_KEY_REJECTED", rep["extension_codes"])
        clean = wv.verify(build.base())                             # control
        self.assertNotIn("X_UNUSED_KEY_REJECTED", clean["extension_codes"])
        self.assertNotIn("rejected_keys", clean["details"])

    def test_vector_26_forgery_verifies_under_bare_equation(self):
        ident = (1).to_bytes(32, "little")
        self.assertTrue(wv.ed_verify_pure(ident, b"any message", ident + bytes(32)))   # why the rule exists


class KeyId(unittest.TestCase):
    def mk(self, sig_kid, rec_kid, signer):
        i = build.base()
        i["receipt"]["receipt"]["key_id"] = rec_kid
        i["receipt"]["signature"]["key_id"] = sig_kid
        build.refresh(i, sign_with=signer)
        return i

    def test_envelope_differs_is_signature_invalid(self):
        rep = wv.verify(self.mk("omega-test-2", "omega-test-1", "omega-test-1"))
        self.assertEqual(rep["problem_codes"], ["SIGNATURE_INVALID"])
        self.assertIs(rep["signature_valid"], False)
        self.assertFalse(rep["results_presented"])
        self.assertEqual(rep["details"]["verification_key_id"], "omega-test-1")
        rep = wv.verify(self.mk("omega-test-1", "omega-test-1", "omega-test-1"))      # control
        self.assertEqual(rep["problem_codes"], [])
        rep = wv.verify(self.mk("omega-test-2", "omega-test-1", "omega-test-1"), P121)  # 1.2.1: envelope chooses
        self.assertEqual(rep["problem_codes"], ["CHECKER_NOT_SIGNER", "SIGNATURE_INVALID"])

    def test_receipt_key_id_chooses_the_key(self):
        rep = wv.verify(self.mk("omega-test-2", "omega-test-2", "omega-test-1"))
        self.assertIn("SIGNATURE_INVALID", rep["problem_codes"])                       # signed by the other key
        rep = wv.verify(self.mk("omega-test-1", "omega-test-1", "omega-test-1"), {"key_id_agreement": "ignore"})
        self.assertIs(rep["signature_valid"], True)


class Step5(unittest.TestCase):
    def timed(self, issued, crit_gen, rec_gen, acc_c=None, acc_r=None, **kw):
        i = build.base()
        r = i["receipt"]["receipt"]
        r["issued_utc"] = issued
        build.criteria_token(i, gen=crit_gen, accuracy=acc_c, **kw)
        g = crit_gen
        frac = g[14:-1]
        r["criteria"]["committed_at"] = "%s-%s-%sT%s:%s:%s%sZ" % (g[:4], g[4:6], g[6:8], g[8:10], g[10:12], g[12:14],
                                                                  frac)
        build.sign(i)
        build.record_token(i, gen=rec_gen, accuracy=acc_r, **kw)
        return i

    def before(self, i, opts=None):
        return wv.verify(copy.deepcopy(i), opts)["criteria_committed_before_check"]

    def test_earlier_of_issued_and_covering_token(self):
        i = self.timed("2026-06-01T12:00:00Z", "20260601123000Z", "20260601130000Z")
        self.assertEqual(self.before(i), "no")
        self.assertEqual(self.before(i, {"reference_time": "covering-token"}), "yes")
        i = self.timed("2026-06-01T14:00:00Z", "20260601123000Z", "20260601130000Z")    # token earlier
        self.assertEqual(self.before(i), "yes")
        i = self.timed("2026-06-01T14:00:00Z", "20260601131000Z", "20260601130000Z")
        self.assertEqual(self.before(i), "no")

    def test_accuracy_boundary_millis_and_micros(self):
        # commit 12:00:00 + 1 ms, reference 12:00:00.002 - 1 ms: equal -> not strictly earlier
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120000.002Z", (None, 1, None), (None, 1, None))
        self.assertEqual(self.before(i), "no")
        self.assertEqual(self.before(i, {"accuracy": "ignore"}), "yes")
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120000.002001Z", (None, 1, None),
                       (None, 1, None))
        self.assertEqual(self.before(i), "yes")
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120000.002001Z", (None, 2, 1),
                       (None, None, None))
        self.assertEqual(self.before(i), "no")                       # 2.001 ms on the criteria token alone: equal
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120000.002001Z", (None, 2, None),
                       (None, None, None))
        self.assertEqual(self.before(i), "yes")                      # 2 ms: 1 microsecond earlier

    def test_accuracy_on_one_side_only(self):
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120001Z", (1, None, None), None)
        self.assertEqual(self.before(i), "no")
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120001Z", None, (1, None, None))
        self.assertEqual(self.before(i), "no")
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120001Z")
        self.assertEqual(self.before(i), "yes")
        self.assertEqual(self.before(i, {"accuracy": "interval"}), "undetermined")

    def test_ordering_ignored(self):
        name = tp._name("war-verify TEST TSA").public_bytes()
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120001Z", (1, None, None), (1, None, None),
                       ordering=True, tsa_name_der=name)
        self.assertEqual(self.before(i), "no")
        self.assertEqual(self.before(i, {"accuracy": "interval"}), "yes")       # RFC 3161 2.4.2 ordering clause

    def test_fallback_committed_at_has_no_accuracy(self):
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120001Z", None, (1, None, None))
        i["criteria_tsr_base64"] = None
        rep = wv.verify(copy.deepcopy(i))
        self.assertEqual(rep["warning_codes"], ["CRITERIA_COMMITMENT_UNVERIFIED"])
        self.assertEqual(rep["criteria_committed_before_check"], "no")          # 12:00:00 vs 12:00:01 - 1 s
        self.assertEqual(self.before(i, {"accuracy": "ignore"}), "yes")         # control

    def test_mismatching_token_never_widens(self):
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120003Z", (5, None, None), None)
        i["criteria_tsr_base64"] = base64.b64encode(tp.unsigned_tsr(tp.tstinfo(
            b"\x11" * 32, gen="20260601120000Z", accuracy=(5, None, None)))).decode()
        rep = wv.verify(copy.deepcopy(i))
        self.assertIn("CRITERIA_TIMESTAMP_MISMATCH", rep["problem_codes"])
        self.assertEqual(rep["criteria_committed_before_check"], "yes")         # committed_at, no accuracy
        i = self.timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120003Z", (5, None, None), None)
        self.assertEqual(self.before(i), "no")                                  # control: a matching token widens


class Independence(unittest.TestCase):
    def mk(self, stated, pname, pkid=None, cname="Example Checker"):
        i = build.base(token=False)
        i["criteria_tsr_base64"] = None
        r = i["receipt"]["receipt"]
        r["independence"] = stated
        r["parties"]["producer"] = {"key_id": pkid, "name": pname}
        r["parties"]["checker"]["name"] = cname
        build.sign(i)
        return wv.verify(i)

    def test_table(self):
        X = "INDEPENDENCE_INCONSISTENT"
        for stated, pname, pkid, derived, inc in (
                ("independent", "Example Vendor", None, "independent", False),
                ("independent", "Example Checker", None, "self-checked", True),
                ("independent", None, None, "undeclared", True),
                ("independent", "  ", None, "undeclared", True),
                ("independent", None, "omega-test-1", "self-checked", True),
                ("independent", None, "omega-test-2", "independent", False),
                ("self-checked", "Example Checker", None, "self-checked", False),
                ("self-checked", "Example Vendor", None, "independent", True),
                ("self-checked", None, None, "undeclared", True)):
            rep = self.mk(stated, pname, pkid)
            self.assertEqual(rep["details"]["independence_derived"], derived, (stated, pname, pkid))
            self.assertEqual(X in rep["problem_codes"], inc, (stated, pname, pkid))
            self.assertEqual("PRODUCER_UNDECLARED" in rep["warning_codes"], derived == "undeclared")
        rep = wv.verify(build.base(), {"independence_rule": "stated-independent"})        # control: 1.2.1 rule
        self.assertNotIn(X, rep["problem_codes"])


class OrderingDiagnostic(unittest.TestCase):
    """details.ordering_provable_under_accuracy is a diagnostic (RFC 3161 2.4.2), not a profile field. Under
    --accuracy widen the covering token stays the one it is measured against even when the reference label is
    'record token genTime - accuracy' (NEMESIS round 3: a mutant that passed None there survived every suite)."""

    def test_widen_label_keeps_the_covering_token(self):
        import json
        import os
        with open(os.path.join(_paths.ROOT, "vectors", "omega-49-ordering-true-ignored.json"), "rb") as fh:
            inputs = json.loads(fh.read())["inputs"]
        rep = wv.verify(copy.deepcopy(inputs))
        self.assertEqual(rep["details"]["reference_source"], "record token genTime - accuracy")
        self.assertEqual(rep["details"]["ordering_provable_under_accuracy"], "yes")
        self.assertEqual(rep["criteria_committed_before_check"], "no")     # ordering TRUE is ignored by the profile


if __name__ == "__main__":
    unittest.main()
