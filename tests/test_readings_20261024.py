"""Readings that the published vectors (bc5a138, PR #1 48ab8c9) do not yet fix, listed on x402-foundation/tsc#4 on
2026-10-24 as candidate vectors, plus the unsigned envelope timestamp.digest_sha256 (README step 6: "informative and
never decides the outcome") and the receipt.tools member of vectors 52 and 57. Each test states which sentence decides
it; where the profile is silent the test pins this verifier's declared choice (README, options table) so that a change
is seen.

Oracle for RFC 8785 serialization: Node v22.23.2, JSON.stringify for numbers and strings and Array.prototype.sort for
member names (UTF-16 code units), run once on 2026-10-24; its output is the literal below."""
import base64
import copy
import hashlib
import json
import os
import unittest

import _paths  # noqa: F401
import war_verify as wv
from _nemesis_forge import Key, b64, tsr, tst

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V01 = os.path.join(ROOT, "fonti/upstream_f7d8984/vectors/01-valid.json")
NODE_OBJ = {"tools": {"numbers_for_canonicalization": [1.5e-7, 1.25e+22, 1e21, 2.5e-300, 0.30000000000000004, -0.0,
                                                        5e-324],
                      "k": {"\U0001F600": 1, "｡": 2, "a": 3}}}
NODE_JCS = ('{"tools":{"k":{"a":3,"\U0001F600":1,"｡":2},"numbers_for_canonicalization":'
            '[1.5e-7,1.25e+22,1e+21,2.5e-300,0.30000000000000004,0,5e-324]}}').encode("utf-8")
K, K2 = Key(7, "k1"), Key(9, "k2")


def doc(edit=None, keys=None, env_kid=None, sig_value=None, record_token=False, env_ts=None):
    with open(V01, "rb") as fh:
        i = wv.strict_json_loads(fh.read())["inputs"]
    i.pop("receipt_tsr_base64")
    r = i["receipt"]["receipt"]
    r["key_id"] = "k1"
    r["parties"]["checker"]["key_id"] = "k1"
    if edit:
        edit(r)
    canon = wv.jcs(r)
    env = {"receipt": r, "signature": {"alg": "Ed25519", "key_id": env_kid or "k1",
                                       "value": sig_value or b64(K.sk.sign(canon))}}
    if record_token:
        dig = hashlib.sha256(canon).digest()
        i["receipt_tsr_base64"] = b64(tsr(tst(dig, "20261020153900Z")))
        env["timestamp"] = env_ts(dig) if env_ts else {
            "covers": wv.COVERS, "digest_sha256": dig.hex(), "gen_time": "20261020153900Z", "status": "granted",
            "tsa": "x", "tsr_file": "r.tsr"}
    i["receipt"] = env
    i["keys"] = keys or {"issuer": "x", "keys": [K.entry(), K2.entry()]}
    return i


def sign_bytes(i, canon):
    i["receipt"]["signature"]["value"] = b64(K.sk.sign(canon))
    return i


def verify(i, opts=None):
    try:
        return wv.verify(i, opts)
    except wv.Refusal as e:
        # 0.6.0: a type error is refused with the step 1 reason (profile 1.4.2 R8) and the path in the detail
        return {"refused": True, "reason": e.reason if not e.detail else "%s | %s" % (e.reason, e.detail)}


class Canonicalization(unittest.TestCase):
    def test_node_oracle_bytes(self):
        self.assertEqual(wv.jcs(copy.deepcopy(NODE_OBJ)), NODE_JCS)

    def test_positive_control_code_point_order_differs(self):
        cp = json.dumps(NODE_OBJ, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertNotEqual(cp, NODE_JCS)

    def test_signed_receipt_with_these_members_passes(self):
        # numbers_for_canonicalization is the member of vectors 52 and 57; "k" (names outside the BMP) is no member of
        # the receipt: refused by default, canonicalized and reported under --unknown-fields report
        edit = lambda r: r["tools"].update(copy.deepcopy(NODE_OBJ["tools"]))
        rep = verify(doc(edit), {"unknown_fields": "report"})
        self.assertIs(rep.get("signature_valid"), True, rep)
        self.assertEqual(rep["problem_codes"], [])
        self.assertIn("X_UNKNOWN_MEMBER: receipt.tools.k (reported, not interpreted: --unknown-fields report)", rep["notes"])
        self.assertTrue(verify(doc(edit)).get("refused"))
        nums = lambda r: r["tools"].__setitem__("numbers_for_canonicalization",
                                                copy.deepcopy(NODE_OBJ["tools"]["numbers_for_canonicalization"]))
        rep = verify(doc(nums))
        self.assertIs(rep.get("signature_valid"), True, rep)
        self.assertEqual(rep["problem_codes"], [])

    def test_signature_over_python_repr_numbers_is_invalid(self):
        edit = lambda r: r["tools"].__setitem__("numbers_for_canonicalization", [1.5e-7, 1.25e+22])
        i = doc(edit)
        other = json.dumps(i["receipt"]["receipt"], sort_keys=True, separators=(",", ":")).encode()
        self.assertIn(b"1.5e-07", other)                               # control: the bytes do differ
        rep = verify(sign_bytes(i, other))
        self.assertEqual(rep["problem_codes"], ["SIGNATURE_INVALID"])

    def test_signature_over_code_point_order_is_invalid(self):
        edit = lambda r: r["tools"].__setitem__("k", {"\U0001F600": 1, "\uff61": 2})
        i = doc(edit)
        other = json.dumps(i["receipt"]["receipt"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        self.assertNotEqual(other, wv.jcs(i["receipt"]["receipt"]))  # control: the bytes do differ
        rep = verify(sign_bytes(i, other), {"unknown_fields": "report"})
        self.assertEqual(rep["problem_codes"], ["SIGNATURE_INVALID"])


class Keys(unittest.TestCase):
    def test_envelope_key_id_differs_from_signed_key_id(self):
        # step 2: "The envelope's signature.key_id must equal it, else SIGNATURE_INVALID"
        rep = verify(doc(env_kid="k2"))
        self.assertIn("SIGNATURE_INVALID", rep["problem_codes"])

    def test_one_public_key_under_two_ids_is_a_key_collision(self):
        # property 3: "The checker key must not equal the producer key" (the key, not its id)
        dup = {"issuer": "x", "keys": [K.entry(), dict(K.entry(), key_id="k1-alias"), K2.entry()]}
        rep = verify(doc(lambda r: r["parties"]["producer"].__setitem__("key_id", "k1-alias"), keys=dup))
        self.assertEqual(sorted(rep["problem_codes"]), ["INDEPENDENCE_INCONSISTENT", "KEY_COLLISION"])
        rep = verify(doc(keys=dup))                                     # producer null: nothing to compare
        self.assertNotIn("KEY_COLLISION", rep["problem_codes"])

    def test_producer_and_checker_naming_the_same_key_id(self):
        rep = verify(doc(lambda r: r["parties"]["producer"].__setitem__("key_id", "k1")))
        self.assertEqual(sorted(rep["problem_codes"]), ["INDEPENDENCE_INCONSISTENT", "KEY_COLLISION"])


class Times(unittest.TestCase):
    def test_fractional_seconds_in_issued_utc_are_read(self):
        # profile 1.4.2 R5: YYYY-MM-DDTHH:MM:SS[.fff]Z. Reading (README, R5): exactly three digits; until 0.5.0 one to
        # nine digits were read, from 0.6.0 ".5Z" is RECEIPT_TIME_UNREADABLE.
        rep = verify(doc(lambda r: r.__setitem__("issued_utc", r["issued_utc"].replace("Z", ".500Z"))))
        self.assertFalse(rep.get("refused"), rep)
        self.assertEqual(rep["problem_codes"], [])
        rep = verify(doc(lambda r: r.__setitem__("issued_utc", r["issued_utc"].replace("Z", ".5Z"))))
        self.assertEqual(rep["problem_codes"], ["RECEIPT_TIME_UNREADABLE"])
        self.assertEqual(rep["criteria_committed_before_check"], "no")


class Times2(unittest.TestCase):
    def test_imprint_match_without_issued_utc_is_refused(self):
        # candidate reading 8 ("imprint_match with no issue time"): issued_utc is a member of every published receipt
        rep = verify(doc(lambda r: r.pop("issued_utc"), record_token=True))
        self.assertTrue(rep.get("refused"), rep)
        self.assertIn("lacks required member", rep["reason"])


class Tools(unittest.TestCase):
    def test_required_members_still_required(self):
        for m in ("profile", "validator"):
            rep = verify(doc(lambda r: r["tools"].pop(m)))
            self.assertTrue(rep.get("refused"), (m, rep))
            self.assertIn("lacks required member", rep["reason"])

    def test_numbers_for_canonicalization_noted(self):
        # vectors 52 and 57: the one member they add to receipt.tools, an array of numbers
        for v in ([], [1, 2.5, -0.0, 1e21]):
            rep = verify(doc(lambda r: r["tools"].__setitem__("numbers_for_canonicalization", v)))
            self.assertEqual(rep["problem_codes"], [], v)
            self.assertIn("receipt.tools.numbers_for_canonicalization not interpreted (profile 1.4.1 vectors 52, 57: "
                          "outcome-neutral)", rep["notes"])
        for v in ("1", 1, None, {}, [True], ["1"], [[1]]):
            rep = verify(doc(lambda r: r["tools"].__setitem__("numbers_for_canonicalization", v)))
            self.assertTrue(rep.get("refused"), v)
            self.assertIn("not an array of numbers", rep["reason"])

    def test_other_members_stay_unknown(self):
        # no vector or sentence opens receipt.tools to other members: closed by construction
        rep = verify(doc(lambda r: r["tools"].__setitem__("x_other", 1)))
        self.assertTrue(rep.get("refused"), rep)
        self.assertIn("unknown member(s) in receipt.tools", rep["reason"])
        rep = verify(doc(lambda r: r["tools"].__setitem__("x_other", 1)), {"unknown_fields": "report"})
        self.assertEqual(rep["problem_codes"], [])
        self.assertIn("X_UNKNOWN_MEMBER: receipt.tools.x_other (reported, not interpreted: --unknown-fields report)",
                      rep["notes"])

    def test_tools_not_an_object_refused(self):
        for v in (["profile", "validator"], "profile", None, 1):
            rep = verify(doc(lambda r: r.__setitem__("tools", v)))
            self.assertTrue(rep.get("refused"), v)
            self.assertIn("receipt.tools is not a JSON object", rep["reason"])


class Encodings(unittest.TestCase):
    """Until 0.5.0 the profile was silent and this verifier refused; profile 1.4.2 fixes both: a non-canonical
    signature value is SIGNATURE_INVALID (R1, vectors 60-63) and an upper-case digest matches nothing (R2, 67)."""

    def test_base64_outside_the_alphabet_unpadded_or_url_refused(self):
        sig = doc()["receipt"]["signature"]["value"]
        for v in (sig[:-3] + "*==", sig.rstrip("="), sig.replace("+", "-").replace("/", "_")):
            if v == sig:
                continue
            rep = verify(doc(sig_value=v))
            self.assertFalse(rep.get("refused"), v)
            self.assertIs(rep["signature_valid"], False)
            self.assertEqual(rep["problem_codes"], ["SIGNATURE_INVALID"], v)

    def test_upper_case_hex_refused(self):
        rep = verify(doc(lambda r: r["criteria"].__setitem__("sha256", r["criteria"]["sha256"].upper())))
        self.assertFalse(rep.get("refused"))
        self.assertIn("CRITERIA_HASH_MISMATCH", rep["problem_codes"])


class EnvelopeTimestamp(unittest.TestCase):
    """README step 6: the record token's imprint decides receipt_timestamp; "the unsigned timestamp.digest_sha256 field
    is informative and never decides the outcome". From 0.5.0 a digest_sha256 outside its form is
    X_TIMESTAMP_METADATA_MALFORMED and a note, never a refusal; the other members of the envelope timestamp are not
    named by the profile and keep the issuer's form (refusal under --unknown-fields refuse, as until 0.4.1)."""

    def variants(self):
        def g(**kw):
            def f(dig):
                t = {"covers": wv.COVERS, "digest_sha256": dig.hex(), "gen_time": "20261020153900Z",
                     "status": "granted", "tsa": "x", "tsr_file": "r.tsr"}
                t.update(kw)
                return {k: v for k, v in t.items() if v is not DROP}
            return f
        DROP = object()
        digest = [g(digest_sha256=v) for v in ("AB" * 32, "ab" * 31, "", 7, None, ["ab" * 32], {})] + [g(digest_sha256=DROP)]
        other = [g(gen_time=DROP), g(gen_time="2026-10-20T15:39:00Z"), g(covers=7), g(status="pending"),
                 g(x_extra="1"), g(tsa=7), g(tsr_file=None), lambda dig: [], lambda dig: "granted",
                 lambda dig: {"status": "none"}, lambda dig: {"status": "none", "reason": 7},
                 lambda dig: {"status": "none", "reason": "r", "x_extra": 1}]
        return digest, other

    def test_digest_never_decides(self):
        digest, _ = self.variants()
        for f in digest[:-1]:
            rep = verify(doc(record_token=True, env_ts=f))
            self.assertFalse(rep.get("refused"), rep)
            self.assertEqual(rep["receipt_timestamp"], "imprint_match")
            self.assertEqual(rep["problem_codes"], [])
            self.assertIn("X_TIMESTAMP_METADATA_MALFORMED", rep["extension_codes"])
            self.assertNotIn("X_TIMESTAMP_METADATA_DISAGREES", rep["extension_codes"])
            self.assertTrue(any(n.startswith("X_TIMESTAMP_METADATA_MALFORMED: envelope.timestamp.digest_sha256 is not")
                                and n.endswith("never decides the outcome: profile step 6)") for n in rep["notes"]),
                            rep["notes"])
        rep = verify(doc(record_token=True, env_ts=digest[-1]))       # a missing member is outside the form
        self.assertTrue(rep.get("refused"))
        self.assertIn("lacks required member", rep["reason"])

    def test_other_members_keep_the_form(self):
        _, other = self.variants()
        for f in other:
            rep = verify(doc(record_token=True, env_ts=f))
            self.assertTrue(rep.get("refused"), rep)
            self.assertIn("envelope.timestamp", rep["reason"])
        rep = verify(doc(record_token=True, env_ts=other[4]), {"unknown_fields": "report"})
        self.assertEqual(rep["receipt_timestamp"], "imprint_match")
        self.assertIn("X_UNKNOWN_MEMBER: envelope.timestamp.x_extra (reported, not interpreted: --unknown-fields report)",
                      rep["notes"])
        self.assertNotIn("X_TIMESTAMP_METADATA_MALFORMED", rep["extension_codes"])

    def test_well_formed_envelope_has_no_malformed_code(self):
        rep = verify(doc(record_token=True))
        self.assertEqual(rep["receipt_timestamp"], "imprint_match")
        self.assertNotIn("X_TIMESTAMP_METADATA_MALFORMED", rep["extension_codes"])


if __name__ == "__main__":
    unittest.main()
