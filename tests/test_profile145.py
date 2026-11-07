"""Profile 1.4.5 (maximusrufus/work-acceptance-record@c4b4bd4, README step 12, vectors 110-111). Oracle: the c4b4bd4
vectors, and generative cases whose expectation comes from the hand-written labels of LISTS below and from the
sentences of step 12 (README of this project, "Profile 1.4.5 rules", U1-U9), never from running the verifier. Positive
control: run on 0.8.0 (ce8de8c), these tests fail (README, "Tests"). From 0.10.0 they run under --profile 1.4.5, the 0.9.0
readings, and on --set c4b4bd4: tests/test_profile147.py holds what 1.4.7 fixes otherwise."""
import base64
import copy
import hashlib
import itertools
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import _paths  # noqa: F401
import build
import score
import test_profile144 as t
import war_verify as wv

P144 = wv.PROFILE_1_4_4
P145 = wv.PROFILE_1_4_5
SET = "c4b4bd4"
STEP1 = wv.STEP1_REASON
X = "INDEPENDENCE_INCONSISTENT"
MISSING = t.MISSING
SIGNER = t.SIGNER
RP = "relying_party_keys"
K1, K2 = build.pub_b64(SIGNER), build.pub_b64("omega-test-2")
K3 = base64.b64encode(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"war-verify-omega TEST key 3 - published seed, "
     b"never trust").digest()).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
K2_NONCANON = K2[:-2] + ALPHABET[ALPHABET.index(K2[-2]) + 1] + "="          # one padding bit set: same bytes, not canonical
K2_BYTES = base64.b64decode(K2)
# the same key plus the point of order 2: signatures can be shared with K2, but another decoded key (U4)
K2_TORSION = base64.b64encode(wv._encode_point(wv._padd(
    wv.ed_decode(K2_BYTES), wv.ed_decode(bytes([0xEC] + [0xFF] * 30 + [0x7F]))))).decode()
assert base64.b64decode(K2_TORSION) != K2_BYTES and wv.ed_same_key(K2_BYTES, base64.b64decode(K2_TORSION))
assert wv.b64_canonical(K2_NONCANON) is None and K3 != K2


SHORT = base64.b64encode(b"\x01" * 31).decode()


def read(f):
    with open(f, "rb") as fh:
        return fh.read()


def entry(kid, pub, **more):
    return dict({"alg": "Ed25519", "key_id": kid, "public_key_base64": pub, "status": "test"}, **more)


def rpdoc(entries, **more):
    return dict({"keys": entries}, **more)


# (label, entries, the keys the list holds, by the labels below): written by hand from U2, U4 and U9
LISTS = [
    ("empty", [], set()),
    ("another key", [entry("a", K3)], {"k3"}),
    ("the producer's key", [entry("p", K2)], {"k2"}),
    ("the producer's key, its identifier", [entry("omega-test-2", K2)], {"k2"}),
    ("the producer's identifier, other bytes", [entry("omega-test-2", K3)], {"k3"}),
    ("the signer's key", [entry("x", K1)], {"k1"}),
    ("both keys", [entry("x", K1), entry("p", K2)], {"k1", "k2"}),
    ("the producer's key, repeated identifier", [entry("a", K2), entry("a", K2)], set()),
    ("repeated identifier, the key second", [entry("a", K3), entry("a", K2)], set()),
    ("repeated identifier, the key first", [entry("a", K2), entry("a", K3)], set()),
    ("not canonical", [entry("a", K2_NONCANON)], set()),
    ("not canonical, and clean", [entry("a", K2_NONCANON), entry("b", K2)], {"k2"}),
    ("repeated, and clean", [entry("a", K3), entry("a", K3), entry("b", K2)], {"k2"}),
    ("the same key under two identifiers", [entry("a", K2), entry("b", K2)], {"k2"}),
    ("another key plus torsion", [entry("a", K2_TORSION)], set()),
    ("listed under an unlisted identifier", [entry("ghost", K2)], {"k2"}),
]
KEY_OF = {"omega-test-2": "k2", SIGNER: "k1", "alias-1": "k1"}
# (name, label for t.oracle)
PRODUCERS = [("Example Vendor", "example vendor"), ("Example Checker", "example checker"), (" EXAMPLE checker\n", "example checker"),
             (None, t.ABSENT), (MISSING, t.ABSENT), ("unknown", t.ABSENT), (7, "J:7")]
CHECKER = ("Example Checker", "example checker")


def doc(stated, pname, pk, rp=MISSING, ck=SIGNER, cname=CHECKER[0], full=False):
    """full: the key list of tests/test_profile144.py, which has repeated entries (KEY_REJECTED, 79); else two clean ones."""
    i = t.doc(stated, cname, pname, ck, pk)
    if not full:
        i["keys"]["keys"] = i["keys"]["keys"][:2]
    if rp is not MISSING:
        i[RP] = copy.deepcopy(rp)
    return i


def run(i, opts=None, **kw):
    try:
        return wv.verify(copy.deepcopy(i), dict(P145, **(opts or {})), **kw)
    except wv.Refusal as e:
        return {"refused": True, "reason": e.reason, "detail": e.detail}


def applies(stated, pk):
    return stated == "independent" and pk not in (MISSING, None)


def expected(stated, plabel, pk, pkind, holds):
    """Steps 8 and 12, on the hand-written labels: (derived, one key, rule applied, key held)."""
    derived, one_key = t.oracle(stated, CHECKER[1], plabel, SIGNER, "signer", pk, pkind)
    held = KEY_OF.get(pk) in holds
    if applies(stated, pk) and not held and derived == "independent":
        derived = "self-checked"
    return derived, one_key, applies(stated, pk), held


def table():
    for stated, (pn, pl), (pk, kind), (label, entries, holds) in itertools.product(
            ("independent", "self-checked"), PRODUCERS, t.KEYS, LISTS):
        yield stated, pn, pl, pk, kind, label, entries, holds


OUTCOME = wv.COMPARED + ("refused", "reason", "tsa_signature")


class Vectorsc4b4bd4(unittest.TestCase):
    def test_112_of_112(self):
        rows = score.score(which=SET)
        self.assertEqual(len(rows), 112)                    # 01-111 and the live record
        self.assertEqual([r["file"] for r in rows if not r["agree"]], [])
        self.assertEqual(sum(r["fields"] for r in rows), 1022)
        self.assertEqual([os.path.basename(f).split("-")[0] for f in score.vector_files(SET)[:-1]],
                         ["%02d" % n for n in range(1, 112)])

    def test_profile_1_4_4_disagrees_on_110_and_111_only(self):
        rows = score.score(dict(P144), which=SET)
        self.assertEqual([os.path.basename(r["file"]).split("-")[0] for r in rows if not r["agree"]], ["110", "111"])
        self.assertEqual(sum(r["fields_agree"] for r in rows), 1004)
        for f in score.vector_files(SET)[-3:-1]:
            rep = wv.run_vector_bytes(read(f), dict(P144))[0]
            self.assertEqual((rep["reason"], rep["reason_detail"]), ("unknown member(s) in inputs", RP))

    def test_older_sets_unchanged(self):
        for which, n, fields in (("1b81ec9", 110, 1004), ("6bb7d0b", 108, 986), ("85a310d", 88, 803), ("bc5a138", 58, 537),
                                 ("48ab8c9", 60, 557), ("1.4.1", 48, 441)):
            rows = score.score(which=which)
            self.assertEqual((len(rows), sum(r["agree"] for r in rows), sum(r["fields_agree"] for r in rows)),
                             (n, n, fields), which)

    def vector(self, n):
        return wv.strict_json_loads(read(score.vector_files(SET)[n - 1]))["inputs"]

    def test_110_derived_and_notes(self):
        rep = run(self.vector(110))
        self.assertEqual((rep["independence"], rep["details"]["independence_derived"]), ("independent", "self-checked"))
        self.assertIn("X_RP_PRODUCER_KEY_NOT_HELD", rep["extension_codes"])
        self.assertEqual(rep["warning_codes"], [])

    def test_110_without_the_list_is_clean(self):
        i = self.vector(110)
        del i[RP]
        rep = run(i)
        self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([], "independent"))

    def test_111_with_the_key_under_another_identifier(self):
        i = self.vector(111)
        i[RP]["keys"][1]["key_id"] = "the-producers-own-name"
        self.assertEqual(run(i)["problem_codes"], [])

    def test_111_with_the_identifier_on_other_bytes(self):
        i = self.vector(111)
        i[RP]["keys"][1]["public_key_base64"] = K2
        rep = run(i)
        self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([X], "self-checked"))

    def test_111_list_equals_the_issuers(self):                 # Q30
        i = self.vector(111)
        self.assertEqual(i[RP]["keys"], i["keys"]["keys"])

    def test_a_list_needs_not_hold_the_checker(self):           # U6
        i = self.vector(111)
        del i[RP]["keys"][0]
        self.assertEqual(run(i)["problem_codes"], [])

    def test_keys_replaced_the_rule_reads_the_list_in_use(self):        # U7
        i = self.vector(111)
        kf = copy.deepcopy(i["keys"])
        kf["keys"][1]["public_key_base64"] = K2                 # the key list in use names other bytes for the producer
        rep = run(i, keys_override=kf)
        self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([X], "self-checked"))
        i[RP]["keys"][1]["public_key_base64"] = K2
        self.assertEqual(run(i, keys_override=kf)["problem_codes"], [])


class Generative(unittest.TestCase):
    def test_every_record_of_the_table(self):
        n, bases = 0, {}
        for stated, pn, pl, pk, kind, label, entries, holds in table():
            n += 1
            where = (stated, pn, pk, label)
            rep = run(doc(stated, pn, pk, rpdoc(entries), full=True))
            self.assertFalse(rep.get("refused"), (where, rep))
            ident = (stated, repr(pn), repr(pk))
            if ident not in bases:
                bases[ident] = run(doc(stated, pn, pk, full=True))
            base = bases[ident]
            derived, one_key, applied, held = expected(stated, pl, pk, kind, holds)
            self.assertEqual(rep["details"]["independence_derived"], derived, where)
            self.assertEqual(rep["independence"], stated, where)
            self.assertEqual(X in rep["problem_codes"], derived != stated, where)
            self.assertEqual("KEY_COLLISION" in rep["problem_codes"], one_key, where)
            self.assertEqual(set(rep["problem_codes"]) - {X}, set(base["problem_codes"]) - {X}, where)
            self.assertEqual(rep["warning_codes"], base["warning_codes"], where)
            self.assertEqual("X_RP_KEYS_NOT_APPLIED" in rep["extension_codes"], not applied, where)
            self.assertEqual("X_RP_PRODUCER_KEY_NOT_HELD" in rep["extension_codes"], applied and not held, where)
            self.assertIn("X_RP_KEYS_FROM_INPUT", rep["local_blocks"], where)
            self.assertEqual("X_RP_KEYS_FROM_INPUT" in base["local_blocks"], False, where)
        self.assertEqual(n, 2 * len(PRODUCERS) * len(t.KEYS) * len(LISTS))

    def test_outcome_depends_on_the_order_of_nothing(self):
        rnd = random.Random(145)
        for _, entries, _h in LISTS:
            want = run(doc("independent", "Example Vendor", "omega-test-2", rpdoc(entries)))
            for _i in range(5):
                shuffled = [dict(sorted(e.items(), key=lambda _: rnd.random())) for e in rnd.sample(entries, len(entries))]
                got = run(doc("independent", "Example Vendor", "omega-test-2", rpdoc(shuffled)))
                self.assertEqual(got["problem_codes"], want["problem_codes"])
                self.assertEqual(got["details"]["independence_derived"], want["details"]["independence_derived"])

    def test_every_list_is_closed_the_same_on_a_rule_that_does_not_apply(self):
        for pk, stated in ((MISSING, "independent"), (None, "independent"), ("omega-test-2", "self-checked")):
            rep = run(doc(stated, "Example Vendor", pk, rpdoc([entry("a", K2, bogus=1)])))
            self.assertEqual((rep.get("reason"), rep.get("detail")), ("unknown member(s) in relying_party_keys.keys[0]", "bogus"))


GOOD = doc("independent", "Example Vendor", "omega-test-2", rpdoc([entry("p", K2)]))
TYPES = [None, True, False, 0, 1, -1, 1.5, "", "x", [], [1], [""], ["x"], {}, {"a": 1}, [[]], [{}], [None]]


class Closed(unittest.TestCase):
    def setUp(self):
        self.assertEqual(run(GOOD)["problem_codes"], [])

    def refused(self, i, reason=None, detail=None, opts=None):
        rep = run(i, opts)
        self.assertTrue(rep.get("refused"), rep)
        if reason is not None:
            self.assertEqual(rep["reason"], reason)
        if detail is not None:
            self.assertEqual(rep["detail"], detail)
        return rep

    def test_new_member_at_every_level(self):
        rnd = random.Random(1450)
        names = ["Keys", "KEYS", "key", "public_key", "publicKey", "public_key_base64 ", "", " ", "keys\x00", "kéys", "Keys",
                 "__proto__", "kid", "use", "x5c", "kty", "crv", "x"] + ["".join(rnd.choice("abcdef_") for _ in range(8)) for _ in range(30)]
        for name in names:
            i = copy.deepcopy(GOOD)
            i[RP][name] = 1
            self.refused(i, "unknown member(s) in relying_party_keys", name)
            i = copy.deepcopy(GOOD)
            i[RP]["keys"][0][name] = 1
            self.refused(i, "unknown member(s) in relying_party_keys.keys[0]", name)
            rep = run(i, {"unknown_fields": "report"})          # the one other value: a note, and the rule still runs
            self.assertIn("X_UNKNOWN_MEMBER", rep["extension_codes"])
            self.assertEqual(rep["problem_codes"], [])

    def test_a_name_near_the_input_is_unknown(self):
        for name in ("relying_party_key", "Relying_party_keys", "relying-party-keys", "relying_party_keys ", "relyingPartyKeys",
                     "relying_party_keys_base64", "rp_keys", "relying_party_keyſ"):
            i = copy.deepcopy(GOOD)
            i[name] = i.pop(RP)
            self.refused(i, "unknown member(s) in inputs", name)

    def test_required_members(self):
        i = copy.deepcopy(GOOD)
        del i[RP]["keys"]
        self.refused(i, "relying_party_keys lacks required member(s)", "keys")
        for m in ("alg", "key_id", "public_key_base64", "status"):
            i = copy.deepcopy(GOOD)
            del i[RP]["keys"][0][m]
            self.refused(i, "relying_party_keys.keys[0] lacks required member(s)", m)

    def test_issuer_is_optional_and_every_member_of_a_key_file_is_read(self):
        for more in ({"issuer": "A producer"}, {"version": "1"}, {"purpose": "x"}, {"also_published": ["u"]}, {"also_published": []},
                     {"issuer": "", "version": "", "purpose": "", "also_published": ["", "x"]}):
            i = copy.deepcopy(GOOD)
            i[RP].update(more)
            self.assertEqual(run(i)["problem_codes"], [], more)
        i = copy.deepcopy(GOOD)
        i[RP]["keys"][0]["since"] = "2026-11-05"
        self.assertEqual(run(i)["problem_codes"], [])

    def test_every_type_at_every_place(self):
        strings = lambda v: isinstance(v, str)                                  # noqa: E731
        # place -> (setter, the values it accepts, by hand), everything else refused
        ok_list = lambda v: isinstance(v, list) and all(isinstance(x, str) for x in v)   # noqa: E731
        places = [("input", lambda i, v: i.__setitem__(RP, v), lambda v: False),
                  ("issuer", lambda i, v: i[RP].__setitem__("issuer", v), strings),
                  ("version", lambda i, v: i[RP].__setitem__("version", v), strings),
                  ("purpose", lambda i, v: i[RP].__setitem__("purpose", v), strings),
                  ("also_published", lambda i, v: i[RP].__setitem__("also_published", v), ok_list),
                  ("keys", lambda i, v: i[RP].__setitem__("keys", v), lambda v: v == []),
                  ("entry", lambda i, v: i[RP]["keys"].__setitem__(0, v), lambda v: False),
                  ("key_id", lambda i, v: i[RP]["keys"][0].__setitem__("key_id", v), lambda v: strings(v) and v != ""),
                  ("alg", lambda i, v: i[RP]["keys"][0].__setitem__("alg", v), lambda v: False),
                  ("status", lambda i, v: i[RP]["keys"][0].__setitem__("status", v), lambda v: False),
                  ("since", lambda i, v: i[RP]["keys"][0].__setitem__("since", v), strings),
                  ("public_key_base64", lambda i, v: i[RP]["keys"][0].__setitem__("public_key_base64", v), strings)]
        for (name, setter, accepted), v in itertools.product(places, TYPES):
            i = copy.deepcopy(GOOD)
            setter(i, v)
            rep = run(i)
            self.assertEqual(bool(rep.get("refused")), not accepted(v), (name, v, rep))
            wrong_type = rep.get("refused") and not (
                (name in ("input", "entry") and isinstance(v, dict)) or (name == "keys" and isinstance(v, list)) or
                (name in ("alg", "status", "key_id") and isinstance(v, str)))
            if wrong_type:                                  # step 10 "Types": the step 1 outcome
                self.assertEqual(rep["reason"], STEP1, (name, v, rep))

    def test_null_never_switches_the_rule_off(self):
        i = copy.deepcopy(GOOD)
        i[RP] = None
        self.refused(i, STEP1)

    def test_the_rule_of_every_entry_runs_even_when_an_earlier_entry_holds_the_key(self):
        i = copy.deepcopy(GOOD)
        i[RP]["keys"].append(entry("b", K3, status="revoked"))
        self.refused(i)
        i = copy.deepcopy(GOOD)
        i[RP]["keys"].append(dict(entry("b", K3), alg="RS256"))
        self.refused(i, "relying_party_keys.keys[1].alg is not Ed25519")

    def test_raw_json(self):
        good = json.dumps({"inputs": GOOD}).encode()
        self.assertEqual(wv.run_vector_bytes(good)[0]["problem_codes"], [])
        for bad in (good.replace(b'"relying_party_keys": {', b'"relying_party_keys": {"keys": [], ', 1),              # member twice
                    good.replace(b'"relying_party_keys": {', b'"relying_party_keys": 1, "relying_party_keys": {', 1),  # input twice
                    good.replace(b'"key_id": "p"', b'"key_id": "p", "key_id": "q"', 1),
                    good.replace(b'"key_id": "p"', b'"key_id": "\\ud800"', 1),
                    good.replace(b'"key_id": "p"', b'"key_id": "p", "since": 9007199254740992', 1),
                    b"\xef\xbb\xbf" + good):
            self.assertNotEqual(bad, good)
            self.assertTrue(wv.run_vector_bytes(bad)[0].get("refused"), bad[:60])
        same = good.replace(b'"relying_party_keys"', b'"relying\\u005fparty_keys"', 1).replace(
            b'"public_key_base64": "' + K2.encode(), b'"public\\u005fkey_base64": "' + K2.encode(), 1)
        self.assertNotEqual(same, good)
        self.assertEqual(wv.run_vector_bytes(same)[0]["problem_codes"], [])

    def test_base64_forms_hold_no_key(self):
        url = K2.replace("+", "-").replace("/", "_")
        forms = [K2_NONCANON, K2 + "=", K2.rstrip("="), " " + K2, K2 + "\n", K2[:20] + "\n" + K2[20:], K2.lower(), K2_BYTES.hex(), "",
                 K2[:-1], "=" + K2, K2[:-4]]
        if url != K2:
            forms.append(url)
        for form in forms:
            i = doc("independent", "Example Vendor", "omega-test-2", rpdoc([entry("p", form)]))
            rep = run(i)
            self.assertFalse(rep.get("refused"), (form, rep))
            self.assertEqual(rep["problem_codes"], [X], form)
            self.assertEqual(rep["details"]["independence_derived"], "self-checked", form)

    def test_every_defect_is_a_local_block_and_named(self):
        for entries, text in (([entry("a", K2_NONCANON), entry("p", K2)], "not canonical base64"),
                              ([entry("a", K3), entry("a", K3), entry("p", K2)], "listed more than once"),
                              ([entry("t", K2_TORSION), entry("p", K2)], "mixed-order"),
                              ([entry("s", SHORT), entry("p", K2)], "not 32 bytes")):
            rep = run(doc("independent", "Example Vendor", "omega-test-2", rpdoc(entries)))
            self.assertEqual(rep["problem_codes"], [], text)
            self.assertIn("X_UNUSED_KEY_REJECTED", rep["local_blocks"], text)
            self.assertTrue([n for n in rep["notes"] if n.startswith("X_UNUSED_KEY_REJECTED: relying_party_keys.keys[") and text in n],
                            rep["notes"])
        clean = run(GOOD)
        self.assertNotIn("X_UNUSED_KEY_REJECTED", clean["local_blocks"])

    def test_a_key_that_is_no_point_counts_by_its_bytes(self):
        i = doc("independent", "Example Vendor", "weak", rpdoc([entry("p", SHORT)]))
        i["keys"]["keys"].append(entry("weak", SHORT))
        rep = run(i)
        self.assertEqual(rep["details"]["independence_derived"], "independent")
        self.assertIn("X_UNUSED_KEY_REJECTED", rep["local_blocks"])


class Rule(unittest.TestCase):
    def derived(self, i, opts=None):
        return run(i, opts)["details"]["independence_derived"]

    def test_not_applied_under_self_checked_keeps_t5(self):
        rep = run(doc("self-checked", "Example Vendor", "omega-test-2", rpdoc([entry("a", K3)])))
        self.assertEqual(rep["details"]["independence_derived"], "independent")
        self.assertEqual(rep["problem_codes"], [X])                 # 108: different parties, stated self-checked
        self.assertIn("X_RP_KEYS_NOT_APPLIED", rep["extension_codes"])

    def test_no_producer_key_id_rests_on_the_names(self):           # 82
        for pk in (MISSING, None):
            rep = run(doc("independent", "Example Vendor", pk, rpdoc([])))
            self.assertEqual(rep["problem_codes"], [])
            self.assertIn("X_RP_KEYS_NOT_APPLIED", rep["extension_codes"])

    def test_no_producer_at_all(self):
        i = t.doc("independent", "Example Checker", "x", SIGNER, MISSING, drop_producer=True)
        i[RP] = rpdoc([entry("a", K2)])
        rep = run(i)
        self.assertEqual(rep["details"]["independence_derived"], "undeclared")
        self.assertIn("PRODUCER_UNDECLARED", rep["warning_codes"])

    def test_q29_undeclared_comes_first(self):
        for name in (None, "", "unknown", MISSING):
            rep = run(doc("independent", name, "omega-test-2", rpdoc([entry("a", K3)])))
            self.assertEqual(rep["details"]["independence_derived"], "undeclared")
            self.assertEqual((rep["problem_codes"], rep["warning_codes"]), ([X], ["PRODUCER_UNDECLARED"]))
            self.assertIn("X_RP_PRODUCER_KEY_NOT_HELD", rep["extension_codes"])

    def test_the_signing_key_listed_is_still_one_key(self):         # "listed or used to sign", U6
        rep = run(doc("independent", "Example Vendor", SIGNER, rpdoc([entry("a", K1)])))
        self.assertIn("KEY_COLLISION", rep["problem_codes"])
        self.assertEqual(rep["details"]["independence_derived"], "self-checked")

    def test_unreadable_producer_entry_is_not_cured(self):          # U6
        for pk in ("dup", "noncanon", "dup-noncanon"):
            rep = run(doc("independent", "Example Vendor", pk, rpdoc([entry("a", K2), entry("b", K3)]), full=True))
            self.assertEqual(rep["details"]["independence_derived"], "self-checked", pk)
            self.assertIn("KEY_REJECTED", rep["problem_codes"], pk)

    def test_stated_independent_reading_does_not_apply_it(self):
        rep = run(doc("independent", "Example Vendor", "omega-test-2", rpdoc([])), {"independence_rule": "stated-independent"})
        self.assertEqual(rep["problem_codes"], [])
        self.assertIn("X_RP_KEYS_NOT_APPLIED", rep["extension_codes"])
        self.assertTrue([n for n in rep["notes"] if "--independence-rule derived" in n])

    def test_key_source_detail(self):
        self.assertIn("travels with the record", run(GOOD)["details"]["relying_party_keys_source"])
        i = copy.deepcopy(GOOD)
        lst = i.pop(RP)
        rep = run(i, rp_override=lst)
        self.assertIn("--relying-party-keys", rep["details"]["relying_party_keys_source"])
        self.assertNotIn("X_RP_KEYS_FROM_INPUT", rep["extension_codes"])
        self.assertNotIn("relying_party_keys_source", run(i)["details"])

    def test_override_is_a_list_of_its_own(self):
        i = doc("independent", "Example Vendor", "omega-test-2", rpdoc([entry("a", K3)]))
        rep = run(i, rp_override=rpdoc([entry("p", K2)]))
        self.assertEqual(rep["problem_codes"], [])
        self.assertTrue([n for n in rep["notes"] if n.startswith("inputs.relying_party_keys not used")])
        i[RP]["keys"][0]["bogus"] = 1                               # the replaced list stays closed
        self.assertEqual(run(i, rp_override=rpdoc([entry("p", K2)]))["reason"], "unknown member(s) in relying_party_keys.keys[0]")
        j = copy.deepcopy(GOOD)
        self.assertEqual(run(j, rp_override=rpdoc([entry("a", K3)]))["problem_codes"], [X])
        self.assertEqual(run(j, rp_override=None)["reason"], STEP1)            # null is not "no list"

    def test_override_needs_the_rule(self):
        with self.assertRaises(ValueError):
            wv.verify(copy.deepcopy(GOOD), dict(P144), rp_override=rpdoc([]))


class Switches(unittest.TestCase):
    """Q24-Q28: each reading and its alternative, one input each side."""
    def codes(self, i, **opts):
        rep = run(i, opts)
        return "refused" if rep.get("refused") else rep["problem_codes"]

    def test_q24_bare_list(self):
        i = doc("independent", "Example Vendor", "omega-test-2", [entry("p", K2)])
        self.assertEqual(run(i)["reason"], STEP1)
        self.assertEqual(self.codes(i, rp_form="bare-list"), [])
        i = doc("independent", "Example Vendor", "omega-test-2", [entry("p", K3)])
        self.assertEqual(self.codes(i, rp_form="bare-list"), [X])
        i = doc("independent", "Example Vendor", "omega-test-2", [])
        self.assertEqual(self.codes(i, rp_form="bare-list"), [X])
        i = doc("independent", "Example Vendor", "omega-test-2", rpdoc([entry("p", K2)]))
        self.assertEqual(self.codes(i, rp_form="bare-list"), [])     # the object stays read
        i = doc("independent", "Example Vendor", "omega-test-2", [1])
        self.assertEqual(self.codes(i, rp_form="bare-list"), "refused")

    def test_q25_empty(self):
        i = doc("independent", "Example Vendor", "omega-test-2", rpdoc([]))
        self.assertEqual(self.codes(i), [X])
        self.assertIn("X_RP_KEYS_EMPTY", run(i)["extension_codes"])
        self.assertEqual(self.codes(i, rp_empty="absent"), [])
        self.assertNotIn("X_RP_KEYS_FROM_INPUT", run(i, {"rp_empty": "absent"})["extension_codes"])
        self.assertIn("X_RP_KEYS_EMPTY", run(i, {"rp_empty": "absent"})["extension_codes"])
        self.assertTrue([n for n in run(i, {"rp_empty": "absent"})["notes"] if "read as absent" in n])
        self.assertEqual(run(i, {"rp_empty": "refuse"})["reason"], "relying_party_keys.keys is an empty list")

    def test_q26_repeated(self):
        for entries in ([entry("a", K2), entry("a", K3)], [entry("a", K3), entry("a", K2)], [entry("a", K2), entry("a", K2)]):
            i = doc("independent", "Example Vendor", "omega-test-2", rpdoc(entries))
            self.assertEqual(self.codes(i), [X])
            self.assertEqual(self.codes(i, rp_repeated="bytes"), [])
            self.assertNotIn("X_UNUSED_KEY_REJECTED", run(i, {"rp_repeated": "bytes"})["local_blocks"])     # V1, from 0.10.0
            self.assertTrue([n for n in run(i, {"rp_repeated": "bytes"})["notes"] if "compared by its bytes" in n])

    def test_q27_defect(self):
        for entries in ([entry("a", K2_NONCANON), entry("p", K2)], [entry("a", K3), entry("a", K3), entry("p", K2)],
                        [entry("t", K2_TORSION), entry("p", K2)]):
            i = doc("independent", "Example Vendor", "omega-test-2", rpdoc(entries))
            self.assertEqual(self.codes(i), [])
            self.assertEqual(self.codes(i, rp_entry_defect="key-rejected"), ["KEY_REJECTED"])
        self.assertEqual(self.codes(GOOD, rp_entry_defect="key-rejected"), [])
        # on a record outside the rule too: the finding is about the list
        i = doc("independent", "Example Vendor", MISSING, rpdoc([entry("a", K2_NONCANON)]))
        self.assertEqual(self.codes(i, rp_entry_defect="key-rejected"), ["KEY_REJECTED"])

    def test_q28_lookup(self):
        i = doc("independent", "Example Vendor", "ghost", rpdoc([entry("ghost", K2)]))
        self.assertEqual(self.codes(i), [X])
        self.assertEqual(self.codes(i, rp_lookup="both"), [])
        self.assertNotIn("party_key_unresolved", run(i, {"rp_lookup": "both"})["details"])
        i = doc("independent", "Example Vendor", "ghost", rpdoc([entry("ghost", K1)]))      # the signer's key: one key
        self.assertEqual(self.codes(i, rp_lookup="both"), [X, "KEY_COLLISION"])
        i = doc("independent", "Example Vendor", "ghost", rpdoc([entry("ghost", K2), entry("ghost", K3)]))
        self.assertEqual(self.codes(i, rp_lookup="both"), [X])                               # repeated: names no key
        i = doc("independent", "Example Vendor", "ghost", rpdoc([entry("ghost", K2), entry("ghost", K3)]))
        self.assertEqual(self.codes(i, rp_lookup="both", rp_repeated="bytes"), [X])
        i = doc("independent", "Example Vendor", "", rpdoc([entry("p", K2)]))
        self.assertEqual(self.codes(i, rp_lookup="both"), [X])                               # an empty id names no key
        i = doc("independent", "Example Vendor", "omega-test-2", rpdoc([entry("omega-test-2", K3)]))
        self.assertEqual(self.codes(i, rp_lookup="both"), [X])                               # listed: keys wins
        i = doc("independent", "Example Vendor", "noncanon", rpdoc([entry("noncanon", K2)]), full=True)
        self.assertIn(X, self.codes(i, rp_lookup="both"))                                    # listed, unreadable: keys wins

    def test_u4_not_key_id_and_not_ed_same_key(self):
        self.assertEqual(self.codes(doc("independent", "Example Vendor", "omega-test-2", rpdoc([entry("omega-test-2", K3)]))), [X])
        self.assertEqual(self.codes(doc("independent", "Example Vendor", "omega-test-2", rpdoc([entry("a", K2_TORSION)]))), [X])

    def test_every_value_gives_112_of_112(self):
        for key, values in wv.OPTION_VALUES.items():
            if key.startswith("rp_") and key != "rp_input":
                for v in values:
                    self.assertEqual(sum(r["agree"] for r in score.score({key: v}, which=SET)), 112, (key, v))


class Profiles(unittest.TestCase):
    def test_each_older_profile_refuses_the_input(self):
        for name, prof in wv.PROFILES.items():
            if name in ("1.4.5", "1.4.7"):
                continue
            self.assertEqual(prof["rp_input"], "unknown", name)
            rep = run(GOOD, prof)
            self.assertEqual((rep["reason"], rep["detail"]), ("unknown member(s) in inputs", RP), name)

    def test_report_of_unknown_fields_is_the_0_8_0_note(self):
        rep = run(doc("independent", "Example Vendor", "omega-test-2", rpdoc([])), dict(P144, unknown_fields="report"))
        self.assertIn("X_UNKNOWN_MEMBER: inputs.relying_party_keys (reported, not interpreted: --unknown-fields report)", rep["notes"])
        self.assertEqual(rep["details"]["independence_derived"], "independent")
        self.assertNotIn("X_RP_KEYS_FROM_INPUT", rep["extension_codes"])

    def test_explicit_switch_overrides_the_profile(self):
        self.assertEqual(run(GOOD, dict(P144, rp_input="step12"))["problem_codes"], [])

    def test_without_the_list_defaults_and_profile_1_4_4_report_the_same(self):
        for f in score.vector_files("1b81ec9"):
            raw = read(f)
            a, b = wv.run_vector_bytes(raw)[0], wv.run_vector_bytes(raw, dict(P144))[0]
            a.pop("options", None), b.pop("options", None)
            self.assertEqual(a, b, f)


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        p = subprocess.run([sys.executable, "-B", os.path.join(score.ROOT, "war_verify.py")] + list(args),
                           capture_output=True, text=True, env=env)
        return p.returncode, p.stdout, p.stderr

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.v110, self.v111 = score.vector_files(SET)[-3:-1]
        self.lst = self.write("rp.json", json.loads(read(self.v111))["inputs"][RP])

    def write(self, name, obj, raw=None):
        f = os.path.join(self.tmp.name, name)
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(raw if raw is not None else json.dumps(obj))
        return f

    def report(self, *args):
        rc, out, _ = self.run_cli(*args)
        return rc, json.loads(out)

    def test_the_file_replaces_the_list_of_the_document(self):
        rc, out = self.report("--relying-party-keys", self.lst, self.v110)
        rep = out["report"]
        self.assertEqual(rc, 1)
        self.assertEqual(rep["problem_codes"], [])
        self.assertTrue([n for n in rep["notes"] if n.startswith("inputs.relying_party_keys not used")])
        self.assertNotIn("X_RP_KEYS_FROM_INPUT", rep["local_blocks"])
        # a list that is replaced stays closed, but its entries are not read for the report
        d = json.loads(read(self.v110))
        d["inputs"][RP]["keys"][0]["public_key_base64"] = "@@@@"
        rep = self.report("--relying-party-keys", self.lst, self.write("defect.json", d))[1]["report"]
        self.assertNotIn("X_UNUSED_KEY_REJECTED", rep["local_blocks"])

    def test_vector_mode_uses_the_file(self):
        self.assertEqual(self.run_cli("--vector", self.v110)[0], 0)
        self.assertEqual(self.run_cli("--vector", "--relying-party-keys", self.lst, self.v110)[0], 3)

    def test_a_record_with_no_list(self):
        i = json.loads(read(self.v110))["inputs"]
        del i[RP]
        f = self.write("bare.json", i)
        self.assertEqual(self.report(f)[1]["report"]["problem_codes"], [])
        shorter = self.write("one.json", {"keys": [json.loads(read(self.lst))["keys"][0]]})
        self.assertEqual(self.report("--relying-party-keys", shorter, f)[1]["report"]["problem_codes"], [X])

    def test_usage_errors(self):
        for args in (("--relying-party-keys", "", self.v110), ("--relying-party-keys", self.lst, "--relying-party-keys", self.lst, self.v110),
                     ("--rp-input", "unknown", "--relying-party-keys", self.lst, self.v110)):
            self.assertEqual(self.run_cli(*args)[0], 64, args)
        for name in set(wv.PROFILES) - {"1.4.5", "1.4.7"}:
            rc, _, err = self.run_cli("--profile", name, "--relying-party-keys", self.lst, self.v110)
            self.assertEqual(rc, 64, name)
            self.assertIn("--rp-input step12", err)
        self.assertEqual(self.run_cli("--relying-party-keys")[0], 64)

    def test_a_switch_overrides_the_profile_on_the_command_line(self):
        self.assertEqual(self.run_cli("--profile", "1.4.4", "--rp-input", "step12", "--relying-party-keys", self.lst, self.v111)[0], 1)
        self.assertEqual(self.run_cli("--vector", "--profile", "1.4.4", self.v110)[0], 3)
        self.assertEqual(self.run_cli("--vector", "--profile", "1.4.4", "--rp-input", "step12", self.v110)[0], 0)

    def test_files_that_cannot_be_read(self):
        for name, raw in (("null.json", "null"), ("list.json", "[]"), ("text.json", "not json"), ("num.json", "1"),
                          ("dup.json", '{"keys":[],"keys":[]}'), ("unknown.json", '{"keys":[],"x":1}')):
            f = self.write(name, None, raw)
            rc, out = self.report("--relying-party-keys", f, self.v110)
            self.assertEqual((rc, out.get("refused") or out["report"].get("refused")), (2, True), name)
        self.assertEqual(self.run_cli("--relying-party-keys", os.path.join(self.tmp.name, "none"), self.v110)[0], 74)

    def test_the_document_list_stays_closed(self):
        d = json.loads(read(self.v110))
        d["inputs"][RP]["keys"][0]["bogus"] = 1
        f = self.write("v.json", d)
        self.assertEqual(self.run_cli("--relying-party-keys", self.lst, f)[0], 2)

    def live(self, *args):
        live = os.path.join(score.ROOT, "fonti", "issuer_274159c")
        return self.report("--keys", os.path.join(live, "checker-keys-live.json"), "--tokens", "pkix", "--tsa-roots",
                           os.path.join(score.ROOT, "roots", "freetsa_cacert.pem"), *args)

    def test_exit_0_and_the_local_block(self):
        live = os.path.join(score.ROOT, "fonti", "issuer_274159c")
        rec, kf = os.path.join(live, "selftest-pass.json"), os.path.join(live, "checker-keys-live.json")
        rc, out = self.live("--relying-party-keys", kf, rec)
        self.assertEqual(rc, 0)                                 # a real key file reads; the record has no producer key_id
        self.assertIn("X_RP_KEYS_NOT_APPLIED", out["report"]["extension_codes"])
        d = json.loads(read(rec))
        d["inputs"][RP] = json.loads(read(kf))
        rc, out = self.live(self.write("carried.json", d))
        self.assertEqual((rc, out["report"]["local_blocks"]), (1, ["X_RP_KEYS_FROM_INPUT"]))

    def test_keys_file_with_null(self):
        f = self.write("null.json", None, "null")
        rc, out = self.report("--keys", f, self.v111)
        self.assertEqual((rc, out["refused"], out["reason"]), (2, True, STEP1))
        rc, out = self.report("--profile", "1.4.4", "--unknown-fields", "report", "--keys", f, self.v111)    # as 0.8.0
        self.assertEqual(rc, 1)
        self.assertIn("X_KEY_FROM_INPUT", out["report"]["local_blocks"])
        rc, out = self.report("--rp-input", "unknown", "--unknown-fields", "report", "--keys", f, self.v111)
        self.assertEqual(rc, 1)                                  # the switch alone keeps it, and a switch overrides a profile
        self.assertEqual(self.run_cli("--profile", "1.4.4", "--rp-input", "step12", "--keys", f, self.v111)[0], 2)

    def test_each_switch_on_the_command_line(self):
        i = json.loads(read(self.v111))["inputs"]
        cases = [("--rp-form", "bare-list", dict(i, **{RP: i[RP]["keys"]}), 2, 1),
                 ("--rp-empty", "absent", dict(i, **{RP: {"keys": []}}), None, None),
                 ("--rp-repeated", "bytes", None, None, None), ("--rp-entry-defect", "key-rejected", None, None, None),
                 ("--rp-lookup", "both", None, None, None), ("--rp-input", "unknown", i, 1, 2)]
        for flag, value, inp, default_rc, alt_rc in cases:
            self.assertEqual(self.run_cli(flag, "bogus", self.v111)[0], 64, flag)
            self.assertEqual(self.run_cli(flag, value, flag, value, self.v111)[0], 64, flag)
            self.assertEqual(self.run_cli(flag, "", self.v111)[0], 64, flag)
            if default_rc is not None:
                f = self.write("sw.json", inp)
                self.assertEqual(self.run_cli(f)[0], default_rc, flag)
                self.assertEqual(self.run_cli(flag, value, f)[0], alt_rc, flag)
        f = self.write("e.json", dict(i, **{RP: {"keys": []}}))
        self.assertEqual(self.report(f)[1]["report"]["problem_codes"], [X])
        self.assertEqual(self.report("--rp-empty", "absent", f)[1]["report"]["problem_codes"], [])
        self.assertEqual(self.report("--rp-empty", "refuse", f)[0], 2)
        producer = i[RP]["keys"][1]
        f = self.write("r.json", dict(i, **{RP: {"keys": [dict(producer, key_id="a"), dict(producer, key_id="a")]}}))
        self.assertEqual(self.report("--profile", "1.4.5", f)[1]["report"]["problem_codes"], [X])
        self.assertEqual(self.report("--profile", "1.4.5", "--rp-repeated", "bytes", f)[1]["report"]["problem_codes"], [])
        self.assertEqual(self.report("--profile", "1.4.5", "--rp-entry-defect", "key-rejected", f)[1]["report"]["problem_codes"],
                         [X, "KEY_REJECTED"])
        g = dict(i)
        g["keys"] = dict(i["keys"], keys=[i["keys"]["keys"][0]])
        f = self.write("l.json", g)
        self.assertEqual(self.report(f)[1]["report"]["problem_codes"], [X])
        self.assertEqual(self.report("--rp-lookup", "both", f)[1]["report"]["problem_codes"], [])

    def test_version(self):
        self.assertEqual(self.report(self.v111)[1]["verifier"], "war_verify 0.11.0")

    def test_usage_text_names_every_flag(self):
        rc, out, _ = self.run_cli("--help")
        self.assertEqual(rc, 0)
        for flag in ("--relying-party-keys", "--rp-input", "--rp-form", "--rp-empty", "--rp-repeated", "--rp-entry-defect", "--rp-lookup",
                     "--profile 1.4.4"):
            self.assertIn(flag, out)


if __name__ == "__main__":
    unittest.main()
