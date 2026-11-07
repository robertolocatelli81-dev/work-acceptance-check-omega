"""Profile 1.4.4 (maximusrufus/work-acceptance-record@1b81ec9, README step 8 "Derived independence" and "Stated and
derived", vectors 108-109). Oracle: the 1b81ec9 vectors, and generative cases whose expectation comes from the
hand-written labels of NAMES and KEYS below, taken from the sentences of step 8 (README of this project, "Profile 1.4.4
rules", T1-T7), never from running the verifier. Positive control: run on 0.7.0 (349a041), these tests fail (README,
"Tests")."""
import copy
import itertools
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

import _paths  # noqa: F401
import build
import score
import testpki as tp
import war_verify as wv

P143 = wv.PROFILE_1_4_3
STEP1 = wv.STEP1_REASON
X = "INDEPENDENCE_INCONSISTENT"
MISSING = object()
ABSENT = None                                # the label of a name that counts as absent

# (value, label): ABSENT, or what the name is equal to after step 8's comparison, written by hand
NAMES = [
    (MISSING, ABSENT), (None, ABSENT), (False, ABSENT), (0, ABSENT), (0.0, ABSENT), (-0.0, ABSENT), ("", ABSENT),
    ([], ABSENT), ({}, ABSENT), (" ", ABSENT), ("\t\r\n ", ABSENT), ("\x0b\x0c", ABSENT), ("\x85", ABSENT),
    ("\xa0", ABSENT), (" ", ABSENT), ("  ", ABSENT), ("  ", ABSENT), ("  ", ABSENT),
    ("　", ABSENT), ("unspecified", ABSENT), ("Unspecified", ABSENT), ("UNSPECIFIED\n", ABSENT),
    ("unknown", ABSENT), (" Unknown ", ABSENT), ("　UNKNOWN\xa0", ABSENT),
    (True, "J:true"), (1, "J:1"), (1.0, "J:1"), (-1, "J:-1"), (0.5, "J:0.5"), (1e-7, "J:1e-7"), ([0], "J:[0]"),
    ([""], 'J:[""]'), ([[]], "J:[[]]"), ([None], "J:[null]"), ({"a": 0}, 'J:{"a":0}'),
    ({"a": 1, "b": 2}, 'J:{"a":1,"b":2}'), ({"b": 2, "a": 1}, 'J:{"a":1,"b":2}'),
    ("x", "x"), (" X ", "x"), ("\tx　", "x"), ("Example Checker", "example checker"),
    (" example CHECKER\n", "example checker"), ("Example  Checker", "example  checker"), ("Example Vendor", "example vendor"),
    ("\x1cx", "\x1cx"), ("x\x1f", "x\x1f"), ("\x1c", "\x1c"), ("​x", "​x"), ("​", "​"),
    ("﻿", "﻿"), ("0", "0"), ("false", "false"), ("null", "null"), ("[]", "[]"), ("unknownx", "unknownx"),
    ("un known", "un known"), ("not specified", "not specified"), ("K", "k"), ("k", "k"),
    ("ΑΣ", "ας"), ("ας", "ας"), ("ασ", "ασ"),
    ("STRASSE", "strasse"), ("straße", "straße"), ("ﬁ", "ﬁ"), ("fi", "fi"),
]
assert len([v for v, _ in NAMES]) == len(NAMES) > 60

SIGNER = "omega-test-1"
# (identifier, class): the producer's or checker's stated key_id in a key list made by keylist()
KEYS = [(MISSING, "none"), (None, "none"), ("", "unlisted"), ("ghost", "unlisted"), ("omega-test-2", "listed"),
        ("dup", "unreadable"), ("noncanon", "unreadable"), ("dup-noncanon", "unreadable"), (SIGNER, "signer"),
        ("alias-1", "signer")]


def keylist():
    k1, k2 = build.pub_b64(SIGNER), build.pub_b64("omega-test-2")
    k3 = build.pub_b64("omega-test-3") if "omega-test-3" in build.SEEDS else k2
    i = build.base(token=False)
    entry = lambda kid, pub: dict(copy.deepcopy(i["keys"]["keys"][0]), key_id=kid, public_key_base64=pub)  # noqa: E731
    # the last character of a 32-byte key carries two zero padding bits: the next letter of the alphabet sets one
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    noncanon = k2[:-2] + alphabet[alphabet.index(k2[-2]) + 1] + "="
    assert wv.b64_canonical(noncanon) is None
    return [entry(SIGNER, k1), entry("omega-test-2", k2), entry("dup", k3), entry("dup", k3), entry("noncanon", noncanon),
            entry("dup-noncanon", noncanon), entry("dup-noncanon", k3), entry("alias-1", k1)]


KEYLIST = keylist()
BASE = build.base(token=False)


def doc(stated, cname, pname, ck=SIGNER, pk=MISSING, drop_producer=False):
    i = copy.deepcopy(BASE)
    i["keys"]["keys"] = copy.deepcopy(KEYLIST)
    r = i["receipt"]["receipt"]
    r["independence"] = stated
    p = {}
    if pname is not MISSING:
        p["name"] = pname
    if pk is not MISSING:
        p["key_id"] = pk
    r["parties"]["producer"] = p
    if drop_producer:
        del r["parties"]["producer"]
    r["parties"]["checker"] = {"name": cname, "key_id": ck}
    build.sign(i, sign_with=SIGNER)
    return i


def run(i, opts=None):
    try:
        return wv.verify(copy.deepcopy(i), dict(opts) if opts else None)
    except wv.Refusal as e:
        return {"refused": True, "reason": e.reason, "detail": e.detail}


def oracle(stated, clabel, plabel, ck, ckind, pk, pkind):
    """Step 8, sentence by sentence, on the hand-written labels."""
    one_key = pkind == "signer" or (pk not in (MISSING, None, "") and pk == ck)
    unread = "unreadable" in (ckind, pkind)
    unlisted = "unlisted" in (ckind, pkind)
    if plabel is ABSENT:
        derived = "undeclared"
    elif clabel is not ABSENT and clabel == plabel:
        derived = "self-checked"
    elif one_key or unread or (unlisted and stated == "independent"):
        derived = "self-checked"
    else:
        derived = "independent"
    return derived, one_key


class Base(unittest.TestCase):
    def check(self, stated, cn, pn, ck=SIGNER, ckind="signer", pk=MISSING, pkind="none", drop=False):
        rep = run(doc(stated, cn[0], pn[0], ck, pk, drop))
        where = (stated, cn, pn, ck, pk, drop)
        self.assertFalse(rep.get("refused"), (where, rep))
        derived, one_key = oracle(stated, cn[1], pn[1], ck, ckind, pk, pkind)
        self.assertEqual(rep["details"]["independence_derived"], derived, where)
        self.assertEqual(rep["independence"], stated, where)
        self.assertEqual(X in rep["problem_codes"], derived != stated, where)
        self.assertEqual("PRODUCER_UNDECLARED" in rep["warning_codes"], derived == "undeclared", where)
        self.assertEqual("SELF_CHECKED" in rep["warning_codes"], stated == "self-checked", where)
        self.assertEqual("KEY_COLLISION" in rep["problem_codes"], one_key, where)
        odd = [v for v in (cn[0], pn[0]) if v is not MISSING and v is not None and not isinstance(v, str)]
        self.assertEqual("X_NAME_NOT_STRING" in rep["extension_codes"], bool(odd), where)
        return rep


class Vectors1b81ec9(unittest.TestCase):
    def test_110_of_110(self):
        rows = score.score(which="1b81ec9")
        self.assertEqual(len(rows), 110)                    # 01-109 and the live record
        self.assertEqual([r["file"] for r in rows if not r["agree"]], [])
        self.assertEqual(sum(r["fields"] for r in rows), 1004)
        self.assertEqual([os.path.basename(f).split("-")[0] for f in score.vector_files("1b81ec9")[:-1]],
                         ["%02d" % n for n in range(1, 110)])

    def test_profile_1_4_3_disagrees_on_109_only(self):
        rows = score.score(dict(P143), which="1b81ec9")
        self.assertEqual([os.path.basename(r["file"]).split("-")[0] for r in rows if not r["agree"]], ["109"])

    def test_older_sets_unchanged(self):
        for which, n, fields in (("6bb7d0b", 108, 986), ("85a310d", 88, 803), ("bc5a138", 58, 537), ("48ab8c9", 60, 557),
                                 ("1.4.1", 48, 441)):
            rows = score.score(which=which)
            self.assertEqual((len(rows), sum(r["agree"] for r in rows), sum(r["fields_agree"] for r in rows)),
                             (n, n, fields), which)

    def test_positive_control_corrupted_expectation_is_caught(self):
        f = score.vector_files("1b81ec9")[-2]                # 109
        v = json.load(open(f, encoding="utf-8"))
        self.assertTrue(wv.run_vector(copy.deepcopy(v))[1]["agree"])
        v["expected"]["warning_codes"] = []
        self.assertFalse(wv.run_vector(v)[1]["agree"])


class GenerativeNames(Base):
    """The whole space of NAMES, as producer and as checker, under both claims."""

    def test_every_producer_name_with_a_named_checker(self):
        for stated, pn in itertools.product(("independent", "self-checked"), NAMES):
            self.check(stated, ("Example Checker", "example checker"), pn)
        ws = list(range(9, 14)) + [0x20, 0x85, 0xa0, 0x1680] + list(range(0x2000, 0x200b)) + [0x2028, 0x2029, 0x202f, 0x205f, 0x3000]
        self.assertEqual(len(ws), 25)                   # PropList.txt, White_Space, written here by hand (README Q22)
        for c in ws:
            self.assertEqual(wv._norm_name(chr(c) + "X" + chr(c), "trim-lower"), "x", hex(c))
            self.assertTrue(wv._producer_undeclared(chr(c)), hex(c))
        for c in (0x1c, 0x1d, 0x1e, 0x1f, 0x180e, 0x200b, 0x2060, 0xfeff):
            self.assertEqual(wv._norm_name(chr(c) + "X", "trim-lower"), chr(c) + "x", hex(c))

    def test_every_pair_of_names(self):
        for cn, pn in itertools.product([n for n in NAMES if n[0] is not MISSING], NAMES):
            self.check("independent", cn, pn)

    def test_random_json_values(self):
        """Random JSON values in the name: absent only in the six forms of the sentence, never refused."""
        rnd = random.Random(144)

        def value(d):
            k = rnd.randrange(9 if d < 3 else 6)
            if k < 6:
                return rnd.choice((None, True, False, 0, 1, -3, 0.0, 2.5, "", "a", " ", "unknown"))
            if k < 8:
                return [value(d + 1) for _ in range(rnd.randrange(3))]
            return {rnd.choice("abc") + str(j): value(d + 1) for j in range(rnd.randrange(3))}

        def absent(v):        # the sentence, literally
            if v is None or v is False or v == "" or v == [] or v == {}:
                return True
            if isinstance(v, str):
                return v.strip() in ("", "unknown")
            return isinstance(v, (int, float)) and not isinstance(v, bool) and v == 0
        for _ in range(600):
            v = value(0)
            rep = run(doc("independent", "Example Checker", v))
            self.assertFalse(rep.get("refused"), (v, rep))
            self.assertEqual("PRODUCER_UNDECLARED" in rep["warning_codes"], absent(v), v)
            self.assertEqual(X in rep["problem_codes"], absent(v), v)

    def test_number_forms_in_the_json_text(self):
        """Only the text decides: every spelling of zero, and numbers that are not zero."""
        for tok, zero in (("0", True), ("-0", True), ("0.0", True), ("-0.0", True), ("0e0", True), ("0E+5", True),
                          ("0.000", True), ("1e-400", True), ("5e-324", False), ("1e-7", False), ("-1", False)):
            i = doc("independent", "Example Checker", "__N__")
            r = i["receipt"]["receipt"]
            r["parties"]["producer"]["name"] = json.loads(tok)
            build.sign(i, sign_with=SIGNER)
            r["parties"]["producer"]["name"] = "__N__"
            raw = json.dumps({"inputs": i}).replace('"__N__"', tok).encode()
            rep = wv.run_vector_bytes(raw, None)[0]
            self.assertFalse(rep.get("refused"), (tok, rep))
            self.assertEqual("PRODUCER_UNDECLARED" in rep["warning_codes"], zero, tok)


class GenerativePresenceAndKeys(Base):
    """The presence of parties.* and every kind of stated key, with every class of name."""

    def test_no_producer(self):
        for stated, (ck, ckind) in itertools.product(("independent", "self-checked"), KEYS[1:]):
            if ck is not MISSING:
                self.check(stated, ("Example Checker", "example checker"), (MISSING, ABSENT), ck, ckind, drop=True)

    def test_every_key_with_every_claim(self):
        names = [(MISSING, ABSENT), (None, ABSENT), ("unknown", ABSENT), ("Example Vendor", "example vendor"),
                 (" example checker ", "example checker"), (True, "J:true")]
        for stated, pn, (pk, pkind) in itertools.product(("independent", "self-checked"), names, KEYS):
            self.check(stated, ("Example Checker", "example checker"), pn, SIGNER, "signer", pk, pkind)

    def test_every_pair_of_keys(self):
        checkers = [k for k in KEYS if k[0] is not MISSING]
        for stated, (ck, ckind), (pk, pkind) in itertools.product(("independent", "self-checked"), checkers, KEYS):
            self.check(stated, ("Example Checker", "example checker"), ("Example Vendor", "example vendor"),
                       ck, "none" if ckind == "signer" else ckind, pk, pkind)

    def test_random_sample_of_the_whole_space(self):
        rnd = random.Random(1444)
        checkers = [k for k in KEYS if k[0] is not MISSING]
        for _ in range(1500):
            cn = rnd.choice([n for n in NAMES if n[0] is not MISSING])
            pn = rnd.choice(NAMES)
            ck, ckind = rnd.choice(checkers)
            pk, pkind = rnd.choice(KEYS)
            self.check(rnd.choice(("independent", "self-checked")), cn, pn, ck, "none" if ckind == "signer" else ckind,
                       pk, pkind)


class ClosedByConstruction(unittest.TestCase):
    """T3: nothing but the members step 8 names is relaxed; new keys, wrong types, duplicates and JSON outside the
    grammar in and around parties stay refused."""

    def refused(self, fn):
        i = copy.deepcopy(BASE)
        fn(i["receipt"]["receipt"]["parties"])
        build.sign(i, sign_with=SIGNER)
        rep = run(i)
        self.assertTrue(rep.get("refused"), rep)
        return rep

    def test_new_keys_at_each_level(self):
        rnd = random.Random(14)
        for _ in range(60):
            k = "".join(rnd.choice("abcdefxyz_-") for _ in range(rnd.randrange(1, 9)))
            if k in ("name", "key_id", "producer", "checker"):
                continue
            v = rnd.choice((None, 0, "", [], {}, True))
            self.refused(lambda p: p.__setitem__(k, v))
            self.refused(lambda p: p["producer"].__setitem__(k, v))
            self.refused(lambda p: p["checker"].__setitem__(k, v))
            self.refused(lambda p: p.__setitem__("producer", {k: v}))
            self.refused(lambda p: (p.pop("producer"), p.__setitem__(k, v)))

    def test_near_miss_member_names(self):
        for k in ("Name", "NAME", "name ", "names", "keyid", "key-id", "Key_id"):
            self.refused(lambda p: p.__setitem__("producer", {k: "x"}))
        for k in ("Producer", "PRODUCER", "producer ", "producers"):
            self.refused(lambda p: (p.pop("producer"), p.__setitem__(k, {"name": "x"})))

    def test_wrong_types_stay_step1(self):
        for v in (None, 0, 1, True, False, "", "x", [], [{}]):
            self.assertEqual(self.refused(lambda p: p.__setitem__("producer", v))["reason"], STEP1, v)
        for v in (0, 1, True, False, [], {}, ["k"]):
            self.assertEqual(self.refused(lambda p: p.__setitem__("producer", {"key_id": v}))["reason"], STEP1, v)

    def test_checker_stays_required(self):
        self.refused(lambda p: p.pop("checker"))
        self.refused(lambda p: p["checker"].pop("name"))
        self.refused(lambda p: p.__setitem__("checker", {}))
        self.refused(lambda p: p.__setitem__("checker", None))
        for v in (None, 0, "x", [], True):
            self.refused(lambda p: p.__setitem__("checker", v))

    def test_json_outside_the_grammar_inside_a_name(self):
        i = doc("independent", "Example Checker", "__N__")
        text = json.dumps({"inputs": i})
        for tok, why in (('"\\ud800"', "surrogate"), ('["\\udc00"]', "surrogate"), ("9007199254740993", "range"),
                         ('{"a":1,"a":2}', "duplicate"), ("NaN", "constant"), ("Infinity", "constant"), ("1e999", "inf"),
                         ("[" * 70 + "]" * 70, "depth"), ("01", "grammar"), ("+1", "grammar"), (".5", "grammar"),
                         ("[1,]", "grammar"), ("tRue", "grammar")):
            rep = wv.run_vector_bytes(text.replace('"__N__"', tok).encode(), None)[0]
            self.assertTrue(rep.get("refused"), (tok, why, rep))
        dup = text.replace('"name": "__N__"', '"name": "a", "name": "b"')
        self.assertNotEqual(dup, text)
        self.assertTrue(wv.run_vector_bytes(dup.encode(), None)[0].get("refused"))

    def test_edited_after_signing_is_still_invalid(self):
        for edit in (lambda r: r["parties"].pop("producer"), lambda r: r["parties"]["producer"].pop("name"),
                     lambda r: r["parties"]["producer"].__setitem__("name", 0)):
            i = copy.deepcopy(BASE)
            edit(i["receipt"]["receipt"])
            self.assertIn("SIGNATURE_INVALID", run(i)["problem_codes"])


class Q19Alternatives(unittest.TestCase):
    """Q19: both alternatives, on the same space. A (default): step 8. B (--name-type refuse): the Types rule (77)."""

    def test_a_never_refuses_b_refuses_every_value_outside_string_or_null(self):
        for v, _ in NAMES:
            if v is MISSING:
                continue
            for role in ("producer", "checker"):
                i = doc("independent", v if role == "checker" else "Example Checker",
                        v if role == "producer" else "Example Vendor")
                a = run(i)
                self.assertFalse(a.get("refused"), (role, v))
                self.assertEqual(any("X_NAME_NOT_STRING: receipt.parties.%s.name" % role in x for x in a["notes"]),
                                 not (v is None or isinstance(v, str)), (role, v))
                b = run(i, {"name_type": "refuse"})
                self.assertEqual(bool(b.get("refused")), not (v is None or isinstance(v, str)), (role, v))
                if b.get("refused"):
                    self.assertEqual(b["reason"], STEP1, (role, v))

    def test_vector_77_is_refused_under_both(self):
        f = [x for x in score.vector_files() if os.path.basename(x).startswith("77-")][0]
        for opts in (None, {"name_type": "refuse"}):
            self.assertTrue(wv.run_vector_bytes(open(f, "rb").read(), opts)[0].get("refused"))


class Q23Claim(unittest.TestCase):
    """T5: the rule as read, and the 0.7.0 reading of the same records."""

    def codes(self, *a, **k):
        opts = k.pop("opts", None)
        return run(doc(*a, **k), opts)

    def test_unlisted_and_empty_under_a_self_checked_claim(self):
        for pk in ("", "ghost"):
            rep = self.codes("self-checked", "Example Checker", "Example Vendor", pk=pk)
            self.assertEqual(rep["details"]["independence_derived"], "independent", pk)
            self.assertIn(X, rep["problem_codes"], pk)
            rep = self.codes("self-checked", "Example Checker", "Example Vendor", pk=pk, opts={"key_claim": "always"})
            self.assertEqual(rep["details"]["independence_derived"], "self-checked", pk)
            self.assertNotIn(X, rep["problem_codes"], pk)

    def test_repeated_and_unreadable_under_either_claim(self):
        for pk in ("dup", "noncanon", "dup-noncanon"):
            for stated, inc in (("self-checked", False), ("independent", True)):
                rep = self.codes(stated, "Example Checker", "Example Vendor", pk=pk)
                self.assertEqual(rep["details"]["independence_derived"], "self-checked", (pk, stated))
                self.assertEqual(X in rep["problem_codes"], inc, (pk, stated))
                self.assertIn("KEY_REJECTED", rep["problem_codes"], (pk, stated))


    def test_vector_75_the_repeated_identifier_is_an_entry_that_cannot_be_read(self):
        """Reading Q23. 75 states self-checked and names different parties, with the checker's identifier listed twice;
        counted only under an independent claim, it would derive independent and be inconsistent."""
        f = [x for x in score.vector_files() if os.path.basename(x).startswith("75-")][0]
        raw = open(f, "rb").read()
        rep, cmp_ = wv.run_vector_bytes(raw, None)
        self.assertTrue(cmp_["agree"])
        self.assertEqual((rep["independence"], rep["problem_codes"], rep["details"]["independence_derived"]),
                         ("self-checked", ["KEY_REJECTED"], "self-checked"))
        names = json.loads(raw)["inputs"]["receipt"]["receipt"]["parties"]
        self.assertNotEqual(names["checker"]["name"], names["producer"]["name"])
        # the same record with the claim changed: inconsistent, the key rule holds under both claims
        i = json.loads(raw)["inputs"]
        i["receipt"]["receipt"]["independence"] = "independent"
        rep = run(i)
        self.assertEqual(rep["details"]["independence_derived"], "self-checked")
        self.assertIn(X, rep["problem_codes"])


class SignerInfosForms(unittest.TestCase):
    """Vectors 92, 105 and 107 omit signerInfos; RFC 5652 5.1 requires the field, and an empty SET is the other way of
    holding no signer. Step 9 outcomes are the same for both; only the note and --tokens pkix tell them apart."""

    @classmethod
    def setUpClass(cls):
        cls.root = tp.make_ca("war-verify TEST root 1.4.4")

    def token(self, digest, gen, present):
        return build.b64(tp.unsigned_tsr(tp.tstinfo(digest, gen=gen), with_signerinfos=present))

    def case(self, which, gen, present, anchors=True, opts=None):
        i = build.base(token=False)
        if which == "criteria":
            d = bytes.fromhex(i["receipt"]["receipt"]["criteria"]["sha256"])
            i["criteria_tsr_base64"] = self.token(d, gen, present)
        else:
            i["criteria_tsr_base64"] = None        # the fixture's own criteria token omits the field too
            build.record_token(i, gen="20260601120005Z")
            d = wv.hashlib.sha256(wv.jcs(i["receipt"]["receipt"])).digest()
            i["receipt_tsr_base64"] = self.token(d, gen, present)
        if anchors:
            i["tsa_roots_base64"] = [build.b64(tp.der(self.root[1]))]
        return run(i, opts)

    def test_fixtures_omit_the_field(self):
        seen = 0
        for n in ("92", "105", "107"):
            f = [x for x in score.vector_files() if os.path.basename(x).startswith(n + "-")][0]
            inp = json.load(open(f, encoding="utf-8"))["inputs"]
            for k in ("criteria_tsr_base64", "receipt_tsr_base64"):
                raw = wv.b64_canonical(inp[k])
                if raw is None:                 # the record token of 92: not canonical base64, matches nothing
                    self.assertEqual((n, k), ("92", "receipt_tsr_base64"))
                    continue
                t = wv.parse_tsr(raw, dict(wv.DEFAULT_OPTIONS))
                self.assertIsNone(t["token"]["signer_infos"], (n, k))
                seen += 1
        self.assertEqual(seen, 5)

    def test_both_forms_give_the_same_outcome(self):
        for which, (gen, want) in itertools.product(("criteria", "receipt"), (("20260301000000Z", "no_signer"),
                                                                              ("20261301000000Z", "failed"))):
            a, b = self.case(which, gen, False), self.case(which, gen, True)
            self.assertEqual(a["tsa_signature"][which], want, (which, gen))
            for k in ("tsa_signature", "problem_codes", "warning_codes", "receipt_timestamp",
                      "criteria_committed_before_check"):
                self.assertEqual(a[k], b[k], (which, gen, k))
            self.assertIn("X_TOKEN_NOT_CMS_CONFORMANT", a["extension_codes"])
            self.assertNotIn("X_TOKEN_NOT_CMS_CONFORMANT", b["extension_codes"])

    def test_without_anchors_not_evaluated(self):
        for which, present in itertools.product(("criteria", "receipt"), (False, True)):
            rep = self.case(which, "20260301000000Z", present, anchors=False)
            self.assertEqual(rep["tsa_signature"][which], "not_evaluated", (which, present))

    def test_pkix_refuses_the_omitted_field_only(self):
        o = {"tokens": "pkix"}
        self.assertTrue(self.case("criteria", "20260301000000Z", False, opts=o).get("refused"))
        rep = self.case("criteria", "20260301000000Z", True, opts=o)
        self.assertFalse(rep.get("refused"), rep)
        self.assertEqual(rep["tsa_signature"]["criteria"], "no_signer")


class Comparison(unittest.TestCase):
    def test_note_for_names_only_nfkc_or_folding_make_equal(self):
        for a, b in (("Strasse", "straße"), ("Example  Checker", "example checker"), ("ﬁ", "fi")):
            rep = run(doc("independent", a, b))
            self.assertEqual(rep["details"]["independence_derived"], "independent", (a, b))
            self.assertIn("X_NAMES_EQUAL_AFTER_NORMALIZATION", rep["extension_codes"], (a, b))
            self.assertEqual(run(doc("independent", a, b), {"name_compare": "normalized"})["details"]
                             ["independence_derived"], "self-checked", (a, b))

    def test_name_compare_does_not_move_unknown(self):
        rep = run(doc("independent", "Example Checker", " UNKNOWN "), {"name_compare": "exact"})
        self.assertIn("PRODUCER_UNDECLARED", rep["warning_codes"])

    def test_exact_keeps_bytes(self):
        rep = run(doc("independent", "Example Checker", " example CHECKER"), {"name_compare": "exact"})
        self.assertEqual(rep["details"]["independence_derived"], "independent")
        rep = run(doc("independent", "Example Checker", " example CHECKER"))
        self.assertEqual(rep["details"]["independence_derived"], "self-checked")

    def test_string_and_value_of_the_same_form_differ(self):
        for a, b in (("1", 1), ("true", True), ("[0]", [0])):
            self.assertEqual(run(doc("independent", a, b))["details"]["independence_derived"], "independent", (a, b))
            self.assertEqual(run(doc("independent", b, a))["details"]["independence_derived"], "independent", (a, b))


class Profile143(unittest.TestCase):
    """--profile 1.4.3 keeps each 0.7.0 reading, and each switch moves one rule only."""

    def test_each_reading(self):
        derived = lambda rep: rep["details"]["independence_derived"]                                     # noqa: E731
        self.assertTrue(run(doc("independent", "c", "v", drop_producer=True), P143).get("refused"))
        self.assertTrue(run(doc("independent", "c", MISSING, pk=None), P143).get("refused"))
        for v in (0, False, True, [], {}, 1.5):
            self.assertEqual(run(doc("independent", "c", v), P143).get("reason"), STEP1, v)
            self.assertEqual(run(doc("independent", v, "p"), P143).get("reason"), STEP1, v)
        self.assertEqual(derived(run(doc("independent", "c", None, pk="omega-test-2"), P143)), "independent")
        self.assertEqual(derived(run(doc("independent", None, None, pk="omega-test-2"), P143)), "independent")  # null = no name
        self.assertEqual(derived(run(doc("independent", "c", "unknown"), P143)), "independent")
        self.assertEqual(derived(run(doc("independent", "c", "  "), P143)), "undeclared")
        self.assertEqual(derived(run(doc("independent", "x", " X"), P143)), "independent")
        self.assertEqual(derived(run(doc("independent", "x", "x"), P143)), "self-checked")
        self.assertEqual(derived(run(doc("self-checked", "c", "v", pk="ghost"), P143)), "self-checked")
        self.assertEqual(derived(run(doc("independent", "", "", pk="omega-test-2"), P143)), "self-checked")

    def test_each_switch_alone(self):
        derived = lambda rep: rep["details"]["independence_derived"]                                     # noqa: E731
        self.assertEqual(derived(run(doc("independent", "c", None, pk="omega-test-2"), {"undeclared": "no-key"})),
                         "independent")
        self.assertEqual(derived(run(doc("independent", "c", "unknown"), {"undeclared": "no-key"})), "independent")
        self.assertEqual(derived(run(doc("independent", "c", 1, pk=None), {"undeclared": "no-key"})), "independent")
        self.assertEqual(derived(run(doc("independent", "c", MISSING, pk=None), {"undeclared": "no-key"})), "undeclared")
        self.assertTrue(run(doc("independent", "c", "v", drop_producer=True), {"producer_presence": "required"})
                        .get("refused"))
        self.assertTrue(run(doc("independent", "c", MISSING), {"producer_presence": "required"}).get("refused"))
        self.assertFalse(run(doc("independent", "c", 5), {"producer_presence": "required"}).get("refused"))
        self.assertFalse(run(doc("independent", "c", MISSING), {"name_type": "refuse"}).get("refused"))

    def test_profiles_inherit(self):
        for k, v in P143.items():
            self.assertEqual(wv.PROFILE_1_4_2[k], v, k)
            self.assertEqual(wv.PROFILE_1_2_1[k], v, k)
            self.assertNotEqual(wv.DEFAULT_OPTIONS[k], v, k)
            self.assertIn(v, wv.OPTION_VALUES[k], k)
        self.assertEqual(set(P143), {"name_compare", "undeclared", "producer_presence", "name_type", "key_claim", "rp_input", "rp_repeated", "rp_point", "sig_r", "criteria_unreadable"})


class CLI144(unittest.TestCase):
    def cli(self, *args):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        return subprocess.run([sys.executable, "-B", os.path.join(score.ROOT, "war_verify.py")] + list(args),
                              capture_output=True, text=True, env=env).returncode

    def test_switches(self):
        v109 = score.vector_files("1b81ec9")[-2]
        self.assertEqual(self.cli("--vector", v109), 0)
        self.assertEqual(self.cli("--vector", "--profile", "1.4.3", v109), 3)
        self.assertEqual(self.cli("--vector", "--producer-presence", "required", v109), 3)
        self.assertEqual(self.cli("--vector", "--profile", "1.4.3", "--producer-presence", "optional", v109), 0)
        for flag, value in (("--undeclared", "no-key"), ("--producer-presence", "required"), ("--name-type", "refuse"),
                            ("--key-claim", "always"), ("--name-compare", "exact")):
            self.assertEqual(self.cli(flag, "bogus", v109), 64, flag)
            self.assertEqual(self.cli(flag, value, flag, value, v109), 64, flag)
        self.assertEqual(self.cli("--vector", "--name-compare", "trim-lower", v109), 0)
        err = subprocess.run([sys.executable, "-B", os.path.join(score.ROOT, "war_verify.py"), "--profile", "9.9.9", v109],
                             capture_output=True, text=True).stderr
        for name in wv.PROFILES:                        # the message names every value the switch takes
            self.assertIn(name, err)

    def derived(self, inp, *args):
        """Runs the command line on a record and returns (exit code, derived independence or None if refused)."""
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "v.json")
            with open(f, "w", encoding="utf-8") as fh:
                json.dump({"inputs": inp, "expected": {}}, fh)
            env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
            p = subprocess.run([sys.executable, "-B", os.path.join(score.ROOT, "war_verify.py"), "--vector"] + list(args) + [f],
                               capture_output=True, text=True, env=env)
        rep = json.loads(p.stdout)["report"]
        return None if rep.get("refused") else rep["details"]["independence_derived"]

    def test_each_switch_changes_the_outcome_on_the_command_line(self):
        """A switch that does not exist is exit 64 too: only a change of outcome shows that it is read."""
        for inp, args, default, other in (
                (doc("independent", "c", None, pk="omega-test-2"), ("--undeclared", "no-key"), "undeclared", "independent"),
                (doc("self-checked", "c", "v", pk="ghost"), ("--key-claim", "always"), "independent", "self-checked"),
                (doc("independent", "c", 5), ("--name-type", "refuse"), "independent", None),
                (doc("independent", "c", MISSING), ("--producer-presence", "required"), "undeclared", None),
                (doc("independent", "x", " X "), ("--name-compare", "exact"), "self-checked", "independent")):
            self.assertEqual(self.derived(inp), default, args)
            self.assertEqual(self.derived(inp, *args), other, args)


if __name__ == "__main__":
    unittest.main()
