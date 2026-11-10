"""Profile 1.4.7 (maximusrufus/work-acceptance-record@6f7a075, step 12, vectors 112-115). Oracle: the vectors, and generative
cases whose expectation comes from the sentences of step 12 (README of this project, "Profile 1.4.7 rules", V1-V5) and from
the hand-written labels of the tables below, never from running the verifier: the class of every key is a label, and it is
checked at import by the Edwards arithmetic written in this file, which shares no line with war_verify.py. Positive
control: run on 0.9.0 (20837ca), these tests fail (README, "Tests")."""
import base64
import copy
import itertools
import json
import os
import subprocess
import sys
import tempfile
import unittest

import _paths  # noqa: F401
import score
import test_profile144 as t
import test_profile145 as u
import war_verify as wv

P145 = wv.PROFILE_1_4_5
X = "INDEPENDENCE_INCONSISTENT"
RP = "relying_party_keys"
SET = "6f7a075"
K1, K2, K3 = u.K1, u.K2, u.K3
PRODUCER = "omega-test-2"
POINT, NOT_HELD, NOT_APPLIED = "X_RP_PRODUCER_KEY_POINT_RULE", "X_RP_PRODUCER_KEY_NOT_HELD", "X_RP_KEYS_NOT_APPLIED"
REPEATED, UNUSED = "X_RP_KEY_ID_REPEATED", "X_UNUSED_KEY_REJECTED"
entry, rpdoc = u.entry, u.rpdoc

# ---- arithmetic of this file (RFC 8032 5.1), affine and slow on purpose
FP = 2 ** 255 - 19
FL = 2 ** 252 + 27742317777372353535851937790883648493
FD = -121665 * pow(121666, -1, FP) % FP
ZERO = (0, 1)


def dec(b):
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    sign, y = n >> 255, n & ((1 << 255) - 1)
    if y >= FP:
        return None
    x2 = (y * y - 1) * pow(FD * y * y + 1, -1, FP) % FP
    x = pow(x2, (FP + 3) // 8, FP)
    if (x * x - x2) % FP:
        x = x * pow(2, (FP - 1) // 4, FP) % FP
    if (x * x - x2) % FP or (x == 0 and sign):
        return None
    return (FP - x if x & 1 != sign else x) % FP, y


def enc(p):
    return (p[1] | (p[0] & 1) << 255).to_bytes(32, "little")


def add(a, b):
    k = FD * a[0] * b[0] * a[1] * b[1] % FP
    return ((a[0] * b[1] + a[1] * b[0]) * pow(1 + k, -1, FP) % FP, (a[1] * b[1] + a[0] * b[0]) * pow(1 - k, -1, FP) % FP)


def mul(n, p):
    r = ZERO
    while n:
        if n & 1:
            r = add(r, p)
        p, n = add(p, p), n >> 1
    return r


def small_order(p):
    return mul(8, p) == ZERO


def prime_order(p):
    return not small_order(p) and mul(FL, p) == ZERO


def b64(b):
    return base64.b64encode(b).decode()


# ---- the 8 points of small order, in the list published with the Curve25519 work; (label, hex, order by hand)
TORSION = [("neutral point", "01" + "00" * 31, 1), ("order 2", "ec" + "ff" * 30 + "7f", 2),
           ("order 4, sign 0", "00" * 32, 4), ("order 4, sign 1", "00" * 31 + "80", 4),
           ("order 8, a", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 8),
           ("order 8, b", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", 8),
           ("order 8, c", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", 8),
           ("order 8, d", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", 8)]
for _label, _h, _order in TORSION:
    _p = dec(bytes.fromhex(_h))
    assert _p is not None and mul(_order, _p) == ZERO and (_order == 1 or mul(_order // 2, _p) != ZERO), _label
assert len({h for _l, h, _o in TORSION}) == 8
# the encodings of those points that are not canonical: y >= p, or x = 0 with the sign bit set
NONCANONICAL = [("neutral, sign bit", "01" + "00" * 30 + "80"), ("order 2, sign bit", "ec" + "ff" * 30 + "ff"),
                ("y = p", "ed" + "ff" * 30 + "7f"), ("y = p, sign bit", "ed" + "ff" * 30 + "ff"),
                ("y = p + 1", "ee" + "ff" * 30 + "7f"), ("y = p + 1, sign bit", "ee" + "ff" * 30 + "ff")]
for _label, _h in NONCANONICAL:
    assert dec(bytes.fromhex(_h)) is None, _label
_y = 2
while dec(_y.to_bytes(32, "little")) is not None:
    _y += 1
NO_POINT = _y.to_bytes(32, "little")                # the first y with no x on the curve
PK1, PK2 = dec(base64.b64decode(K1)), dec(base64.b64decode(K2))
assert prime_order(PK1) and prime_order(PK2) and prime_order(dec(base64.b64decode(K3)))
MIXED = [("K2 + " + label, enc(add(PK2, dec(bytes.fromhex(h))))) for label, h, _o in TORSION[1:]]
MIXED_SIGNER = [("K1 + " + label, enc(add(PK1, dec(bytes.fromhex(h))))) for label, h, _o in TORSION[1:]]
for _label, _b in MIXED + MIXED_SIGNER:
    _p = dec(_b)
    assert not small_order(_p) and not prime_order(_p), _label
# (label, base64, one key with the signer by a small-order component)
FAILING = [(lb, b64(bytes.fromhex(h)), False) for lb, h, _o in TORSION] + \
          [(lb, b64(bytes.fromhex(h)), False) for lb, h in NONCANONICAL] + \
          [(lb, b64(b), False) for lb, b in MIXED] + [(lb, b64(b), True) for lb, b in MIXED_SIGNER] + \
          [("no curve point", b64(NO_POINT), False), ("31 bytes", b64(b"\x01" * 31), False), ("33 bytes", b64(b"\x01" * 33), False),
           ("64 bytes", b64(b"\x01" * 64), False), ("the empty string", "", False)]
NEGATED = enc((FP - PK2[0], PK2[1]))                # the sign bit of K2 flipped: another key, of prime order
assert prime_order(dec(NEGATED)) and NEGATED != base64.b64decode(K2)
PASSING = [("K2", K2, False), ("K3", K3, False), ("-K2", b64(NEGATED), False)]
NEUTRAL = b64(bytes.fromhex(TORSION[0][1]))


# (label, entries for the producer's key `pub`, supplied, the list holds pub): U4, V1, V2, by hand
def lists(pub):
    return [("no list", None, False, False),
            ("the key under the producer's identifier", [entry(PRODUCER, pub)], True, True),
            ("the key under another identifier", [entry("unrelated", pub)], True, True),
            ("the key after a clean entry", [entry("x", K1), entry("y", pub)], True, True),
            ("the key twice, same identifier", [entry("a", pub), entry("a", pub)], True, True),
            ("another key only", [entry(PRODUCER, K3 if pub != K3 else K1)], True, False),
            ("empty", [], True, False)]


NAMES = [("Example Vendor", "other"), ("Example Checker", "same"), (None, "undeclared")]


def record(stated, pname, pub, entries, pk=PRODUCER):
    i = u.doc(stated, pname, pk, u.MISSING if entries is None else rpdoc(entries))
    i["keys"]["keys"][1]["public_key_base64"] = pub
    return i


def run(i, opts=None, **kw):
    try:
        return wv.verify(copy.deepcopy(i), dict(opts) if opts else None, **kw)
    except wv.Refusal as e:
        return {"refused": True, "reason": e.reason, "detail": e.detail}


def expected(stated, kind, fails, one_key, supplied, held, rule=True):
    """Steps 8 and 12: (derived, rule applied)."""
    applied = supplied and stated == "independent"
    if kind == "undeclared":
        derived = "undeclared"
    elif kind == "same" or one_key or (applied and (not held or (fails and rule))):
        derived = "self-checked"
    else:
        derived = "independent"
    return derived, applied


def read(f):
    with open(f, "rb") as fh:
        return fh.read()


def nums(rows):
    return [os.path.basename(r["file"]).split("-")[0] for r in rows if not r["agree"]]


class Vectors6f7a075(unittest.TestCase):
    def vector(self, n):
        return wv.strict_json_loads(read(score.vector_files(SET)[n - 1]))["inputs"]

    def test_116_of_116(self):
        rows = score.score(which=SET)
        self.assertEqual(len(rows), 116)                    # 01-115 and the live record
        self.assertEqual(nums(rows), [])
        self.assertEqual((sum(r["fields_agree"] for r in rows), sum(r["fields"] for r in rows)), (1058, 1058))
        self.assertEqual([os.path.basename(f).split("-")[0] for f in score.vector_files(SET)[:-1]],
                         ["%02d" % n for n in range(1, 116)])

    def test_the_default_set_starts_with_6f7a075(self):      # 1.4.8 adds 116-118 (tests/test_profile148.py)
        self.assertEqual(score.vector_files()[:115], score.vector_files(SET)[:115])

    def test_older_sets_unchanged(self):
        for which, n, fields in (("c4b4bd4", 112, 1022), ("1b81ec9", 110, 1004), ("6bb7d0b", 108, 986), ("85a310d", 88, 803),
                                 ("bc5a138", 58, 537), ("48ab8c9", 60, 557), ("1.4.1", 48, 441), ("1.4", 37, 332), ("1.3", 28, 245)):
            rows = score.score(which=which)
            self.assertEqual((len(rows), sum(r["agree"] for r in rows), sum(r["fields_agree"] for r in rows)),
                             (n, n, fields), which)

    def test_profile_1_4_5_disagrees_on_113_114_115(self):
        rows = score.score(dict(P145), which=SET)
        self.assertEqual(nums(rows), ["113", "114", "115"])
        self.assertEqual(sum(r["fields_agree"] for r in rows), 1055)

    def test_each_reading_alone(self):
        for opts, bad in (({"rp_repeated": "no-key"}, ["113"]), ({"rp_point": "off"}, ["114", "115"]),
                          ({"rp_point": "always"}, []), ({"rp_entry_defect": "key-rejected"}, ["112", "114", "115"])):
            self.assertEqual(nums(score.score(opts, which=SET)), bad, opts)

    def test_112(self):
        rep = run(self.vector(112))
        self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([X], "self-checked"))
        self.assertIn(NOT_HELD, rep["extension_codes"])
        self.assertIn(UNUSED, rep["local_blocks"])

    def test_113(self):
        i = self.vector(113)
        rep = run(i)
        self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([], "independent"))
        self.assertEqual(rep["local_blocks"].count(UNUSED), 0)
        self.assertEqual(len([n for n in rep["notes"] if n.startswith(REPEATED + ":")]), 2)
        i[RP]["keys"].reverse()
        self.assertEqual(run(i)["problem_codes"], [])
        del i[RP]["keys"][-1]                               # the checker's entry goes; the two repeated ones stay
        self.assertEqual(run(i)["problem_codes"], [])

    def test_114_and_115(self):
        for n in (114, 115):
            i = self.vector(n)
            rep = run(i)
            self.assertEqual((rep["problem_codes"], rep["warning_codes"], rep["independence"]), ([X], [], "independent"), n)
            self.assertEqual(rep["details"]["independence_derived"], "self-checked", n)
            self.assertIn(POINT, rep["extension_codes"], n)
            self.assertNotIn(NOT_HELD, rep["extension_codes"], n)
            self.assertIn("small-order", [x for x in rep["notes"] if x.startswith(POINT)][0], n)
            self.assertIn(UNUSED, rep["local_blocks"], n)   # the bad entries of both lists: V3, U9
            self.assertEqual(run(i, {"rp_point": "off"})["problem_codes"], [], n)
            del i[RP]
            rep = run(i)                                    # V4: "Without relying_party_keys the rule is not applied"
            self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([], "independent"), n)
            self.assertNotIn(POINT, rep["extension_codes"], n)


class PointRule(unittest.TestCase):
    def table(self):
        for (label, pub, one_key), fails in [(x, True) for x in FAILING] + [(x, False) for x in PASSING]:
            for stated, (pname, kind), (lname, entries, supplied, held) in itertools.product(
                    ("independent", "self-checked"), NAMES, lists(pub)):
                yield label, pub, one_key, fails, stated, pname, kind, lname, entries, supplied, held

    def test_every_class_of_key_in_every_list(self):
        n = 0
        for label, pub, one_key, fails, stated, pname, kind, lname, entries, supplied, held in self.table():
            n += 1
            where = (label, stated, kind, lname)
            i = record(stated, pname, pub, entries)
            rep = run(i)
            self.assertFalse(rep.get("refused"), (where, rep))
            derived, applied = expected(stated, kind, fails, one_key, supplied, held)
            self.assertEqual(rep["details"]["independence_derived"], derived, where)
            self.assertEqual(rep["independence"], stated, where)
            self.assertEqual(X in rep["problem_codes"], derived != stated, where)
            self.assertEqual("KEY_COLLISION" in rep["problem_codes"], one_key, where)
            self.assertNotIn("KEY_REJECTED", rep["problem_codes"], where)       # 114, 115: the key is the signer's only
            self.assertEqual(POINT in rep["extension_codes"], applied and fails, where)
            self.assertEqual(NOT_HELD in rep["extension_codes"], applied and not held, where)
            self.assertEqual(NOT_APPLIED in rep["extension_codes"], supplied and not applied, where)
            self.assertEqual(UNUSED in rep["local_blocks"], fails, where)
            self.assertNotIn(POINT, rep["local_blocks"], where)                 # a note: the block of the key is UNUSED
            self.assertEqual(rep["signature_valid"], True, where)
            self.assertEqual("PRODUCER_UNDECLARED" in rep["warning_codes"], kind == "undeclared", where)
        self.assertEqual(n, (len(FAILING) + len(PASSING)) * 2 * len(NAMES) * 7)

    def test_rule_off_is_the_same_table_without_v3(self):
        for label, pub, one_key, fails, stated, pname, kind, lname, entries, supplied, held in self.table():
            if kind != "other":
                continue
            where = (label, stated, lname)
            rep = run(record(stated, pname, pub, entries), {"rp_point": "off"})
            self.assertEqual(rep["details"]["independence_derived"],
                             expected(stated, kind, fails, one_key, supplied, held, rule=False)[0], where)
            self.assertNotIn(POINT, rep["extension_codes"], where)

    def test_the_note_names_the_class(self):
        for pub, words in ((NEUTRAL, "small-order"), (b64(MIXED[0][1]), "mixed-order"), (b64(NO_POINT), "not a curve point"),
                           (b64(b"\x01" * 31), "not 32 bytes"), (b64(bytes.fromhex(NONCANONICAL[2][1])), "y >= p"),
                           (b64(bytes.fromhex(NONCANONICAL[0][1])), "sign bit")):
            rep = run(record("independent", "Example Vendor", pub, [entry("p", pub)]))
            note = [n for n in rep["notes"] if n.startswith(POINT)]
            self.assertEqual(len(note), 1, words)
            self.assertIn(words, note[0])
            self.assertIn(repr(PRODUCER), note[0])

    def test_the_key_read_is_the_producers_not_the_lists(self):
        # a small-order entry in the list that is not the producer's key changes nothing in the rule (U9)
        rep = run(record("independent", "Example Vendor", K2, [entry("n", NEUTRAL), entry("p", K2)]))
        self.assertEqual((rep["problem_codes"], rep["extension_codes"].count(POINT)), ([], 0))
        self.assertIn(UNUSED, rep["local_blocks"])
        # the checker's key is not read by this rule
        i = record("independent", "Example Vendor", K2, [entry("p", K2)])
        rep = run(i, keys_override=dict(i["keys"], keys=i["keys"]["keys"] + [entry("spare", NEUTRAL)]))
        self.assertEqual(rep["problem_codes"], [])

    def test_keys_replaced_the_rule_reads_the_list_in_use(self):        # U7
        i = record("independent", "Example Vendor", K2, [entry("p", NEUTRAL)])
        kf = copy.deepcopy(i["keys"])
        kf["keys"][1]["public_key_base64"] = NEUTRAL
        rep = run(i, keys_override=kf)
        self.assertEqual((rep["problem_codes"], POINT in rep["extension_codes"]), ([X], True))
        rep = run(i, rp_override=rpdoc([entry("p", K2)]))
        self.assertEqual(rep["problem_codes"], [])
        rep = run(record("independent", "Example Vendor", NEUTRAL, []), rp_override=rpdoc([entry("p", NEUTRAL)]))
        self.assertEqual((rep["problem_codes"], POINT in rep["extension_codes"]), ([X], True))

    def test_outside_the_conditions_of_u3(self):                        # V4
        for pk in (u.MISSING, None):
            i = record("independent", "Example Vendor", NEUTRAL, [entry("p", NEUTRAL)], pk=pk)
            rep = run(i)
            self.assertNotIn(POINT, rep["extension_codes"], pk)
            self.assertIn(NOT_APPLIED, rep["extension_codes"], pk)
            self.assertEqual(rep["problem_codes"], [], pk)
        for kid in ("", "ghost"):                                       # T5: no key to read
            rep = run(record("independent", "Example Vendor", K2, [entry("p", K2)], pk=kid))
            self.assertEqual((rep["problem_codes"], POINT in rep["extension_codes"]), ([X], False), kid)
        rep = run(record("independent", "Example Vendor", NEUTRAL, [entry("p", NEUTRAL)]), {"independence_rule": "stated-independent"})
        self.assertEqual((rep["problem_codes"], POINT in rep["extension_codes"]), ([], False))

    def test_q31_always(self):
        opts = {"rp_point": "always"}
        rep = run(record("independent", "Example Vendor", NEUTRAL, None), opts)         # no list
        self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([X], "self-checked"))
        self.assertIn(POINT, rep["extension_codes"])
        rep = run(record("self-checked", "Example Vendor", NEUTRAL, [entry("p", NEUTRAL)]), opts)   # the claim
        self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([], "self-checked"))
        rep = run(record("self-checked", "Example Vendor", NEUTRAL, [entry("p", NEUTRAL)]))
        self.assertEqual((rep["problem_codes"], rep["details"]["independence_derived"]), ([X], "independent"))
        rep = run(record("independent", "Example Vendor", K2, None), opts)              # a prime-order key
        self.assertEqual(rep["problem_codes"], [])
        rep = run(record("independent", "Example Vendor", NEUTRAL, None), dict(opts, independence_rule="stated-independent"))
        self.assertEqual((rep["problem_codes"], POINT in rep["extension_codes"]), ([], False))

    def test_q28_lookup_reads_the_rule_too(self):
        i = u.doc("independent", "Example Vendor", "only-in-the-list", rpdoc([entry("only-in-the-list", NEUTRAL)]))
        rep = run(i, {"rp_lookup": "both"})
        self.assertEqual((rep["problem_codes"], POINT in rep["extension_codes"]), ([X], True))
        i = u.doc("independent", "Example Vendor", "only-in-the-list", rpdoc([entry("only-in-the-list", K2)]))
        self.assertEqual(run(i, {"rp_lookup": "both"})["problem_codes"], [])

    def test_q29_undeclared_comes_first(self):
        rep = run(record("independent", None, NEUTRAL, [entry("p", NEUTRAL)]))
        self.assertEqual(rep["details"]["independence_derived"], "undeclared")
        self.assertEqual((rep["problem_codes"], rep["warning_codes"]), ([X], ["PRODUCER_UNDECLARED"]))


class RepeatedKeyId(unittest.TestCase):
    def test_every_position_and_order(self):
        n = 0
        ids = ("a", PRODUCER, u.SIGNER)
        for kid, size in itertools.product(ids, (2, 3, 4)):
            for pubs in itertools.product((K2, K3, K1), repeat=size):
                entries = [entry(kid, p) for p in pubs]
                n += 1
                where = (kid, pubs)
                held = K2 in pubs                           # by hand: matched by key, whatever the position
                rep = run(record("independent", "Example Vendor", K2, entries))
                self.assertEqual(rep["problem_codes"], [] if held else [X], where)
                self.assertEqual(NOT_HELD in rep["extension_codes"], not held, where)
                self.assertNotIn(UNUSED, rep["local_blocks"], where)
                self.assertEqual(len([x for x in rep["notes"] if x.startswith(REPEATED + ":")]), size, where)
                old = run(record("independent", "Example Vendor", K2, entries), {"rp_repeated": "no-key"})
                self.assertEqual(old["problem_codes"], [X], where)
                self.assertIn(UNUSED, old["local_blocks"], where)
                self.assertNotIn(REPEATED, old["extension_codes"], where)
        self.assertEqual(n, 3 * (3 ** 2 + 3 ** 3 + 3 ** 4))

    def test_some_repeated_some_not(self):
        for entries, n_rep, held in (([entry("a", K3), entry("b", K2), entry("a", K3)], 2, True),
                                     ([entry("a", K2), entry("b", K3), entry("a", K3)], 2, True),
                                     ([entry("a", K3), entry("b", K3), entry("a", K1)], 2, False),
                                     ([entry("a", K2), entry("b", K2)], 0, True)):
            rep = run(record("independent", "Example Vendor", K2, entries))
            self.assertEqual((rep["problem_codes"], rep["extension_codes"].count(REPEATED) and
                              len([x for x in rep["notes"] if x.startswith(REPEATED + ":")])), ([] if held else [X], n_rep), entries)

    def test_a_defect_of_its_own_stays_a_defect(self):
        nc = u.K2_NONCANON
        rep = run(record("independent", "Example Vendor", K2, [entry("a", nc), entry("a", K2)]))
        self.assertEqual(rep["problem_codes"], [])
        self.assertIn(UNUSED, rep["local_blocks"])
        rep = run(record("independent", "Example Vendor", K2, [entry("a", nc), entry("a", nc)]))
        self.assertEqual(rep["problem_codes"], [X])
        self.assertEqual(len([x for x in rep["notes"] if x.startswith(REPEATED)]), 2)      # V1: it names every such entry
        rep = run(record("independent", "Example Vendor", K2, [entry("a", NEUTRAL), entry("a", K2)]))
        self.assertEqual(rep["problem_codes"], [])
        self.assertIn(UNUSED, rep["local_blocks"])
        self.assertTrue([x for x in rep["notes"] if x.startswith(UNUSED) and "small-order" in x])
        rep = run(record("independent", "Example Vendor", K2, [entry("a", K3), entry("a", K2)]), {"rp_entry_defect": "key-rejected"})
        self.assertEqual(rep["problem_codes"], [])          # V1: no defect, so the switch has nothing to add
        rep = run(record("independent", "Example Vendor", K2, [entry("a", NEUTRAL), entry("a", K2)]), {"rp_entry_defect": "key-rejected"})
        self.assertEqual(rep["problem_codes"], ["KEY_REJECTED"])

    def test_the_key_file_keeps_its_rule(self):             # V1: 75, 79, T5
        i = u.doc("independent", "Example Vendor", PRODUCER, rpdoc([entry("p", K2)]))
        i["keys"]["keys"].append(entry(PRODUCER, K2))
        rep = run(i)
        self.assertEqual(rep["details"]["independence_derived"], "self-checked")
        self.assertIn("KEY_REJECTED", rep["problem_codes"])

    def test_lookup_by_identifier_needs_one_key(self):      # Q28: a key_id, so a repeated one names none
        i = u.doc("independent", "Example Vendor", "only-in-the-list",
                  rpdoc([entry("only-in-the-list", K2), entry("only-in-the-list", K2)]))
        self.assertEqual(run(i, {"rp_lookup": "both"})["problem_codes"], [X])


class Profiles(unittest.TestCase):
    def test_the_values(self):
        self.assertEqual(P145, dict(wv.PROFILE_1_4_7, rp_repeated="no-key", rp_point="off"))
        self.assertEqual((wv.DEFAULT_OPTIONS["rp_repeated"], wv.DEFAULT_OPTIONS["rp_point"]), ("bytes", "step12"))
        for name, prof in wv.PROFILES.items():
            if name not in ("1.4.7", "1.4.8"):
                self.assertEqual({k: prof[k] for k in P145}, P145, name)
        self.assertEqual(sorted(wv.PROFILES), ["1.2.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.7", "1.4.8"])
        self.assertEqual(wv.OPTION_VALUES["rp_point"], ("step12", "off", "always"))
        self.assertEqual(wv.OPTION_VALUES["rp_repeated"], ("bytes", "no-key"))

    def test_profile_1_4_5_is_the_table_of_0_9_0(self):
        for pub, one_key in ((NEUTRAL, False), (b64(MIXED[0][1]), False), (K2, False)):
            i = record("independent", "Example Vendor", pub, [entry("p", pub)])
            rep = run(i, P145)
            self.assertEqual(rep["problem_codes"], [], pub)
            self.assertNotIn(POINT, rep["extension_codes"], pub)
        i = record("independent", "Example Vendor", K2, [entry("a", K2), entry("a", K2)])
        rep = run(i, P145)
        self.assertEqual(rep["problem_codes"], [X])
        self.assertIn(UNUSED, rep["local_blocks"])

    def test_q27_the_open_case_keeps_the_switch(self):
        i = record("independent", "Example Vendor", K2, [entry("n", NEUTRAL), entry("p", K2)])
        self.assertEqual(run(i)["problem_codes"], [])
        self.assertEqual(run(i, {"rp_entry_defect": "key-rejected"})["problem_codes"], ["KEY_REJECTED"])
        i = record("independent", "Example Vendor", K2, [entry("a", u.K2_NONCANON), entry("p", K2)])
        self.assertEqual(run(i, {"rp_entry_defect": "key-rejected"})["problem_codes"], ["KEY_REJECTED"])


class CommandLine(unittest.TestCase):
    def run_cli(self, *args):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        p = subprocess.run([sys.executable, "-B", os.path.join(score.ROOT, "war_verify.py")] + list(args),
                           capture_output=True, text=True, env=env)
        return p.returncode, p.stdout, p.stderr

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.files = score.vector_files(SET)

    def write(self, name, obj):
        f = os.path.join(self.tmp.name, name)
        with open(f, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return f

    def test_vectors_agree_on_the_command_line(self):
        for n in (112, 113, 114, 115):
            self.assertEqual(self.run_cli("--vector", self.files[n - 1])[0], 0, n)
        self.assertEqual(self.run_cli("--vector", "--profile", "1.4.5", self.files[112])[0], 3)
        self.assertEqual(self.run_cli("--vector", "--rp-repeated", "no-key", self.files[112])[0], 3)
        self.assertEqual(self.run_cli("--vector", "--rp-point", "off", self.files[113])[0], 3)
        self.assertEqual(self.run_cli("--vector", "--rp-point", "always", self.files[113])[0], 0)
        self.assertEqual(self.run_cli("--vector", "--rp-entry-defect", "key-rejected", self.files[111])[0], 3)
        self.assertEqual(self.run_cli("--vector", "--profile", "1.4.5", "--rp-point", "step12", self.files[113])[0], 0)

    def test_usage_errors(self):
        f = self.files[113]
        for args in (("--rp-point", "bogus"), ("--rp-point", ""), ("--rp-point", "off", "--rp-point", "off"),
                     ("--rp-repeated", "bogus"), ("--profile", "1.4.6"), ("--profile", "9.9.9"),
                     ("--profile", "1.4.5", "--profile", "1.4.4")):
            self.assertEqual(self.run_cli(*args, f)[0], 64, args)
        self.assertEqual(self.run_cli("--rp-point")[0], 64)
        for args in (("--rp-point=off",), ("--rp-poin", "off"), ("--RP-POINT", "off"), ("--profile=1.4.5",)):
            self.assertEqual(self.run_cli(*args, f)[0], 64, args)
        self.assertIn("1.4.5, 1.4.4", self.run_cli("--profile", "1.4.6", f)[2])

    def test_the_list_from_a_file_and_the_exit(self):
        i = wv.strict_json_loads(read(self.files[112]))["inputs"]
        lst = self.write("rp.json", i.pop(RP))
        f = self.write("r.json", i)
        rc, out, _ = self.run_cli("--relying-party-keys", lst, f)
        rep = json.loads(out)["report"]
        self.assertEqual((rep["problem_codes"], rep["accepted_as_stated"]), ([], True))
        self.assertNotIn(UNUSED, rep["local_blocks"])       # V1: the repeated key_id adds no block
        self.assertIn(REPEATED, rep["extension_codes"])
        rep = json.loads(self.run_cli("--profile", "1.4.5", "--relying-party-keys", lst, f)[1])["report"]
        self.assertIn(UNUSED, rep["local_blocks"])

    def test_exit_0_with_a_repeated_key_id(self):           # the live record and a list that repeats a key_id it does not use
        live = os.path.join(score.ROOT, "fonti", "issuer_274159c")
        base = ("--keys", os.path.join(live, "checker-keys-live.json"), "--tokens", "pkix", "--tsa-roots",
                os.path.join(score.ROOT, "roots", "freetsa_cacert.pem"))
        lst = self.write("rp.json", rpdoc([entry("a", K2), entry("a", K3)]))
        rec = os.path.join(live, "selftest-pass.json")
        self.assertEqual(self.run_cli(*base, "--relying-party-keys", lst, rec)[0], 0)
        self.assertEqual(self.run_cli(*base, "--profile", "1.4.5", "--relying-party-keys", lst, rec)[0], 1)

    def test_usage_text_names_every_flag(self):
        rc, out, _ = self.run_cli("--help")
        self.assertEqual(rc, 0)
        for words in ("--rp-point step12|off|always", "(default step12)", "--rp-repeated bytes|no-key", "(default bytes)",
                      "  --profile 1.4.5              the readings 0.9.0 gave", "profile 1.4.7"):
            self.assertIn(words, out)


if __name__ == "__main__":
    unittest.main()
