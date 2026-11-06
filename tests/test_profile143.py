"""Profile 1.4.3 (maximusrufus/work-acceptance-record@6bb7d0b, README step 11 "Profile 1.4.3 clarifications", vectors
91-107). Oracle: the 6bb7d0b vectors, and generative cases near each rule's edges whose expectation is written from
the rule's sentence (README of this project, "Profile 1.4.3 rules", S1-S8), never from running the verifier.
Positive control: run on 0.6.0 (c51ff40), these tests fail (README, "Tests")."""
import base64
import copy
import itertools
import os
import random
import unittest

import _paths  # noqa: F401
import build
import score
import testpki as tp
import war_verify as wv
from test_profile142 import GEN_BAD, entry, trailing_bit_variants

UNVERIFIED = "CRITERIA_COMMITMENT_UNVERIFIED"
STEP1 = wv.STEP1_REASON
P142 = wv.PROFILE_1_4_2
P143 = wv.PROFILE_1_4_3


def run(inp, opts=None):
    try:
        return wv.verify(copy.deepcopy(inp), dict(opts) if opts else None)
    except wv.Refusal as e:
        return {"refused": True, "reason": e.reason, "detail": e.detail}


def fixture(token=False):
    return build.base(token=token)


def edit(inp, fn, resign=True):
    fn(inp["receipt"]["receipt"])
    if resign:
        build.sign(inp)
    return inp


def short(rows):
    return [os.path.basename(r["file"]).split("-")[0] for r in rows if not r["agree"]]


class Vectors6bb7d0b(unittest.TestCase):
    def test_108_of_108(self):
        rows = score.score(which="6bb7d0b")
        self.assertEqual(len(rows), 108)                    # 01-107 and the live record
        self.assertEqual(short(rows), [])
        self.assertEqual(sum(r["fields"] for r in rows), 986)
        self.assertEqual([os.path.basename(f).split("-")[0] for f in score.vector_files("6bb7d0b")[:-1]],
                         ["%02d" % n for n in range(1, 108)])

    def test_profile_1_4_2_differs_only_where_the_readings_differ(self):
        # S1 (91), S3 (94), S4 (95), S2 (104, 106): the 0.6.0 readings; 105 and 107 (S7) agree under both
        self.assertEqual(short(score.score(dict(P142), which="6bb7d0b")), ["91", "94", "95", "104", "106"])

    def test_positive_control_corrupted_expectation_is_caught(self):
        def corrupt(doc):
            d = copy.deepcopy(doc)
            d["expected"]["problem_codes"] = list(d["expected"].get("problem_codes", [])) + ["KEY_COLLISION"]
            return wv.run_vector(d)
        files = score.vector_files()[90:107]
        self.assertEqual(sum(r["agree"] for r in score.score(verify_fn=corrupt, files=files)), 0)


class S1KeyScope(unittest.TestCase):
    """S1 (91, 79, 69): the canonical-base64 key rule applies to the signer's entry and entries a stated party names."""

    def setUp(self):
        self.k1, self.k2 = build.pub_b64("omega-test-1"), build.pub_b64("omega-test-2")

    def with_keys(self, keys, producer_kid=None, independence="independent"):
        i = fixture()
        i["keys"]["keys"] = keys

        def f(r):
            r["parties"]["producer"]["key_id"] = producer_kid
            r["independence"] = independence
        return edit(i, f)

    def bads(self, s):
        return trailing_bit_variants(s) + [s.rstrip("="), s[:10] + " " + s[10:], s[:-2] + "!=", s + "\n",
                                           s.replace("+", "-").replace("/", "_"), "=" + s]
        # "" is canonical base64 of no bytes: the point rule (step 2, signer only) decides it, not S1 (Q16)

    def test_unread_entry_in_every_position(self):
        for bad, pos in itertools.product(self.bads(self.k2), range(3)):
            keys = [entry("omega-test-1", self.k1), entry("omega-test-2", self.k2)]
            keys.insert(pos, entry("x", bad))
            rep = run(self.with_keys(keys, "omega-test-2"))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"], rep["warning_codes"]), (True, [], []),
                             (bad, pos))
            self.assertIn("X_UNUSED_KEY_REJECTED", rep["extension_codes"])      # a local block, never silent
            self.assertIn("X_UNUSED_KEY_REJECTED", rep["local_blocks"])
            rep = run(self.with_keys(keys, "omega-test-2"), P142)              # 0.6.0 reading (Q1)
            self.assertEqual(rep["problem_codes"], ["KEY_REJECTED"], (bad, pos))

    def test_used_entries_still_rejected(self):
        for bad in self.bads(self.k2):
            # the producer names it (69)
            rep = run(self.with_keys([entry("omega-test-1", self.k1), entry("p", bad)], "p", "self-checked"))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (True, ["KEY_REJECTED"]), bad)
            # the checker names it (the checker is not the signer here)
            i = self.with_keys([entry("omega-test-1", self.k1), entry("c", bad), entry("omega-test-2", self.k2)],
                               "omega-test-2", "self-checked")
            rep = run(edit(i, lambda r: r["parties"]["checker"].__setitem__("key_id", "c")))
            self.assertIn("KEY_REJECTED", rep["problem_codes"], bad)
        for bad in self.bads(self.k1):
            # the signer's: no signature check
            # (the checker names it too, so independence is derived self-checked: R6, 69)
            rep = run(self.with_keys([entry("omega-test-1", bad), entry("omega-test-2", self.k2)], None, "self-checked"))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (False, ["KEY_REJECTED"]), bad)
            # the signer's, named by no stated party: still read (it signed), never in the unread-entry note
            i = self.with_keys([entry("omega-test-1", bad), entry("omega-test-2", self.k2)], "omega-test-2",
                               "self-checked")
            rep = run(edit(i, lambda r: r["parties"]["checker"].__setitem__("key_id", "omega-test-2")))
            self.assertFalse(rep["signature_valid"], bad)
            self.assertIn("KEY_REJECTED", rep["problem_codes"], bad)
            self.assertNotIn("X_UNUSED_KEY_REJECTED", rep["extension_codes"], bad)

    def test_repeated_identifier_unread_is_still_rejected(self):
        for pos in range(4):
            keys = [entry("omega-test-1", self.k1), entry("omega-test-2", self.k2), entry("x", self.k2)]
            keys.insert(pos, entry("x", self.k1))
            rep = run(self.with_keys(keys, "omega-test-2"))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (True, ["KEY_REJECTED"]), pos)
        # the first entry under the repeated identifier not canonical base64: still KEY_REJECTED (79), and the
        # note on unread non-canonical entries (S1, 91) does not list it as "no KEY_REJECTED"
        for bad in self.bads(self.k2):
            keys = [entry("omega-test-1", self.k1), entry("omega-test-2", self.k2), entry("x", bad), entry("x", self.k2)]
            rep = run(self.with_keys(keys, "omega-test-2"))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (True, ["KEY_REJECTED"]), bad)
            self.assertNotIn("X_UNUSED_KEY_REJECTED", rep["extension_codes"], bad)
            self.assertFalse([n for n in rep["notes"] if n.startswith("X_UNUSED_KEY_REJECTED")], bad)


class S2EmptyKeyId(unittest.TestCase):
    """S2 (104, 106, 103): an empty signed or envelope key_id names no key: SIGNATURE_INVALID, not a refusal."""

    def case(self, signed, envelope, checker, producer="omega-test-2", independence="independent", opts=None):
        i = fixture()

        def f(r):
            r["key_id"] = signed
            r["parties"]["checker"]["key_id"] = checker
            r["parties"]["producer"]["key_id"] = producer
            r["independence"] = independence
        edit(i, f, resign=False)
        i["receipt"]["signature"]["key_id"] = envelope
        build.sign(i, sign_with="omega-test-1")
        return run(i, opts)

    def test_table(self):
        K = "omega-test-1"
        # (signed, envelope, checker, independence) -> problem codes, written from S2
        table = [
            (("", "", K, "independent"), ["CHECKER_NOT_SIGNER", "SIGNATURE_INVALID"]),                       # 104
            (("", K, K, "independent"), ["CHECKER_NOT_SIGNER", "SIGNATURE_INVALID"]),
            ((K, "", K, "independent"), ["SIGNATURE_INVALID"]),
            (("", "", "", "independent"), ["INDEPENDENCE_INCONSISTENT", "SIGNATURE_INVALID"]),               # 106
            (("", "", "", "self-checked"), ["SIGNATURE_INVALID"]),
            (("", "", None, "independent"), ["CHECKER_NOT_SIGNER", "SIGNATURE_INVALID"]),
            ((K, K, "", "independent"), ["CHECKER_NOT_SIGNER", "INDEPENDENCE_INCONSISTENT"]),               # 103
            ((K, K, "", "self-checked"), ["CHECKER_NOT_SIGNER"]),
        ]
        for (signed, envelope, checker, ind), want in table:
            rep = self.case(signed, envelope, checker, independence=ind, opts={"key_claim": "always"})   # README T5
            self.assertFalse(rep.get("refused"), (signed, envelope, checker, rep))
            self.assertEqual(sorted(rep["problem_codes"]), want, (signed, envelope, checker, ind))
            self.assertIs(rep["signature_valid"], signed == K and envelope == K, (signed, envelope))
            if "" in (signed, envelope):
                self.assertIn("X_KEY_ID_EMPTY", rep["extension_codes"])

    def test_empty_identifiers_never_collide(self):
        for signed, checker in (("", ""), ("omega-test-1", ""), ("", "omega-test-1")):
            for ind in ("independent", "self-checked"):
                rep = self.case(signed, signed, checker, producer="", independence=ind)
                self.assertNotIn("KEY_COLLISION", rep["problem_codes"], (signed, checker))
                self.assertIn("INDEPENDENCE_INCONSISTENT", rep["problem_codes"])          # README T5, both claims
                rep = self.case(signed, signed, checker, producer="", independence=ind, opts={"key_claim": "always"})
                self.assertEqual("INDEPENDENCE_INCONSISTENT" in rep["problem_codes"], ind == "independent")
        # control: the same non-empty identifier for producer and checker is still a collision
        rep = self.case("omega-test-1", "omega-test-1", "omega-test-1", producer="omega-test-1")
        self.assertIn("KEY_COLLISION", rep["problem_codes"])

    def test_profile_1_4_2_keeps_the_refusal_and_the_comparison(self):
        for signed, envelope in (("", "omega-test-1"), ("omega-test-1", "")):
            rep = self.case(signed, envelope, "omega-test-1", opts=P142)
            self.assertEqual(rep.get("refused"), True, (signed, envelope))
        rep = self.case("omega-test-1", "omega-test-1", "", producer="", opts=P142)
        self.assertIn("KEY_COLLISION", rep["problem_codes"])

    def test_wrong_type_is_still_step1(self):
        for v in (None, 0, [], {}):
            rep = self.case(v, "omega-test-1", "omega-test-1")
            self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1), v)


def malformed_digests(h, n=200, seed=1403):
    """Strings that are not 64 hexadecimal digits: every length 0-70 of hex, other characters at random positions,
    non-ASCII digits, blanks and line ends. Deterministic (seeded)."""
    rnd = random.Random(seed)
    out = ["", h[:63], h + "0", h[:-1] + "g", h[:-1] + "\n", h + "\n", " " + h[1:], h[:32] + " " + h[33:],
           "０" * 64, "٠" * 64, h[:-1] + "١", h.upper()[:-1] + "G", "0x" + h[2:], h[:-2] + "==",
           "é" * 64]
    out += ["".join(rnd.choice("0123456789abcdef") for _ in range(k)) for k in range(0, 71) if k != 64]
    pool = [chr(c) for c in range(0x20, 0x7f) if chr(c) not in "0123456789abcdefABCDEF"] + ["٣", "ａ", "\t"]
    for _ in range(n):
        p = rnd.randrange(64)
        out.append(h[:p] + rnd.choice(pool) + h[p + 1:])
    return list(dict.fromkeys(out))


class S3MalformedDigests(unittest.TestCase):
    """S3 (94): a digest string that is not 64 hex digits matches nothing; not a refusal."""

    def test_criteria_digest_with_document_and_token(self):
        i = fixture()
        self.assertIn("criteria_file_base64", i)                       # vector 01's criteria document and token
        h = i["receipt"]["receipt"]["criteria"]["sha256"]
        for v in malformed_digests(h):
            rep = run(edit(copy.deepcopy(i), lambda r: r["criteria"].__setitem__("sha256", v)))
            self.assertFalse(rep.get("refused"), (v, rep))
            self.assertEqual((rep["criteria_hash"], sorted(rep["problem_codes"]), rep["warning_codes"]),
                             ("mismatch", ["CRITERIA_HASH_MISMATCH", "CRITERIA_TIMESTAMP_MISMATCH"], [UNVERIFIED]),
                             repr(v))
            self.assertIn("X_DIGEST_MALFORMED", rep["extension_codes"])
            self.assertNotIn("X_DIGEST_NOT_LOWERCASE", rep["extension_codes"], repr(v))   # one note per digest
            rep = run(edit(copy.deepcopy(i), lambda r: r["criteria"].__setitem__("sha256", v)), P142)
            self.assertTrue(rep.get("refused"), repr(v))                   # 0.6.0 reading (Q4)

    def test_criteria_digest_without_document_or_token(self):
        i = fixture()
        i.pop("criteria_file_base64")
        i["criteria_tsr_base64"] = None
        rep = run(edit(i, lambda r: r["criteria"].__setitem__("sha256", "0" * 63)))
        self.assertEqual((rep["criteria_hash"], rep["problem_codes"], rep["warning_codes"]),
                         ("not-supplied", [], [UNVERIFIED]))

    def test_file_digests(self):
        for name in ("remediated", "original"):
            for v in malformed_digests("ab" * 32, n=30):
                i = fixture()

                def f(r):
                    r["files"].setdefault(name, dict(r["files"]["remediated"]))["sha256"] = v
                rep = run(edit(i, f))
                self.assertFalse(rep.get("refused"), (name, v, rep))
                self.assertEqual(rep["problem_codes"], [], (name, v))
                i["delivered_file_base64" if name == "remediated" else "original_file_base64"] = build.b64(b"x")
                rep = run(i)
                self.assertEqual(rep["files"][name], "mismatch", (name, v))

    def test_wrong_type_is_still_step1(self):
        for v in (None, 1, ["a" * 64], {"h": "a" * 64}, True):
            rep = run(edit(fixture(), lambda r: r["criteria"].__setitem__("sha256", v)))
            self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1), v)


class S4StatedFraction(unittest.TestCase):
    """S4 (95, 96): one to three ASCII fraction digits in committed_at and issued_utc."""

    def rep(self, member, value, opts=None):
        i = fixture()
        i["criteria_tsr_base64"] = None

        def f(r):
            if member == "issued_utc":
                r["issued_utc"] = value
            else:
                r["criteria"]["committed_at"] = value
        return run(edit(i, f), opts)

    def test_every_digit_count(self):
        for member, stem in (("issued_utc", "2026-06-01T12:00:00"), ("committed_at", "2026-03-01T00:00:00")):
            for k in range(0, 11):
                for digits in ("".join(random.Random(k * 7 + j).choice("0123456789") for _ in range(k))
                               for j in range(3)):
                    v = stem + "." + digits + "Z"
                    rep = self.rep(member, v)
                    readable = 1 <= k <= 3
                    self.assertEqual("RECEIPT_TIME_UNREADABLE" in rep["problem_codes"], not readable, (member, v))
                    rep = self.rep(member, v, P142)
                    self.assertEqual("RECEIPT_TIME_UNREADABLE" in rep["problem_codes"], k != 3, (member, v))

    def test_non_ascii_digits_and_second_60(self):
        for v in ("2026-06-01T12:00:00.٥Z", "2026-06-01T12:00:00.５Z", "2026-06-01T12:00:0٠Z",
                  "2026-06-01T12:00:00.5 Z", "2026-06-01T12:00:00.+5Z", "2026-06-01T12:00:00.-5Z",
                  "2026-06-30T23:59:60Z", "2026-06-30T23:59:60.5Z"):
            self.assertEqual(self.rep("issued_utc", v)["problem_codes"], ["RECEIPT_TIME_UNREADABLE"], repr(v))


class S5TimeAgreement(unittest.TestCase):
    """S5 (99): committed_at agrees with genTime only without a fraction and equal to the second."""

    def case(self, committed_at, gen, opts=None):
        i = fixture()
        edit(i, lambda r: r["criteria"].__setitem__("committed_at", committed_at))
        build.criteria_token(i, gen=gen)
        return run(i, opts)

    def test_table(self):
        rows = [  # committed_at, genTime, CRITERIA_TIME_MISMATCH under 1.4.3, under 0.6.0 (truncate)
            ("2026-03-01T00:00:00Z", "20260301000000Z", False, False),
            ("2026-03-01T00:00:00Z", "20260301000000.5Z", False, False),           # 99
            ("2026-03-01T00:00:00Z", "20260301000000.999Z", False, False),
            ("2026-03-01T00:00:00Z", "20260301000001Z", True, True),
            ("2026-03-01T00:00:01Z", "20260301000000.999Z", True, True),
            ("2026-03-01T00:00:00.500Z", "20260301000000.5Z", True, False),         # a fraction always disagrees
            ("2026-03-01T00:00:00.000Z", "20260301000000Z", True, False),
            ("2026-03-01T00:00:00.5Z", "20260301000000.5Z", True, True),            # 0.6.0: unreadable (Q5)
            ("2026-03-01T00:00:00.12Z", "20260301000000.12Z", True, True),
            ("2026-03-01T00:00:00.123Z", "20260301000000.1234Z", True, False),
        ]
        for ca, gen, new, old in rows:
            self.assertEqual("CRITERIA_TIME_MISMATCH" in self.case(ca, gen)["problem_codes"], new, (ca, gen))
            self.assertEqual("CRITERIA_TIME_MISMATCH" in self.case(ca, gen, P142)["problem_codes"], old, (ca, gen))

    def test_generative_second_rule(self):
        rnd = random.Random(1435)
        for _ in range(150):
            s1, s2 = rnd.randrange(60), rnd.randrange(60)
            frac = "".join(rnd.choice("0123456789") for _ in range(rnd.randrange(0, 5))).rstrip("0")
            gen = "202603010000%02d%sZ" % (s2, "." + frac if frac else "")
            nd = rnd.randrange(0, 4)
            cfrac = "".join(rnd.choice("0123456789") for _ in range(nd))
            if rnd.random() < 0.5:      # the same instant written with a fraction: the case the old rule let agree
                s1 = s2
                if 0 < len(frac) <= 3:
                    nd, cfrac = 3, frac.ljust(3, "0")
            ca = "2026-03-01T00:00:%02d%sZ" % (s1, "." + cfrac if nd else "")
            want = not (nd == 0 and s1 == s2)
            self.assertEqual("CRITERIA_TIME_MISMATCH" in self.case(ca, gen)["problem_codes"], want, (ca, gen))


class S7AuthorityCheckWithoutUsableGenTime(unittest.TestCase):
    """S7 (105, 107): with anchors, a token whose genTime is not usable is `failed`, also when it has no signer."""

    @classmethod
    def setUpClass(cls):
        cls.root = tp.make_ca("war-verify TEST root 1.4.3")

    def case(self, gen, opts=None, signerinfos=False):
        i = fixture()
        d = bytes.fromhex(i["receipt"]["receipt"]["criteria"]["sha256"])
        ascii_only = tp.gentime
        tp.gentime = lambda s: tp.tlv(0x18, s.encode("utf-8"))        # non-ASCII content too, still tagged [UNIVERSAL 24]
        try:
            i["criteria_tsr_base64"] = build.b64(tp.unsigned_tsr(tp.tstinfo(d, gen=gen), with_signerinfos=signerinfos))
        finally:
            tp.gentime = ascii_only
        i["tsa_roots_base64"] = [build.b64(tp.der(self.root[1]))]
        return run(i, opts)

    def test_no_signer_and_unusable_gentime(self):
        ctl = self.case("20260301000000Z")                                       # control: usable genTime
        self.assertEqual(ctl["tsa_signature"], {"criteria": "no_signer"})
        for g in GEN_BAD + ["20260301000000.-0Z", "20260301000000. 5Z", "20260301000000.٥Z".encode().decode()]:
            rep = self.case(g)
            self.assertEqual(rep["tsa_signature"], {"criteria": "failed"}, repr(g))
            self.assertEqual(rep["warning_codes"], [UNVERIFIED], repr(g))
            self.assertEqual(self.case(g, P142)["tsa_signature"], {"criteria": "failed"}, repr(g))  # a fix, not a reading
            self.assertEqual(self.case(g, {"tsa_precedence": "evaluability-first"})["tsa_signature"],
                             {"criteria": "no_signer"}, repr(g))

    def test_counts(self):
        evaluated = [g for g in GEN_BAD if not self.case(g).get("refused")]
        self.assertGreaterEqual(len(evaluated), len(GEN_BAD) - 2)


class S8Unchanged(unittest.TestCase):
    """S8 (92, 93, 101, 102): already so in 0.6.0; pinned here with the 1.4.3 vectors."""

    def test_vectors(self):
        files = [f for f in score.vector_files() if os.path.basename(f).split("-")[0] in ("92", "93", "101", "102")]
        rows = score.score(files=files)
        self.assertEqual((len(rows), short(rows)), (4, []))
        self.assertEqual(short(score.score(dict(P142), files=files)), [])


class CLI143(unittest.TestCase):
    """--profile 1.4.2 and the four new switches on the command line (each a separate value, never last-wins)."""

    def run_cli(self, *args):
        import subprocess, sys
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        return subprocess.run([sys.executable, "-B", os.path.join(score.ROOT, "war_verify.py")] + list(args),
                              capture_output=True, text=True, env=env).returncode

    def vec(self, n):
        return [f for f in score.vector_files() if os.path.basename(f).startswith("%s-" % n)][0]

    def test_profiles_and_switches(self):
        for n, switch in (("91", ("--key-scope", "all-entries")), ("94", ("--digest-form", "refuse")),
                          ("95", ("--stated-fraction", "three")), ("104", ("--empty-key-id", "refuse"))):
            self.assertEqual(self.run_cli("--vector", self.vec(n)), 0, n)
            self.assertEqual(self.run_cli("--vector", "--profile", "1.4.2", self.vec(n)), 3, n)
            self.assertEqual(self.run_cli("--vector", *switch, self.vec(n)), 3, n)
            self.assertEqual(self.run_cli("--vector", "--profile", "1.4.2", switch[0],
                                          wv.DEFAULT_OPTIONS[switch[0][2:].replace("-", "_")], self.vec(n)), 0, n)
            self.assertEqual(self.run_cli(*(switch + switch + (self.vec(n),))), 64, n)
            self.assertEqual(self.run_cli(switch[0], "bogus", self.vec(n)), 64, n)
        self.assertEqual(self.run_cli("--vector", "--profile", "1.2.1", self.vec("95")), 3)
        self.assertEqual(self.run_cli("--profile", "9.9.9", self.vec("95")), 64)
        self.assertEqual(self.run_cli("--profile", "1.4.2", "--profile", "1.2.1", self.vec("95")), 64)
        self.assertEqual(self.run_cli("--vector", "--time-agreement", "second", self.vec("99")), 0)

    def test_profile_1_2_1_carries_the_1_4_2_readings(self):
        for k, v in wv.PROFILE_1_4_2.items():
            self.assertEqual(wv.PROFILE_1_2_1[k], v, k)
        self.assertEqual(set(wv.PROFILE_1_4_2) - set(P143), {"key_scope", "empty_key_id", "digest_form",
                                                             "stated_fraction", "time_agreement"})
        for k, v in wv.PROFILE_1_4_2.items():
            self.assertNotEqual(wv.DEFAULT_OPTIONS[k], v, k)
            self.assertIn(v, wv.OPTION_VALUES[k], k)


if __name__ == "__main__":
    unittest.main()
