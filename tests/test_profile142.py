"""Profile 1.4.2 (maximusrufus/work-acceptance-record@85a310d, README step 10 "Profile 1.4.2 rules", vectors 58-87).
Oracle: the 85a310d vectors, and generative cases near each rule's edges whose expectation is written from the rule's
sentence (README of this project, "Profile 1.4.2 rules", R1-R10), never from running the verifier. Each class names
its rule and vectors. Positive control: run on 0.5.0 (7c96866), these tests fail (README, "Tests")."""
import base64
import copy
import hashlib
import itertools
import os
import unittest

import _paths  # noqa: F401
import build
import score
import testpki as tp
import war_verify as wv

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
STEP1 = wv.STEP1_REASON
UNVERIFIED = "CRITERIA_COMMITMENT_UNVERIFIED"


def run(inp, opts=None):
    try:
        return wv.verify(copy.deepcopy(inp), opts)
    except wv.Refusal as e:
        return {"refused": True, "reason": e.reason, "detail": e.detail}


def fixture(token=False):
    """Vector 01 re-keyed to the omega TEST keys, no record token: valid, independent, criteria committed first."""
    return build.base(token=token)


def edit(inp, fn, resign=True):
    fn(inp["receipt"]["receipt"])
    if resign:
        build.sign(inp)
    return inp


def entry(kid, pub_b64, status="test"):
    return {"alg": "Ed25519", "key_id": kid, "public_key_base64": pub_b64, "status": status}


def trailing_bit_variants(s):
    """Same decoded bytes, non-zero unused bits in the last data character (non-canonical, RFC 4648 3.5)."""
    pad = len(s) - len(s.rstrip("="))
    unused = {1: 2, 2: 4}[pad]
    last = len(s) - pad - 1
    v = ALPHA.index(s[last])
    out = [s[:last] + ALPHA[v | b] + s[last + 1:] for b in range(1, 1 << unused)]
    for o in out:
        assert base64.b64decode(o) == base64.b64decode(s) and o != s
    return out


class Vectors85a310d(unittest.TestCase):
    def test_88_of_88(self):
        rows = score.score(which="85a310d")
        self.assertEqual(len(rows), 88)
        self.assertEqual([r["file"] for r in rows if not r["agree"]], [])
        self.assertEqual(sum(r["fields"] for r in rows), 803)

    def test_cb7e8f1_88_to_90(self):
        # the clarification of 2026-10-27 (cb7e8f1): 88 closes Q6 (the other way than 0.6.0 first read it), 89 and
        # 90 confirm the R1 reading of Q2; the vector member proposed_by (88) is metadata
        import glob
        files = sorted(glob.glob(os.path.join(score.ROOT, "fonti/upstream_cb7e8f1/vectors/*.json")))
        self.assertEqual([os.path.basename(f)[:2] for f in files], ["88", "89", "90"])
        rows = score.score(files=files)
        self.assertEqual([(r["file"], r["disagreements"]) for r in rows if not r["agree"]], [])
        self.assertEqual(sum(r["fields"] for r in rows), 27)
        # the vector document itself stays closed: a member that is not in VECTOR_META is refused with its name
        import json
        with open(files[0], "rb") as fh:
            doc = json.load(fh)
        doc["nemesis_member"] = 1
        with self.assertRaises(wv.Refusal) as cm:
            wv.run_vector_bytes(json.dumps(doc).encode(), None)
        self.assertEqual((cm.exception.reason, cm.exception.detail), ("unknown member(s) in the vector document", "nemesis_member"))

    def test_01_to_57_inputs_and_expected_as_bc5a138(self):
        # profile 1.4.2: "vectors 01-57 and their outcomes are unchanged"
        import json
        old, new = score.vector_files("bc5a138")[:-1], score.vector_files("85a310d")[:57]
        for f, g in zip(old, new):
            with open(f, "rb") as a, open(g, "rb") as b:
                x, y = json.load(a), json.load(b)
            self.assertEqual((x["inputs"], x["expected"]), (y["inputs"], y["expected"]), g)


class R1CanonicalBase64(unittest.TestCase):
    """R1 (60-63, 69): canonical base64 only; a non-canonical signature value is SIGNATURE_INVALID, a key KEY_REJECTED."""

    @classmethod
    def setUpClass(cls):
        cls.inp = fixture()
        cls.control = run(cls.inp)
        cls.sig = cls.inp["receipt"]["signature"]["value"]

    def test_control(self):
        self.assertIs(self.control["signature_valid"], True)
        self.assertEqual(self.control["problem_codes"], [])

    def check_invalid(self, v):
        i = copy.deepcopy(self.inp)
        i["receipt"]["signature"]["value"] = v
        rep = run(i)
        self.assertFalse(rep.get("refused"), (v, rep))
        self.assertIs(rep["signature_valid"], False, v)
        self.assertEqual(rep["problem_codes"], ["SIGNATURE_INVALID"], v)
        for k in ("criteria_hash", "independence", "warning_codes", "receipt_timestamp", "verdict_recomputed",
                  "criteria_committed_before_check"):
            self.assertEqual(rep[k], self.control[k], (v, k))

    def test_insertion_of_every_foreign_character_at_every_position(self):
        for pos in range(len(self.sig) + 1):
            for ch in (" ", "\t", "\n", "\r", "!", "*", "-", "_", ".", ":", "=", "é", "\x00"):
                self.check_invalid(self.sig[:pos] + ch + self.sig[pos:])

    def test_replacement_by_url_safe_or_foreign_characters(self):
        for pos in range(len(self.sig) - 2):
            for ch in ("-", "_", "!", " ", "="):
                self.check_invalid(self.sig[:pos] + ch + self.sig[pos + 1:])

    def test_trailing_bits_and_padding(self):
        for v in trailing_bit_variants(self.sig):            # 64 bytes: 4 unused bits, 15 variants (62)
            self.check_invalid(v)
        for v in (self.sig.rstrip("="), self.sig[:-1], self.sig + "=", self.sig + "==", self.sig + "AAAA",
                  "=" + self.sig[:-1]):
            self.check_invalid(v)

    def test_signature_value_type_is_step1(self):
        for v in (None, 1, True, [], {}, [self.sig]):
            i = copy.deepcopy(self.inp)
            i["receipt"]["signature"]["value"] = v
            rep = run(i)
            self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1), v)

    def test_b64_canonical_exhaustive_on_four_characters(self):
        # oracle written independently of the implementation: the canonical strings of length 4 are the encodings of
        # every 1- and 2-byte string plus every 4-character string without '=' (3 bytes, no unused bits)
        canon = {base64.b64encode(bytes(b)).decode() for n in (1, 2) for b in itertools.product(range(256), repeat=n)}
        for rest in itertools.product(ALPHA + "=", repeat=3):
            s = "Q" + "".join(rest)
            want = s in canon or "=" not in s
            self.assertEqual(wv.b64_canonical(s) is not None, want, s)
        for s in ("", "Q", "QQ", "QQ=", "QQ==QQ==", "QQ==\n", " QQ==", "QUJD\n", "QUJD "):
            self.assertEqual(wv.b64_canonical(s) is not None, s in ("", "QQ==QQ==") and s == "", s)


class R1R3KeyList(unittest.TestCase):
    """R1 (69) and R3 (75, 79): a non-canonical public key or a repeated key_id is KEY_REJECTED."""

    def setUp(self):
        self.inp = fixture()
        self.k1 = build.pub_b64("omega-test-1")
        self.k2 = build.pub_b64("omega-test-2")

    def with_keys(self, keys, producer_kid=None, independence="independent"):
        i = copy.deepcopy(self.inp)
        i["keys"]["keys"] = keys

        def f(r):
            r["parties"]["producer"]["key_id"] = producer_kid
            r["independence"] = independence
        return edit(i, f)

    def test_control_canonical_alias_is_a_collision(self):
        rep = run(self.with_keys([entry("omega-test-1", self.k1), entry("alias", self.k1)], "alias", "self-checked"))
        self.assertEqual(rep["problem_codes"], ["KEY_COLLISION"])                       # 65, 87
        self.assertEqual(rep["warning_codes"], ["SELF_CHECKED"])

    def test_non_canonical_entry_in_every_role(self):
        for bad in trailing_bit_variants(self.k1) + [self.k1.rstrip("="), self.k1[:10] + " " + self.k1[10:],
                                                       self.k1[:-2] + "!="]:
            # producer's entry: the checker's key under a non-canonical string (69)
            rep = run(self.with_keys([entry("omega-test-1", self.k1), entry("p", bad)], "p", "self-checked"))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"], rep["warning_codes"]),
                             (True, ["KEY_REJECTED"], ["SELF_CHECKED"]), bad)
            rep = run(self.with_keys([entry("omega-test-1", self.k1), entry("p", bad)], "p", "independent"))
            self.assertEqual(sorted(rep["problem_codes"]), ["INDEPENDENCE_INCONSISTENT", "KEY_REJECTED"], bad)
            # the signer's (and checker's) entry: no signature check
            rep = run(self.with_keys([entry("omega-test-1", bad), entry("omega-test-2", self.k2)], None, "self-checked"))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (False, ["KEY_REJECTED"]), bad)
            # an entry no party names (reading, README R1): KEY_REJECTED, independence untouched
            rep = run(self.with_keys([entry("omega-test-1", self.k1), entry("x", bad)], None, "independent"))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"], rep["warning_codes"]),
                             (True, ["KEY_REJECTED"], []), bad)
            self.assertNotIn("X_UNUSED_KEY_REJECTED", rep["extension_codes"], bad)   # the profile code, not the local block

    def test_repeated_key_id_in_every_position(self):
        e1, e2 = entry("omega-test-1", self.k1), entry("omega-test-2", self.k2)
        third = entry("omega-test-3", self.k2)
        for dup, same_key in itertools.product(("omega-test-1", "omega-test-2", "omega-test-3"), (True, False)):
            base = [e1, e2, third]
            src = [e for e in base if e["key_id"] == dup][0]
            extra = dict(src) if same_key else dict(src, public_key_base64=self.k2 if src["public_key_base64"] ==
                                                    self.k1 else self.k1)
            for pos in range(len(base) + 1):
                keys = base[:pos] + [extra] + base[pos:]
                producer = "omega-test-2"
                rep = run(self.with_keys(keys, producer, "independent"))
                self.assertFalse(rep.get("refused"), (dup, pos, rep))
                self.assertIn("KEY_REJECTED", rep["problem_codes"], (dup, pos))
                if dup == "omega-test-1":                       # the signer's and checker's id (75)
                    self.assertIs(rep["signature_valid"], False)
                    self.assertNotIn("SIGNATURE_INVALID", rep["problem_codes"])
                    self.assertIn("INDEPENDENCE_INCONSISTENT", rep["problem_codes"])
                elif dup == "omega-test-2":                     # the producer's id: derived self-checked
                    self.assertIs(rep["signature_valid"], True)
                    self.assertEqual(sorted(rep["problem_codes"]), ["INDEPENDENCE_INCONSISTENT", "KEY_REJECTED"])
                else:                                           # unrelated id (79)
                    self.assertIs(rep["signature_valid"], True)
                    self.assertEqual(rep["problem_codes"], ["KEY_REJECTED"])
                    self.assertEqual(rep["warning_codes"], [])
                self.assertNotIn("X_UNUSED_KEY_REJECTED", rep["extension_codes"], (dup, pos))   # KEY_REJECTED, not local

    def test_empty_key_list_is_refused(self):
        rep = run(self.with_keys([]))
        self.assertEqual((rep.get("refused"), rep.get("reason")), (True, "keys.keys is an empty list"))
        rep = run(self.with_keys({}))
        self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1))

    def test_key_rule_refuse_keeps_the_refusals(self):
        keys = [entry("omega-test-1", self.k1), entry("omega-test-1", self.k1)]
        self.assertTrue(run(self.with_keys(keys), {"key_rule": "refuse"}).get("refused"))
        keys = [entry("omega-test-1", self.k1), entry("x", trailing_bit_variants(self.k2)[0])]
        self.assertTrue(run(self.with_keys(keys), {"key_rule": "refuse"}).get("refused"))


class R2LowerCaseDigests(unittest.TestCase):
    """R2 (67): an upper-case hex digit in a record digest matches no digest."""

    def test_one_upper_case_letter_at_every_position(self):
        i = fixture()
        h = i["receipt"]["receipt"]["criteria"]["sha256"]
        n = 0
        for pos, ch in enumerate(h):
            if ch not in "abcdef":
                continue
            n += 1
            rep = run(edit(copy.deepcopy(i), lambda r: r["criteria"].__setitem__("sha256", h[:pos] + ch.upper() +
                                                                                 h[pos + 1:])))
            self.assertFalse(rep.get("refused"))
            self.assertEqual(rep["criteria_hash"], "mismatch", pos)
            self.assertEqual(sorted(rep["problem_codes"]), ["CRITERIA_HASH_MISMATCH", "CRITERIA_TIMESTAMP_MISMATCH"])
            self.assertEqual(rep["warning_codes"], [UNVERIFIED])
        self.assertGreater(n, 0)

    def test_other_forms_still_refused_and_wrong_type_is_step1(self):
        i = fixture()
        h = i["receipt"]["receipt"]["criteria"]["sha256"]
        for v in (h[:-1], h + "0", "g" * 64, " " + h[1:], h[:-1] + "\n", h + "\n", h.upper() + "\n"):
            rep = run(edit(copy.deepcopy(i), lambda r: r["criteria"].__setitem__("sha256", v)))
            self.assertTrue(rep.get("refused"), v)
            self.assertNotEqual(rep["reason"], STEP1)
        for v in (None, 1, [h], {"h": h}):
            rep = run(edit(copy.deepcopy(i), lambda r: r["criteria"].__setitem__("sha256", v)))
            self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1), v)

    def test_delivered_file_digest_upper_case_is_a_mismatch(self):
        i = fixture()
        data = b"delivered"
        i["delivered_file_base64"] = base64.b64encode(data).decode()
        d = hashlib.sha256(data).hexdigest()
        edit(i, lambda r: r["files"]["remediated"].update(sha256=d, bytes=len(data)))
        self.assertEqual(run(i)["files"]["remediated"], "match")
        edit(i, lambda r: r["files"]["remediated"].update(sha256=d.upper()))
        self.assertEqual(run(i)["files"]["remediated"], "mismatch")


class R1Inputs(unittest.TestCase):
    """R1: "a token or criteria file that is not canonical base64 matches nothing"."""

    def test_criteria_file_and_tokens(self):
        i = fixture(token=True)
        ctl = run(i)
        self.assertEqual((ctl["criteria_hash"], ctl["receipt_timestamp"], ctl["problem_codes"]),
                         ("match", "imprint_match", []))
        for name in ("criteria_file_base64", "criteria_tsr_base64", "receipt_tsr_base64"):
            v = i[name]
            bads = [v[:4] + " " + v[4:], v[:4] + "!" + v[5:]]
            bads += trailing_bit_variants(v)[:1] + [v.rstrip("=")] if v.endswith("=") else [v + "=", v + "===="]
            for bad in bads:
                j = copy.deepcopy(i)
                j[name] = bad
                rep = run(j)
                self.assertFalse(rep.get("refused"), (name, rep))
                if name == "criteria_file_base64":
                    self.assertEqual((rep["criteria_hash"], rep["problem_codes"]), ("mismatch",
                                                                                    ["CRITERIA_HASH_MISMATCH"]))
                elif name == "criteria_tsr_base64":            # reading: a token over other bytes
                    self.assertEqual(rep["problem_codes"], ["CRITERIA_TIMESTAMP_MISMATCH"])
                    self.assertEqual(rep["warning_codes"], [UNVERIFIED])
                else:
                    self.assertEqual(rep["receipt_timestamp"], "imprint_mismatch")
                    self.assertEqual(rep["problem_codes"], [])
                self.assertIn("X_BASE64_NONCANONICAL", rep["extension_codes"])

    def test_delivered_and_original_files(self):
        data = b"delivered!"                                   # 10 bytes: "==" padding, 4 unused bits
        i = fixture()
        d = hashlib.sha256(data).hexdigest()
        edit(i, lambda r: r["files"].update(remediated=dict(r["files"]["remediated"], sha256=d, bytes=len(data)),
                                            original=dict(r["files"]["remediated"], sha256=d, bytes=len(data))))
        for name, side in (("delivered_file_base64", "remediated"), ("original_file_base64", "original")):
            j = copy.deepcopy(i)
            j[name] = base64.b64encode(data).decode()
            self.assertEqual(run(j)["files"][side], "match")
            for bad in trailing_bit_variants(j[name]) + [j[name].rstrip("="), " " + j[name]]:
                k = copy.deepcopy(j)
                k[name] = bad
                rep = run(k)
                self.assertEqual((rep["files"][side], rep["problem_codes"]), ("mismatch", []), (name, bad))


GEN_OK = ["20260301000000Z", "20260301000000.5Z", "20260301000000.123Z", "20260301000000.0001Z",
          "20260301000000.999999999Z"]
GEN_BAD = ["20260301000000", "20260301000000z", "20260301000000+0000", "20260301010000+0100", "20260301000000-0000",
           "20260301000000.Z", "20260301000000.0Z", "20260301000000.50Z", "20260301000000.5000Z", "20260301000000,5Z",
           "202603010000Z", "2026030100Z", "202603010000000Z", "20261301000000Z", "20260001000000Z", "20260300000000Z",
           "20260332000000Z", "20260230000000Z", "20270229000000Z", "20260301240000Z", "20260301006000Z",
           "20260301000060Z", " 20260301000000Z", "20260301000000Z ", "2026-03-01T00:00:00Z", "", "Z",
           "2026030100000aZ", "+2026030100000Z", "20260301000000.+5Z", "20260301000000.5ZZ", "2026030100000\x7fZ"]


class R4GenTime(unittest.TestCase):
    """R4 (70-74, 78): a genTime outside DER UTC GeneralizedTime with real calendar fields is no usable time."""

    def crit(self, gen, digest=None, **kw):
        i = fixture()
        build.criteria_token(i, gen=gen, digest=digest, **kw)
        return run(i)

    def test_usable_forms(self):
        for g in GEN_OK:
            rep = self.crit(g)
            self.assertFalse(rep.get("refused"), (g, rep))
            self.assertEqual((rep["problem_codes"], rep["warning_codes"]), ([], []), g)

    def test_every_other_form_gives_no_time(self):
        for g in GEN_BAD:
            rep = self.crit(g)
            self.assertFalse(rep.get("refused"), (g, rep))
            self.assertEqual((rep["problem_codes"], rep["warning_codes"]), ([], [UNVERIFIED]), g)
            self.assertEqual(rep["criteria_committed_before_check"], "yes", g)        # from committed_at (78)
            self.assertIn("X_GENTIME_UNUSABLE", rep["extension_codes"], g)

    def test_unusable_time_does_not_hide_an_imprint_mismatch(self):
        for g in GEN_BAD[:5]:
            rep = self.crit(g, digest=b"\x11" * 32)
            self.assertEqual((rep["problem_codes"], rep["warning_codes"]),
                             (["CRITERIA_TIMESTAMP_MISMATCH"], [UNVERIFIED]), g)

    def test_unusable_record_token_time_is_no_reference(self):
        # the record token covers the record; a usable genTime earlier than the criteria time decides "no"
        i = fixture()
        build.record_token(i, gen="20260201000000Z")
        ctl = run(i)
        self.assertEqual((ctl["receipt_timestamp"], ctl["criteria_committed_before_check"]), ("imprint_match", "no"))
        i["criteria_tsr_base64"] = None                 # only the covering record token supplies a time (structural)
        rep = run(i)
        self.assertEqual((rep["criteria_committed_before_check"], rep["warning_codes"]), ("no", [UNVERIFIED]))
        self.assertIn("X_TSA_NOT_VERIFIED", rep["extension_codes"])
        self.assertEqual(rep["details"]["token_authentication"]["record_token"],
                         "unauthenticated (--tokens structural: TSA signature not checked)")
        for g in ("20260201000000+0000", "20261301000000Z", "20260201000000.10Z"):
            j = fixture()
            build.record_token(j, gen=g)
            j["receipt"]["timestamp"]["gen_time"] = "20260201000000Z"      # the issuer's unsigned copy, well formed
            rep = run(j)
            self.assertFalse(rep.get("refused"), (g, rep))
            self.assertEqual((rep["receipt_timestamp"], rep["criteria_committed_before_check"], rep["problem_codes"]),
                             ("imprint_match", "yes", []), g)
            self.assertIn("X_TIMESTAMP_METADATA_DISAGREES", rep["extension_codes"], g)   # the unsigned copy disagrees


class R4Milliseconds(unittest.TestCase):
    """R4 (66, 68): criteria time rounded up, reference time down, to the millisecond; strict <."""

    def case(self, crit_gen, issued, rec_gen=None, opts=None):
        i = fixture()

        def f(r):
            r["issued_utc"] = issued
            r["criteria"]["committed_at"] = "%s-%s-%sT%s:%s:%sZ" % (crit_gen[:4], crit_gen[4:6], crit_gen[6:8],
                                                                    crit_gen[8:10], crit_gen[10:12], crit_gen[12:14])
        edit(i, f)
        build.criteria_token(i, gen=crit_gen)
        if rec_gen:
            build.record_token(i, gen=rec_gen)
        rep = run(i, opts)
        self.assertFalse(rep.get("refused"), rep)
        self.assertEqual(rep["warning_codes"], [])
        self.assertNotIn("CRITERIA_TIME_MISMATCH", rep["problem_codes"])
        return rep["criteria_committed_before_check"]

    def test_table(self):
        T = "2026-06-01T12:00:00"
        for crit, issued, want in (("20260601120000.2495Z", T + ".250Z", "no"),      # 68
                                   ("20260601120000.2491Z", T + ".250Z", "no"),
                                   ("20260601120000.249Z", T + ".250Z", "yes"),
                                   ("20260601120000.5Z", T + ".250Z", "no"),         # 66
                                   ("20260601120000.0001Z", T + ".001Z", "no"),
                                   ("20260601120000Z", T + ".001Z", "yes"),
                                   ("20260601120000Z", T + "Z", "no"),
                                   ("20260601115959.999Z", T + "Z", "yes"),
                                   ("20260601115959.9991Z", T + "Z", "no")):
            self.assertEqual(self.case(crit, issued), want, (crit, issued))
            # the same rounding in the branch without widening (--accuracy ignore; no token states an accuracy)
            self.assertEqual(self.case(crit, issued, opts={"accuracy": "ignore"}), want, (crit, issued, "ignore"))

    def test_reference_from_a_covering_token_rounds_down(self):
        later = "2026-06-01T13:00:00.000Z"
        self.assertEqual(self.case("20260601120000.001Z", later, "20260601120000.0019Z"), "no")
        self.assertEqual(self.case("20260601120000.001Z", later, "20260601120000.002Z"), "yes")
        self.assertEqual(self.case("20260601120000.0001Z", later, "20260601120000.0019Z"), "no")
        self.assertEqual(self.case("20260601120000.001Z", later, "20260601120000.0019Z", opts={"accuracy": "ignore"}),
                         "no")


STATED_OK = ["2026-06-01T12:00:00Z", "2026-06-01T12:00:00.123Z", "2026-06-01T12:00:00.000Z", "2028-02-29T00:00:00Z"]
STATED_BAD = ["2026-06-01T12:00:00.1Z", "2026-06-01T12:00:00.12Z", "2026-06-01T12:00:00.1234Z",
              "2026-06-01t12:00:00Z", "2026-06-01T12:00:00z", "2026-06-01T12:00:00+00:00", "2026-06-01T12:00:00-00:00",
              "2026-06-01T12:00:00", "2026-06-01 12:00:00Z", "2026-06-01T12:00Z", "2026-13-01T00:00:00Z",
              "2026-00-01T00:00:00Z", "2026-02-30T00:00:00Z", "2027-02-29T00:00:00Z", "2026-06-31T00:00:00Z",
              "2026-06-01T24:00:00Z", "2026-06-01T12:60:00Z", "2026-06-30T23:59:60Z", "20260601T120000Z",
              "2026-6-01T12:00:00Z", " 2026-06-01T12:00:00Z", "2026-06-01T12:00:00Z ", "", "2026-06-01T12:00:00,123Z",
              "2026-06-01T12:00:00.Z", "+2026-06-01T12:00:00Z", "\u0662026-06-01T12:00:00Z",
              "2026-06-01T12:00:00Z\n", "2026-06-01T12:00:00.123Z\n", "2026-06-01T12:00:00Z\r\n", "\n2026-06-01T12:00:00Z"]


class R5StatedTimes(unittest.TestCase):
    """R5 (76): committed_at / issued_utc outside YYYY-MM-DDTHH:MM:SS[.fff]Z give RECEIPT_TIME_UNREADABLE and "no".
    Clarified at cb7e8f1 (vector 88): step 5 uses committed_at only without a usable criteria token; with one, an
    unreadable committed_at is CRITERIA_TIME_MISMATCH and the token decides "committed before"."""

    def rep(self, member, value, token=False, other_bytes=False):
        i = fixture()
        if not token:
            i["criteria_tsr_base64"] = None
        elif other_bytes:
            build.criteria_token(i, digest=b"\x11" * 32)      # a token over other bytes: fallback to committed_at

        def f(r):
            if member == "issued_utc":
                r["issued_utc"] = value
            else:
                r["criteria"]["committed_at"] = value
        return run(edit(i, f))

    def test_readable(self):
        for v in STATED_OK:
            rep = self.rep("issued_utc", v)
            self.assertEqual(rep["problem_codes"], [], v)
            self.assertEqual(rep["criteria_committed_before_check"], "yes", v)
            rep = self.rep("committed_at", v.replace("2026-06-01T12", "2026-03-01T00").replace("2028-02-29",
                                                                                                 "2024-02-29"))
            self.assertEqual(rep["problem_codes"], [], v)

    def test_unreadable_in_every_form(self):
        for member, token in (("issued_utc", False), ("committed_at", False), ("issued_utc", True)):
            for v in STATED_BAD:
                rep = self.rep(member, v, token)
                self.assertFalse(rep.get("refused"), (member, v, rep))
                self.assertEqual(rep["problem_codes"], ["RECEIPT_TIME_UNREADABLE"], (member, v, token))
                self.assertEqual(rep["criteria_committed_before_check"], "no", (member, v))
                self.assertEqual(rep["warning_codes"], [] if token else [UNVERIFIED], (member, v, token))
                self.assertIn("token_authentication", rep["details"], (member, v, token))
        for v in STATED_BAD:
            # cb7e8f1 vector 88: a usable criteria token supplies the time; committed_at is not used, it disagrees
            rep = self.rep("committed_at", v, token=True)
            self.assertEqual((rep["problem_codes"], rep["criteria_committed_before_check"], rep["warning_codes"]),
                             (["CRITERIA_TIME_MISMATCH"], "yes", []), v)
            # a token over other bytes gives no time: committed_at is used, so it is unreadable (R5, 76)
            rep = self.rep("committed_at", v, token=True, other_bytes=True)
            self.assertEqual((sorted(rep["problem_codes"]), rep["criteria_committed_before_check"], rep["warning_codes"]),
                             (["CRITERIA_TIMESTAMP_MISMATCH", "RECEIPT_TIME_UNREADABLE"], "no", [UNVERIFIED]), v)

    def test_wrong_type_is_step1(self):
        for member in ("issued_utc", "committed_at"):
            for v in (None, 0, 1.5, True, [], {}, ["2026-06-01T12:00:00Z"]):
                rep = self.rep(member, v)
                self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1), (member, v))


class R6Independence(unittest.TestCase):
    """R6 (80-82): a stated party key_id must be non-empty and listed once, else derived self-checked."""

    def rep(self, producer, independence="independent", checker="omega-test-1", drop=False):
        i = fixture()

        def f(r):
            if drop:
                r["parties"]["producer"].pop("key_id")
            else:
                r["parties"]["producer"]["key_id"] = producer
            r["parties"]["checker"]["key_id"] = checker
            r["independence"] = independence
        return run(edit(i, f))

    def test_table(self):
        for producer, ind, want in (("", "independent", ["INDEPENDENCE_INCONSISTENT"]),           # 80
                                    ("unknown", "independent", ["INDEPENDENCE_INCONSISTENT"]),    # 81
                                    (" ", "independent", ["INDEPENDENCE_INCONSISTENT"]),
                                    ("OMEGA-TEST-2", "independent", ["INDEPENDENCE_INCONSISTENT"]),
                                    ("omega-test-2", "independent", []),
                                    (None, "independent", []),
                                    ("", "self-checked", []),
                                    ("unknown", "self-checked", []),
                                    ("omega-test-2", "self-checked", ["INDEPENDENCE_INCONSISTENT"])):
            rep = self.rep(producer, ind)
            self.assertEqual(rep["problem_codes"], want, (producer, ind))
            self.assertEqual(rep["warning_codes"], ["SELF_CHECKED"] if ind == "self-checked" else [],
                             (producer, ind))
        rep = self.rep(None, drop=True)                                                         # 82
        self.assertEqual((rep["problem_codes"], rep["warning_codes"], rep["independence"]), ([], [], "independent"))
        # the 1.2.1 reading (--independence-rule stated-independent) does not read R6: 80 and 81 then disagree
        for producer in ("", "unknown"):
            rep = run(edit(fixture(), lambda r: (r["parties"]["producer"].__setitem__("key_id", producer),
                                                 r.__setitem__("independence", "independent"))),
                      {"independence_rule": "stated-independent"})
            self.assertEqual((rep["problem_codes"], rep["independence"], rep["details"]["independence_derived"]),
                             ([], "independent", "independent"), producer)

    def test_checker_key_id_unlisted(self):
        rep = self.rep("omega-test-2", checker="ghost")
        self.assertEqual(sorted(rep["problem_codes"]), ["CHECKER_NOT_SIGNER", "INDEPENDENCE_INCONSISTENT"])
        rep = self.rep("omega-test-2", "self-checked", checker="ghost")
        self.assertEqual(rep["problem_codes"], ["CHECKER_NOT_SIGNER"])

    def test_party_key_id_wrong_type_is_step1(self):
        for v in (1, True, [], {}, ["omega-test-2"]):
            rep = self.rep(v)
            self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1), v)


class R7CheckerIsTheSigner(unittest.TestCase):
    """R7 (64, 86): CHECKER_NOT_SIGNER compares identifiers with the signed key_id, never the envelope's."""

    def test_alias_identifier_for_the_signers_key_is_not_the_signer(self):
        i = fixture()
        i["keys"]["keys"].append(entry("alias-1", build.pub_b64("omega-test-1")))
        rep = run(edit(i, lambda r: r["parties"]["checker"].__setitem__("key_id", "alias-1")))
        self.assertEqual(rep["problem_codes"], ["CHECKER_NOT_SIGNER"])
        self.assertIs(rep["signature_valid"], True)

    def test_envelope_naming_another_key_is_signature_invalid_only(self):
        for other in ("omega-test-2", "alias-1"):
            i = fixture()
            i["keys"]["keys"].append(entry("alias-1", build.pub_b64("omega-test-1")))
            i["receipt"]["signature"]["key_id"] = other
            rep = run(i)
            self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (False, ["SIGNATURE_INVALID"]), other)
        # reading Q15: an empty signing identifier is refused (not SIGNATURE_INVALID), as until 0.5.0
        for where in ("signature", "receipt"):
            i = fixture()
            i["receipt"][where]["key_id"] = ""
            if where == "receipt":
                build.sign(i, sign_with="omega-test-1")
            rep = run(i)
            self.assertEqual((rep.get("refused"), rep.get("reason")), (True, "%s.key_id is empty" % where), where)

    def test_profile_1_2_1_keeps_the_key_comparison(self):
        i = fixture()
        i["keys"]["keys"].append(entry("alias-1", build.pub_b64("omega-test-1")))
        rep = run(edit(i, lambda r: r["parties"]["checker"].__setitem__("key_id", "alias-1")), dict(wv.PROFILE_1_2_1))
        self.assertNotIn("CHECKER_NOT_SIGNER", rep["problem_codes"])


def _paths_of(v, path=()):
    if isinstance(v, dict):
        for k in v:
            yield from _paths_of(v[k], path + (k,))
    elif isinstance(v, list):
        for n, x in enumerate(v):
            yield from _paths_of(x, path + (n,))
    yield path, v


def _set(root, path, value):
    for p in path[:-1]:
        root = root[p]
    root[path[-1]] = value


NULLABLE = {("receipt", "receipt", "parties", "checker", "key_id"), ("receipt", "receipt", "parties", "checker", "name"),
            ("receipt", "receipt", "parties", "producer", "key_id"), ("receipt", "receipt", "parties", "producer", "name"),
            ("receipt", "timestamp")}
OPTIONAL_NULLABLE_INPUTS = {("criteria_file_base64",), ("criteria_tsr_base64",), ("receipt_tsr_base64",)}


class R8Types(unittest.TestCase):
    """R8 (77): a member of the record or the inputs with another type is refused with the step 1 outcome."""

    def test_every_member_of_the_fixture_with_every_other_type(self):
        i = fixture(token=True)
        i["keys"]["keys"][0]["since"] = "2026-01-01"
        samples = {"str": "x", "int": 7, "bool": True, "null": None, "list": [], "dict": {}, "float": 1.5}

        def kind(v):
            return ("bool" if isinstance(v, bool) else "int" if isinstance(v, int) else "float" if isinstance(v, float)
                    else "str" if isinstance(v, str) else "null" if v is None else "list" if isinstance(v, list)
                    else "dict")
        n = 0
        for path, v in list(_paths_of(i)):
            if not path or path in (("receipt", "receipt", "schema"), ("receipt", "receipt", "suite"),
                                    ("receipt", "receipt", "canonicalization")) or path[:4] == (
                                        "receipt", "receipt", "suite", "digest") or path[:4] == (
                                        "receipt", "receipt", "suite", "signature"):
                continue                                         # step 1 itself: already the step 1 outcome
            if path == ("receipt", "timestamp", "digest_sha256"):
                continue    # step 6: "informative and never decides the outcome" (a note; README R8, reading)
            if path[:3] == ("receipt", "receipt", "payment"):
                continue    # vector 55: a payment outside its form "changes no outcome" (a note; README R8/Q13, reading)
            for t, s in samples.items():
                if t == kind(v) or (t == "null" and (path in NULLABLE or path in OPTIONAL_NULLABLE_INPUTS)):
                    continue
                if path in NULLABLE and kind(v) == "null" and t == "str":
                    continue                                     # a party's key_id or name: a string or null
                if t == "dict" and kind(v) == "dict" or t == "list" and kind(v) == "list":
                    continue
                j = copy.deepcopy(i)
                _set(j, path, copy.deepcopy(s))
                rep = run(j)
                n += 1
                self.assertTrue(rep.get("refused"), (path, t, rep))
                self.assertEqual(rep["reason"], STEP1, (path, t, rep))
        self.assertGreater(n, 300)

    def test_vector_77(self):
        rows = score.score(files=[f for f in score.vector_files("85a310d") if "/77-" in f])
        self.assertTrue(rows[0]["agree"])
        for roots in (7, "x", {}, [7], [None], [["x"]]):             # inputs.tsa_roots_base64 and its items
            j = fixture()
            j["tsa_roots_base64"] = roots
            rep = run(j)
            self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1), roots)
        # README R8 reading / Q13: receipt.payment itself, or any of its members, of another type: vector 55's rule
        # (a note and unsupported, not the step 1 refusal of 77)
        i = fixture()
        ctl = run(i)
        for value in (7, "x", None, [], True):
            j = edit(copy.deepcopy(i), lambda r: r.__setitem__("payment", value))
            rep = run(j)
            self.assertFalse(rep.get("refused"), (value, rep))
            self.assertEqual((rep["problem_codes"], rep["verdict_recomputed"]), (ctl["problem_codes"], ctl["verdict_recomputed"]), value)
            self.assertTrue(any("receipt.payment outside the stated form" in n for n in rep["notes"]), value)


class RootsTypesBeforePkix(unittest.TestCase):
    """README, R8: the element types of inputs.tsa_roots_base64 are refused before the PKIX requirement, so the
    refusal is the step 1 outcome (exit 2) even where cryptography cannot be imported (exit 74 otherwise)."""

    def test_wrong_element_type_is_refused_without_cryptography(self):
        import json
        import subprocess
        import sys
        import tempfile
        wvp = os.path.join(score.ROOT, "war_verify.py")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        with tempfile.TemporaryDirectory() as d:
            for roots, want_rc in (([7], 2), ([build.b64(b"\x30\x00")], 74)):      # a string element needs PKIX
                f = os.path.join(d, "v.json")
                i = fixture()
                i["tsa_roots_base64"] = roots
                with open(f, "w") as fh:
                    json.dump({"inputs": i, "expected": {}}, fh)
                code = ("import sys; sys.modules['cryptography'] = None; import runpy; sys.argv = [%r, %r]; "
                        "runpy.run_path(%r, run_name='__main__')" % (wvp, f, wvp))
                p = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, env=env)
                self.assertEqual(p.returncode, want_rc, (roots, p.stdout[-300:], p.stderr[-300:]))
                if want_rc == 2:
                    self.assertEqual(json.loads(p.stdout)["report"]["reason"], STEP1)


NONCANON_EDITS = (lambda v: v[:4] + " " + v[4:], lambda v: v + "A", lambda v: v[:-1] + "!")   # always non-canonical


class Readings142(unittest.TestCase):
    """Readings where step 10 leaves the case open (README, "Profile 1.4.2: readings not fixed by the text")."""

    @classmethod
    def setUpClass(cls):
        cls.root = tp.make_ca("war-verify TEST root 1.4.2")
        cls.tsa = tp.make_tsa(cls.root)

    def signed(self, gen, b64_edit=None, anchors=True):
        i = fixture()
        d = bytes.fromhex(i["receipt"]["receipt"]["criteria"]["sha256"])
        i["criteria_tsr_base64"] = build.b64(tp.signed_tsr(tp.tstinfo(d, gen=gen), self.tsa, self.root[1]))
        if b64_edit:
            i["criteria_tsr_base64"] = b64_edit(i["criteria_tsr_base64"])
        if anchors:
            i["tsa_roots_base64"] = [build.b64(tp.der(self.root[1]))]
        return run(i)

    def test_q11_authority_check_without_usable_gentime_is_failed(self):
        ctl = self.signed("20260301000000Z")
        self.assertEqual((ctl["tsa_signature"], ctl["warning_codes"]), ({"criteria": "verified"}, []))
        for g in ("20261301000000Z", "20260301000000+0000", "20260301000000.50Z"):
            rep = self.signed(g)
            self.assertEqual((rep["tsa_signature"], rep["problem_codes"], rep["warning_codes"]),
                             ({"criteria": "failed"}, [], [UNVERIFIED]), g)
        # Q3 (the profile author's answer on tsc#4, not in the text): a non-canonical token with anchors is `failed`
        for edit_ in NONCANON_EDITS:
            rep = self.signed("20260301000000Z", edit_)
            self.assertEqual((rep["tsa_signature"], rep["problem_codes"], rep["warning_codes"]),
                             ({"criteria": "failed"}, ["CRITERIA_TIMESTAMP_MISMATCH"], [UNVERIFIED]))
        i = fixture(token=True)                                     # the record token, non-canonical, with anchors
        i["receipt_tsr_base64"] = i["receipt_tsr_base64"][:4] + " " + i["receipt_tsr_base64"][4:]
        i["tsa_roots_base64"] = [build.b64(tp.der(self.root[1]))]
        rep = run(i)
        self.assertEqual((rep["receipt_timestamp"], rep["tsa_signature"]["receipt"]), ("imprint_mismatch", "failed"))

    def test_q2_q3_non_canonical_token_with_anchors(self):
        # Q2 (cb7e8f1 vector 90): a token over other bytes; Q3 (the profile author's answer on tsc#4, not in the
        # text): without anchors `not_evaluated`; with anchors `failed` (asserted in test_q11_..., which needs PKIX)
        for edit_ in NONCANON_EDITS:
            rep = self.signed("20260301000000Z", edit_, anchors=False)
            self.assertEqual((rep["problem_codes"], rep["warning_codes"], rep["tsa_signature"]),
                             (["CRITERIA_TIMESTAMP_MISMATCH"], [UNVERIFIED], {"criteria": "not_evaluated"}))
            self.assertEqual(rep["criteria_committed_before_check"], "yes")

    def test_q8_accuracy_added_after_rounding(self):
        i = fixture()
        edit(i, lambda r: r.__setitem__("issued_utc", "2026-06-01T12:00:00.001Z") or
             r["criteria"].__setitem__("committed_at", "2026-06-01T12:00:00Z"))
        build.criteria_token(i, gen="20260601120000Z", accuracy=(None, None, 1))     # 1 microsecond
        rep = run(i)
        self.assertEqual((rep["problem_codes"], rep["criteria_committed_before_check"]), ([], "yes"))
        build.criteria_token(i, gen="20260601120000Z", accuracy=(None, 1, None))     # 1 millisecond: equal
        self.assertEqual(run(i)["criteria_committed_before_check"], "no")


class R10Tools(unittest.TestCase):
    """R10 (84, 85): two members of receipt.tools whose outcome the vectors fix; their form is closed."""

    def test_members_noted_and_closed(self):
        for m, good, bads in (("numbers_exponent_form", [1.5e-7, 2.5e21, 0], ("1", [True], [[1]], {}, None)),
                              ("keys_utf16_order", {"z": "a", "\U0001F600": "b"}, ([], {"a": 1}, {"a": None}, "x"))):
            rep = run(edit(fixture(), lambda r: r["tools"].__setitem__(m, good)))
            self.assertEqual(rep["problem_codes"], [], m)
            self.assertTrue(any(n.startswith("receipt.tools.%s not interpreted" % m) for n in rep["notes"]))
            for b in bads:
                rep = run(edit(fixture(), lambda r: r["tools"].__setitem__(m, b)))
                self.assertEqual((rep.get("refused"), rep.get("reason")), (True, STEP1), (m, b))


if __name__ == "__main__":
    unittest.main()
