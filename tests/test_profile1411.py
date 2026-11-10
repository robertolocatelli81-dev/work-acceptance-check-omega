"""Profile 1.4.11 (maximusrufus/work-acceptance-record@8ce7f42, steps 4 and 12, vectors 119-126). Oracle: the vectors, the
hand-written labels of the tables below, the 66 noncharacters as Unicode 23.7 lists them (written out here, not computed by the
verifier's test), and the sentences of the profile (README of this project, "Profile 1.4.11 rules", X1-X7); never the verifier's
own output. Positive control: run on 0.11.0 (7d9f528) the tests of X4 and X7 fail (README, "Tests"); the tests of X1-X3 and X5
pin what 0.11.0 already gave, and serve as regression tests for 119-126 and their edges."""
import base64
import copy
import json
import os
import random
import tempfile
import unittest

import _paths  # noqa: F401
import score
import test_profile147 as v
import test_profile148 as w
import war_verify as wv

SET = "8ce7f42"
UNREADABLE, RESULTS, HASH = w.UNREADABLE, w.RESULTS, w.HASH
P148 = wv.PROFILE_1_4_8
STRICT = {"criteria_noncharacters": "unreadable"}       # the other reading of Q36
NOTE = "X_CRITERIA_NOT_I_JSON"
RAW, extra, record = w.RAW, w.extra, w.record

# Unicode 15.1, 23.7: "The last two code points of each plane are noncharacters ... In addition, there is a contiguous range of
# another 32 noncharacter code points in the BMP: U+FDD0..U+FDEF."
NONCHARACTERS = sorted(set(range(0xFDD0, 0xFDF0)) | {plane * 0x10000 + low for plane in range(17) for low in (0xFFFE, 0xFFFF)})
assert len(NONCHARACTERS) == 66


def escaped(c):
    """The JSON escape of a code point: \\uXXXX, or a surrogate pair past the BMP."""
    if c < 0x10000:
        return b"\\u%04x" % c
    c -= 0x10000
    return b"\\u%04x\\u%04x" % (0xD800 + (c >> 10), 0xDC00 + (c & 0x3FF))


def nest(level, value):
    """A member `x` of the root whose value holds `value` at `level` (the member's own value is level 1)."""
    return extra(b'"x":' + b"[" * (level - 1) + value + b"]" * (level - 1))


def codes(data, opts=None, matches=True):
    rep = v.run(record(data, matches), opts)
    assert not rep.get("refused"), rep
    return sorted(c for c in rep["problem_codes"] if c.startswith("CRITERIA_") and c != "CRITERIA_TIMESTAMP_MISMATCH")


def reason(data, opts=None):
    return v.run(record(data), opts)["details"].get("criteria_unreadable")


def noted(data, opts=None, matches=True):
    return [n for n in v.run(record(data, matches), opts)["notes"] if n.startswith(NOTE)]


def num(f):
    return int(os.path.basename(f).split("-")[0])


class Vectors8ce7f42(unittest.TestCase):
    def test_127_of_127(self):
        rows = score.score(which=SET)
        self.assertEqual((len(rows), sum(r["agree"] for r in rows)), (127, 127), v.nums(rows))
        self.assertEqual((sum(r["fields_agree"] for r in rows), sum(r["fields"] for r in rows)), (1157, 1157))

    def test_the_default_set_is_8ce7f42(self):
        self.assertEqual(score.vector_files(), score.vector_files(SET))
        files = score.vector_files(SET)
        self.assertEqual(len(files), 127)
        self.assertEqual([num(f) for f in files[118:126]], list(range(119, 127)))
        self.assertTrue(all("upstream_8ce7f42" in f for f in files[118:126]))
        self.assertEqual(files[:118] + files[126:], score.vector_files("3e53aac"))

    def test_older_sets_unchanged(self):
        for which, n in (("3e53aac", 119), ("6f7a075", 116), ("c4b4bd4", 112), ("1b81ec9", 110), ("6bb7d0b", 108), ("85a310d", 88),
                         ("bc5a138", 58), ("48ab8c9", 60), ("1.4.1", 48), ("1.4", 37), ("1.3", 28)):
            rows = score.score(which=which)
            self.assertEqual((len(rows), sum(r["agree"] for r in rows)), (n, n), which)

    def test_no_outcome_of_01_to_118_changes(self):
        """The changelog of 1.4.11: the whole report under the defaults equals that under --profile 1.4.8, but `options`."""
        for f in score.vector_files("3e53aac"):
            raw = v.read(f)
            a, b = wv.run_vector_bytes(raw)[0], wv.run_vector_bytes(raw, dict(P148))[0]
            a.pop("options", None)
            b.pop("options", None)
            self.assertEqual(a, b, f)

    def test_each_reading_alone(self):
        for opts, bad in (({}, []), (dict(P148), []), ({"criteria_noncharacters": "readable"}, []),
                          ({"criteria_limits": "readable"}, ["121", "122", "123", "124", "126"]),     # X1: outside 1.4.11
                          ({"rp_point": "always"}, ["119", "120"]),                                  # X5: outside 1.4.11
                          ({"rp_point": "off"}, ["114", "115"]),
                          (dict(wv.PROFILE_1_4_7), ["117", "118", "121", "122", "123", "124", "126"]),
                          ({"criteria_read": "always"}, []), ({"criteria_shape": "absent"}, []), ({"criteria_types": "known"}, [])):
            self.assertEqual(v.nums(score.score(opts, which=SET)), bad, opts)

    def test_119_and_120(self):
        files = score.vector_files(SET)
        rep = wv.run_vector_bytes(v.read(files[118]))[0]
        self.assertEqual((rep["problem_codes"], rep["warning_codes"], rep["independence"]), ([], [], "independent"))
        self.assertNotIn("relying_party_keys", wv.strict_json_loads(v.read(files[118]))["inputs"])
        self.assertFalse(any(n.startswith("X_RP_PRODUCER_KEY_POINT_RULE") for n in rep["notes"]))
        rep = wv.run_vector_bytes(v.read(files[119]))[0]
        self.assertEqual((rep["problem_codes"], rep["warning_codes"], rep["independence"]),
                         (["INDEPENDENCE_INCONSISTENT"], ["SELF_CHECKED"], "self-checked"))
        self.assertEqual(rep["details"]["independence_derived"], "independent")
        self.assertFalse(any(n.startswith("X_RP_PRODUCER_KEY_POINT_RULE") for n in rep["notes"]))
        for f in files[118:120]:                                                   # what --rp-point always gives instead
            rep = wv.run_vector_bytes(v.read(f), {"rp_point": "always"})[0]
            self.assertEqual(rep["details"]["independence_derived"], "self-checked", f)

    def test_121_to_126(self):
        files = score.vector_files(SET)
        for n, why in ((121, "byte order mark"), (122, "integer outside the I-JSON range"), (123, "non-finite number"),
                       (124, "nesting deeper than 64"), (126, "nesting deeper than 64")):
            rep = wv.run_vector_bytes(v.read(files[n - 1]))[0]
            self.assertEqual(rep["problem_codes"], [UNREADABLE], n)
            self.assertIn(why, rep["details"]["criteria_unreadable"], n)
            self.assertEqual((rep["criteria_hash"], rep["signature_valid"], rep["accepted_as_stated"]), ("match", True, False), n)
            self.assertNotIn("criteria_results_mismatch", rep["details"], n)
        rep = wv.run_vector_bytes(v.read(files[124]))[0]
        self.assertEqual((rep["problem_codes"], rep["criteria_hash"]), ([], "match"))
        self.assertNotIn("criteria_unreadable", rep["details"])


class Noncharacters(unittest.TestCase):
    """X4, reading Q36."""

    def test_the_list(self):
        self.assertEqual(NONCHARACTERS[:2], [0xFDD0, 0xFDD1])
        self.assertEqual(NONCHARACTERS[-2:], [0x10FFFE, 0x10FFFF])
        self.assertEqual(sum(1 for c in NONCHARACTERS if c < 0x10000), 34)

    def test_each_of_the_66_escaped_in_a_value(self):
        for c in NONCHARACTERS:
            data = extra(b'"x":"a' + escaped(c) + b'b"')
            self.assertEqual(codes(data, STRICT), [UNREADABLE], hex(c))
            self.assertEqual(reason(data, STRICT), "JSON string with the noncharacter U+%04X (RFC 7493 2.1)" % c)
            self.assertEqual(codes(data), [], hex(c))
            self.assertEqual(len(noted(data)), 1, hex(c))
            self.assertIn("U+%04X " % c, noted(data)[0])
            self.assertEqual(codes(data, P148), [], hex(c))
            self.assertEqual(noted(data, P148), [], hex(c))

    def test_each_of_the_66_as_bytes_in_a_name(self):
        for c in NONCHARACTERS:
            data = extra(b'"' + chr(c).encode("utf-8") + b'":1', "item")
            self.assertEqual(codes(data, STRICT), [UNREADABLE], hex(c))
            self.assertEqual((codes(data), len(noted(data))), ([], 1), hex(c))
            self.assertEqual(codes(data, {"criteria_noncharacters": "readable"}), [], hex(c))
            self.assertEqual(noted(data, {"criteria_noncharacters": "readable"}), [], hex(c))

    def test_the_neighbours_are_characters(self):
        near = sorted({c + d for c in NONCHARACTERS for d in (-2, -1, 1, 2)} - set(NONCHARACTERS))
        near = [c for c in near if 0 <= c <= 0x10FFFF and not 0xD800 <= c <= 0xDFFF]
        self.assertEqual(len(near), 17 * 2 + 16 * 2 + 4)  # two below each plane's pair, two above it but on plane 16, and FDCE-FDF1
        for c in near:
            self.assertEqual(codes(extra(b'"x":"' + escaped(c) + b'"'), STRICT), [], hex(c))
            self.assertEqual(noted(extra(b'"x":"' + escaped(c) + b'"')), [], hex(c))

    def test_every_place(self):
        ff = "￿".encode("utf-8")
        for label, data in (("upper-case escape", extra(b'"x":"\\uFFFF"')), ("raw bytes", extra(b'"x":"' + ff + b'"')),
                            ("a pair for U+1FFFE", extra(b'"x":"\\ud83f\\udffe"')), ("a pair for U+10FFFF", extra(b'"x":"\\udbff\\udfff"')),
                            ("raw U+10FFFF", extra(b'"x":"' + "\U0010ffff".encode() + b'"')),
                            ("in a name of the root", extra(b'"\\ufdd0":1')), ("in a name of a criterion", extra(b'"\\ufdef":1', "item")),
                            ("in the id of a criterion", RAW.replace(b'"id":"c1"', b'"id":"c1\\uffff"')),
                            ("in the title of a criterion", RAW.replace(b"First required", b"\\ufffeFirst required")),
                            ("in an array of arrays", extra(b'"x":[[1,["\\ufdd5"]]]')), ("in an object in an array", extra(b'"x":[{"y":"\\ufffe"}]')),
                            ("at the end of a long string", extra(b'"x":"' + b"a" * 5000 + b'\\uffff"')),
                            ("in a name nested in objects", extra(b'"x":{"y":{"\\uffff":null}}')), ("the whole string", extra(b'"x":"\\uffff"')),
                            ("the empty name, then one", extra(b'"x":{"":"\\uffff"}'))):
            self.assertEqual(codes(data, STRICT), [UNREADABLE], label)
            self.assertIn("noncharacter", reason(data, STRICT), label)
            self.assertEqual(len(noted(data)), 1, label)

    def test_the_text_without_one(self):
        for label, data in (("a pair that is not one", extra(b'"x":"\\ud83d\\ude00"')), ("U+FEFF in a value", extra(b'"x":"\\ufeff"')),
                            ("an escaped backslash before the text", extra(b'"x":"\\\\uffff"')), ("the document", RAW),
                            ("U+FFFD", extra('"x":"�"'.encode())), ("U+FFFF written as a number", extra(b'"x":65535'))):
            self.assertEqual(codes(data, STRICT), [], label)
            self.assertEqual(noted(data), [], label)

    def test_a_hash_that_does_not_match_comes_first(self):                     # W7, Q32
        data = extra(b'"x":"\\uffff"')
        self.assertEqual(codes(data, matches=False), [HASH])
        self.assertEqual(noted(data, matches=False), [])
        self.assertEqual(codes(data, dict(STRICT, criteria_read="always"), matches=False), sorted([HASH, UNREADABLE]))
        self.assertEqual(codes(data, {"criteria_read": "always"}, matches=False), [HASH])

    def test_the_parser_comes_first(self):
        for label, data, why in (("2^53 too", extra(b'"x":["\\uffff",9007199254740992]'), "integer outside"),
                                 ("a lone surrogate too", extra(b'"x":["\\uffff","\\ud800"]'), "lone surrogate"),
                                 ("a repeated name too", extra(b'"x":"\\uffff","x":1'), "duplicate JSON member name"),
                                 ("depth 65 too", extra(b'"x":["\\uffff",' + b"[" * 64 + b"]" * 64 + b"]"), "nesting deeper than 64")):
            self.assertIn(why, reason(data), label)

    def test_a_type_after_it(self):
        data = RAW.replace(b'"id":"c1"', b'"id":1').replace(b"First required", b"\\uffffFirst required")
        self.assertIn("noncharacter", reason(data, STRICT))
        self.assertIn("is not a string", reason(data))
        self.assertIn("is not a string", reason(data, P148))

    def test_under_criteria_limits_readable(self):
        deep = extra(b'"x":' + b"[" * 300 + b'"\\uffff"' + b"]" * 300)
        self.assertEqual(codes(deep), [UNREADABLE])
        self.assertIn("nesting deeper than 64", reason(deep))
        self.assertEqual(codes(deep, dict(STRICT, criteria_limits="readable")), [UNREADABLE])
        self.assertIn("noncharacter", reason(deep, dict(STRICT, criteria_limits="readable")))
        self.assertEqual(codes(deep, {"criteria_limits": "readable"}), [])
        self.assertEqual(len(noted(deep, {"criteria_limits": "readable"})), 1)
        self.assertEqual(noted(deep), [])
        self.assertEqual(codes(deep, {"criteria_limits": "readable", "criteria_noncharacters": "readable"}), [])
        big = extra(b'"x":[9007199254740992,"\\ufdd0"]')
        self.assertIn("noncharacter", reason(big, dict(STRICT, criteria_limits="readable")))

    def test_a_document_that_is_one_string(self):
        """RFC 7493 2.1 names member names and string values in arrays and object members: a root string is not reached, and
        the document, which is no object, stays reading Q33 under every value."""
        for data in (b'"\\uffff"', '"\uffff"'.encode("utf-8")):
            for opts in (None, STRICT, {"criteria_noncharacters": "readable"}):
                self.assertEqual(codes(data, opts), [RESULTS], (data, opts))
                self.assertEqual(noted(data, opts), [], (data, opts))
        self.assertEqual(codes(b'["\\uffff"]', STRICT), [UNREADABLE])
        self.assertEqual(len(noted(b'["\\uffff"]')), 1)

    def test_every_older_profile_reads_it(self):
        data = extra(b'"x":"\\uffff"')
        for name, p in wv.PROFILES.items():
            self.assertEqual(p["criteria_noncharacters"], "readable", name)
            got = codes(data, p)
            self.assertNotIn(UNREADABLE, got, name)
            self.assertEqual(noted(data, p), [], name)
        self.assertEqual(codes(data, dict(P148, criteria_noncharacters="unreadable")), [UNREADABLE])

    def test_generated_strings(self):
        """2,000 strings of code points drawn near the noncharacters and elsewhere, as bytes or escapes, against NONCHARACTERS."""
        rng = random.Random(1411)
        pool = sorted({c + d for c in NONCHARACTERS for d in range(-3, 4)} | set(range(0x20, 0x7F)) | {0xE9, 0x4E2D, 0x1F600, 0xFEFF})
        pool = [c for c in pool if 0x20 <= c <= 0x10FFFF and not 0xD800 <= c <= 0xDFFF and c not in (0x22, 0x5C)]
        hits = 0
        for k in range(2000):
            cps = [rng.choice(pool) for _ in range(rng.randrange(1, 5))]
            body = b"".join(escaped(c) if rng.random() < 0.5 else chr(c).encode("utf-8") for c in cps)
            where = rng.randrange(3)
            data = extra(b'"x":"' + body + b'"') if where == 0 else extra(b'"' + body + b'":0', "item") if where == 1 else \
                extra(b'"x":[{"y":["' + body + b'"]}]')
            want = any(c in NONCHARACTERS for c in cps)
            hits += want
            got = wv._criteria_unreadable(data, dict(wv.DEFAULT_OPTIONS, **STRICT))
            self.assertEqual(got is not None, want, (k, cps))
            if want:
                self.assertIn("noncharacter", got)
            self.assertIsNone(wv._criteria_unreadable(data, wv.DEFAULT_OPTIONS), (k, cps))
            self.assertEqual(wv._criteria_noncharacter(data, wv.DEFAULT_OPTIONS) is not None, want, (k, cps))
        self.assertGreater(hits, 400)
        self.assertLess(hits, 1800)


class Limits(unittest.TestCase):
    """X1-X3: what 0.11.0 already gave, pinned for 1.4.11."""

    def test_every_kind_of_value_at_64_and_65(self):
        for val in (b"0", b"-1.5", b'"s"', b'""', b"null", b"true", b"false", b"[]", b"{}"):
            self.assertEqual(codes(nest(64, val)), [], (64, val))
            self.assertEqual(codes(nest(65, val)), [UNREADABLE], (65, val))
            self.assertIn("nesting deeper than 64", reason(nest(65, val)))
        for val in (b"[1]", b'{"a":1}', b'{"a":[]}'):                            # a container at 64 holds its member at 65
            self.assertEqual(codes(nest(63, val)), [], (63, val))
            self.assertEqual(codes(nest(64, val)), [UNREADABLE], (64, val))

    def test_objects_count_as_arrays(self):
        objs = lambda n, val: extra(b'"x":' + b'{"a":' * (n - 1) + val + b"}" * (n - 1))
        self.assertEqual(codes(objs(64, b"0")), [])
        self.assertEqual(codes(objs(65, b"0")), [UNREADABLE])
        mixed = lambda n: extra(b'"x":' + b'[{"a":' * ((n - 1) // 2) + b"0" + b"}]" * ((n - 1) // 2))
        self.assertEqual(codes(mixed(63)), [])
        self.assertEqual(codes(mixed(65)), [UNREADABLE])

    def test_the_level_is_from_the_root(self):
        """A criterion's member is level 3: the root (0), `criteria` (1), the criterion (2)."""
        self.assertEqual(codes(extra(b'"y":' + b"[" * 61 + b"0" + b"]" * 61, "item")), [])
        self.assertEqual(codes(extra(b'"y":' + b"[" * 62 + b"0" + b"]" * 62, "item")), [UNREADABLE])

    def test_integers(self):                                                    # X2, Q37
        for label, num_, want in (("2^53 - 1", b"9007199254740991", []), ("1 - 2^53", b"-9007199254740991", []),
                                  ("2^53", b"9007199254740992", [UNREADABLE]), ("-2^53", b"-9007199254740992", [UNREADABLE]),
                                  ("2^53 + 1", b"9007199254740993", [UNREADABLE]), ("2^64", b"18446744073709551616", [UNREADABLE]),
                                  ("2^53 with a fraction", b"9007199254740992.0", []), ("2^53 with an exponent", b"9.007199254740992e15", []),
                                  ("1e16", b"1e16", []), ("2^64 with an exponent", b"1.8446744073709552E19", []), ("-0", b"-0", []),
                                  ("an integer of 400 digits", b"1" * 400, [UNREADABLE])):
            self.assertEqual(codes(extra(b'"x":' + num_)), want, label)

    def test_overflow_and_underflow(self):                                      # X3, Q38
        for label, num_, want in (("the largest double", b"1.7976931348623157e308", []),
                                  ("just below the halfway point", b"1.7976931348623158e308", []),
                                  ("the halfway point", b"1.7976931348623159e308", [UNREADABLE]),
                                  ("1e309", b"1e309", [UNREADABLE]), ("-1e400", b"-1e400", [UNREADABLE]), ("1E+400", b"1E+400", [UNREADABLE]),
                                  ("1e-400", b"1e-400", []), ("-1e-400", b"-1e-400", []), ("the smallest subnormal", b"5e-324", []),
                                  ("half of it", b"2e-324", []), ("thirty digits of pi", b"3.141592653589793238462643383279", []),
                                  ("an exponent of 400 digits", b"1e" + b"9" * 400, [UNREADABLE]),
                                  ("a negative exponent of 400 digits", b"1e-" + b"9" * 400, [])):
            self.assertEqual(codes(extra(b'"x":' + num_)), want, label)

    def test_the_byte_order_mark(self):
        self.assertEqual(codes(b"\xef\xbb\xbf" + RAW), [UNREADABLE])
        self.assertEqual(codes(b" \xef\xbb\xbf" + RAW), [UNREADABLE])          # not at the start: not JSON
        self.assertEqual(codes(extra('"x":"﻿"'.encode())), [])             # U+FEFF inside a string is a character

    def test_criteria_limits_readable_is_outside_1_4_11(self):
        files = score.vector_files(SET)
        for n in (121, 122, 123, 124, 126):
            rep, cmp_ = wv.run_vector_bytes(v.read(files[n - 1]), {"criteria_limits": "readable"})
            self.assertFalse(cmp_["agree"], n)
            self.assertEqual(rep["problem_codes"], [], n)



# ---- generative tests over the text of step 4 (X1-X4) and step 12 (X5); every expectation below is written from the rules, before running
INT_VALUES = [-(2 ** 53 + 1), -(2 ** 53), -(2 ** 53 - 1), 2 ** 53 - 1, 2 ** 53, 2 ** 53 + 1, 10 ** 20]


def number_forms(n):
    """(form, text, is an integer by X2): the forms of the integer n."""
    sign, d = ("-" if n < 0 else ""), str(abs(n))
    e = len(d) - 1
    mant = d[0] + ("." + d[1:].rstrip("0") if d[1:].rstrip("0") else "")
    return [("integer", sign + d, True), ("fraction", sign + d + ".0", False), ("exponent e", "%s%se%d" % (sign, mant, e), False),
            ("exponent E", "%s%sE%d" % (sign, mant, e), False), ("exponent e+", "%s%se+%d" % (sign, mant, e), False)]


PLACES = [("a member of the root", lambda body: extra(b'"x":' + body)), ("a member of a criterion", lambda body: extra(b'"x":' + body, "item")),
          ("in an array 10 levels down", lambda body: extra(b'"x":' + b"[" * 9 + body + b"]" * 9)),
          ("a member of an object in an array", lambda body: extra(b'"x":[{"y":' + body + b'}]'))]


class GenerativeNumbers(unittest.TestCase):
    """X2, X3: every integer of the list in every form, at every place; overflow, underflow, negative zero."""

    def test_integers_in_every_form(self):
        n = 0
        for value in INT_VALUES:
            for form, txt, integer in number_forms(value):
                self.assertEqual(float(txt), float(value), txt)                  # the form writes the value
                want = [UNREADABLE] if integer and abs(value) > 2 ** 53 - 1 else []   # X2: only the integer form; Q37
                for place, put in PLACES:
                    data = put(txt.encode())
                    self.assertEqual(codes(data), want, (txt, place))
                    if want:
                        self.assertIn("integer outside the I-JSON range", reason(data), txt)
                    n += 1
        self.assertEqual(n, 7 * 5 * 4)

    def test_negative_zero(self):
        for txt in (b"-0", b"-0.0", b"-0e0", b"-0E+0", b"-0e-0", b"-0.000e5"):
            for place, put in PLACES:
                self.assertEqual(codes(put(txt)), [], (txt, place))

    def test_overflow(self):                                                     # X3
        for txt in (b"1e309", b"-1e309", b"1E400", b"1e+400", b"-1E+400", b"1.7976931348623159e308", b"179769313486231590" + b"0" * 291 + b".0"):
            for place, put in PLACES:
                data = put(txt)
                self.assertEqual(codes(data), [UNREADABLE], (txt, place))
                self.assertIn("non-finite number", reason(data), txt)

    def test_underflow(self):                                                    # X3, Q38: no overflow, readable
        for txt in (b"1e-400", b"-1e-400", b"4.9e-324", b"2.4e-324", b"2.5e-324", b"1E-400", b"0.0000000000000000000000001e-310"):
            for place, put in PLACES:
                self.assertEqual(codes(put(txt)), [], (txt, place))


class GenerativeByteOrderMark(unittest.TestCase):
    """X1 (121): a byte order mark at the start; elsewhere it is a character in a string, or text outside the grammar."""

    BOM = b"\xef\xbb\xbf"

    def test_at_the_start(self):
        for data in (self.BOM + RAW, self.BOM + self.BOM + RAW, self.BOM + b" " + RAW, self.BOM + b"[]", self.BOM + b"{}"):
            self.assertEqual(codes(data), [UNREADABLE], data[:8])
            self.assertIn("byte order mark", reason(data))

    def test_inside_a_string_it_is_a_character(self):
        for data in (extra(b'"x":"' + self.BOM + b'"'), extra(b'"x":"a' + self.BOM + b'b"'), extra(b'"' + self.BOM + b'":1'),
                     extra(b'"x":"\\ufeff"'), extra(b'"x":"' + self.BOM + b'"', "item"), RAW.replace(b"First required", self.BOM + b"First required")):
            self.assertEqual(codes(data), [], data[-40:])

    def test_between_tokens_it_is_not_json(self):
        for data in (b" " + self.BOM + RAW, RAW[:1] + self.BOM + RAW[1:], RAW + self.BOM, extra(b'"x":' + self.BOM + b"1")):
            self.assertEqual(codes(data), [UNREADABLE], data[:12])
            self.assertIn("not JSON", reason(data))


VALUES = [("a number", b"0"), ("a string", b'"s"'), ("true", b"true"), ("null", b"null"), ("an empty array", b"[]"),
          ("an empty object", b"{}"), ("an object with a member", b'{"a":0}')]


class GenerativeDepth(unittest.TestCase):
    """X1 (124-126): the deepest value, at 63, 64, 65 and 200, of every kind, through arrays or members, under the root or a criterion."""

    def depth_doc(self, level, value, wrap, where):
        start = 1 if where == "root" else 3                                        # the root's member is level 1; a criterion's member, 3
        n = level - start
        if wrap == "arrays":
            body = b"[" * n + value + b"]" * n
        else:
            body = b'{"a":' * n + value + b"}" * n
        return extra(b'"x":' + body, "top" if where == "root" else "item")

    def test_the_grid(self):
        n = 0
        for level in (63, 64, 65, 200):
            for label, value in VALUES:
                deepest = level + (1 if value == b'{"a":0}' else 0)
                want = [UNREADABLE] if deepest > 64 else []
                for wrap in ("arrays", "members"):
                    for where in ("root", "criterion"):
                        data = self.depth_doc(level, value, wrap, where)
                        self.assertEqual(codes(data), want, (level, label, wrap, where))
                        if want:
                            self.assertIn("nesting deeper than 64", reason(data))
                        n += 1
        self.assertEqual(n, 4 * 7 * 2 * 2)

    def test_100000_levels(self):
        """No RecursionError and no crash: CRITERIA_UNREADABLE under every value of the switches that read the file."""
        for wrap in ("arrays", "members"):
            for where in ("root", "criterion"):
                data = self.depth_doc(100000, b"0", wrap, where)
                for opts in (None, {"criteria_limits": "readable"}, dict(P148), {"criteria_limits": "readable", "criteria_noncharacters": "readable"},
                             {"criteria_read": "always"}, {"criteria_shape": "absent", "criteria_types": "known"}):
                    rep = v.run(record(data), opts)
                    self.assertFalse(rep.get("refused"), (wrap, where, opts))
                    self.assertEqual([c for c in rep["problem_codes"] if c.startswith("CRITERIA_") and "TIMESTAMP" not in c], [UNREADABLE],
                                     (wrap, where, opts))
                    self.assertTrue(rep["details"]["criteria_unreadable"], (wrap, where, opts))
                rep = v.run(record(data), dict(wv.PROFILE_1_4_7))                    # 0.10.0's reading: the results correspond to nothing read
                self.assertEqual([c for c in rep["problem_codes"] if c.startswith("CRITERIA_") and "TIMESTAMP" not in c], [RESULTS])


# ---- X5, Q31: the product of every input step 12 names; expected outcome from the text, before running
PRODUCER_KEYS = [("a key of prime order", "K2", False), ("the neutral point", "NEUTRAL", True), ("a point of order 8", "ORDER8", True),
                 ("y = p, not canonical", "YP", True), ("no entry in keys", None, False)]
RP_LISTS = [("no list", None), ("a list that holds the producer's bytes", "holds"), ("a list of another key only", "other")]
CLAIMS = ("independent", "self-checked")
PRODUCERS = [("Example Vendor", "named"), (None, "undeclared")]
KEY_IDS = ("stated", "not stated")


def q31_expected(rp, claim, producer, key, key_id):
    """Step 8 (T2, T5) and step 12 (U3, V3, X5) as written: derived independence, rule applied."""
    _label, pub, fails = key
    applied = rp is not None and claim == "independent" and key_id == "stated"          # X5: "only under the conditions above"
    if producer == "undeclared":
        return "undeclared", applied                                                  # T2, Q29
    if key_id == "stated" and pub is None and claim == "independent":
        return "self-checked", applied                                                # T5: not listed, under the independent claim
    if applied and (rp == "other" or pub is None or fails):
        return "self-checked", applied                                                # U5 not held; V3 point rule
    return "independent", applied


def q31_record(rp, claim, pname, key, key_id):
    _label, pub, _fails = key
    pubs = {"K2": v.K2, "NEUTRAL": v.NEUTRAL, "ORDER8": v.b64(bytes.fromhex(v.TORSION[4][1])), "YP": v.b64(bytes.fromhex(v.NONCANONICAL[2][1]))}
    lst = None if rp is None else [v.entry("p", pubs[pub] if pub else v.K2)] if rp == "holds" else [v.entry("q", v.K3)]
    i = v.record(claim, pname, pubs.get(pub, v.K2), lst, pk=v.PRODUCER if key_id == "stated" else v.u.MISSING)
    if pub is None:
        del i["keys"]["keys"][1]
    return i


class Q31Product(unittest.TestCase):
    def table(self):
        import itertools
        return itertools.product(RP_LISTS, CLAIMS, PRODUCERS, PRODUCER_KEYS, KEY_IDS)

    def test_the_product(self):
        n = 0
        for (rl, rp), claim, (pname, producer), key, key_id in self.table():
            where = (rl, claim, producer, key[0], key_id)
            rep = v.run(q31_record(rp, claim, pname, key, key_id))
            self.assertFalse(rep.get("refused"), (where, rep))
            derived, applied = q31_expected(rp, claim, producer, key, key_id)
            self.assertEqual(rep["details"]["independence_derived"], derived, where)
            self.assertEqual((rep["independence"], v.X in rep["problem_codes"]), (claim, derived != claim), where)
            self.assertEqual(v.POINT in rep["extension_codes"], applied and key[2], where)
            self.assertEqual(v.NOT_APPLIED in rep["extension_codes"], rp is not None and not applied, where)
            self.assertEqual("SELF_CHECKED" in rep["warning_codes"], claim == "self-checked", where)
            self.assertEqual("PRODUCER_UNDECLARED" in rep["warning_codes"], producer == "undeclared", where)
            self.assertNotIn("KEY_REJECTED", rep["problem_codes"], where)
            self.assertTrue(rep["signature_valid"], where)
            n += 1
        self.assertEqual(n, 3 * 2 * 2 * 5 * 2)

    def test_the_other_readings_of_the_rule_differ(self):
        """--rp-point always runs the rule outside the conditions (outside 1.4.11, X5); off is the 0.9.0 reading."""
        always = off = 0
        for (rl, rp), claim, (pname, producer), key, key_id in self.table():
            i = q31_record(rp, claim, pname, key, key_id)
            base = v.run(i)["details"]["independence_derived"]
            always += v.run(i, {"rp_point": "always"})["details"]["independence_derived"] != base
            off += v.run(i, {"rp_point": "off"})["details"]["independence_derived"] != base
        self.assertGreater(always, 0)
        self.assertGreater(off, 0)


# ---- closure by construction on the criteria file: every input reaches a stated outcome with a reason
CRIT = ("CRITERIA_UNREADABLE", "CRITERIA_RESULTS_MISMATCH", "CRITERIA_HASH_MISMATCH")


class ClosedCriteriaFile(unittest.TestCase):
    def closed(self, data, opts=None, label=""):
        """No exception; one outcome; a reason for each code; a readable document's members named in the notes."""
        try:
            rep = wv.verify(copy.deepcopy(record(data)), dict(opts) if opts else None)
        except Exception as e:                                                     # a refusal of the record would be a defect here too
            self.fail("%s: %s %s" % (label, type(e).__name__, e))
        got = [c for c in rep["problem_codes"] if c in CRIT]
        self.assertLessEqual(len(got), 1, label)
        if got == [UNREADABLE]:
            self.assertTrue(isinstance(rep["details"].get("criteria_unreadable"), str) and rep["details"]["criteria_unreadable"], label)
        elif got == [RESULTS]:
            self.assertTrue(rep["details"].get("criteria_results_mismatch"), label)
        else:
            self.assertEqual(got, [], label)
            doc = json.loads(data[3:] if data[:3] == b"\xef\xbb\xbf" else data, parse_int=lambda _s: 0)   # --criteria-limits readable
            for m in sorted(set(doc) - {"criteria"}):
                self.assertTrue(any(repr(m) in n for n in rep["notes"]), (label, m))
            for k, c in enumerate(doc["criteria"]):
                for m in sorted(set(c) - {"id", "required", "title"}):
                    self.assertTrue(any("criteria[%d].%s" % (k, m) in n for n in rep["notes"]), (label, m))
        return got

    OPTS = [None, {"criteria_limits": "readable"}, {"criteria_shape": "absent"}, {"criteria_types": "known"}, dict(P148),
            {"criteria_noncharacters": "readable", "criteria_limits": "readable", "criteria_types": "known", "criteria_shape": "absent"}]

    def test_new_members_at_every_level(self):
        for name in (b"zz", b"ID", b"id ", b"Required", b"criteria_", b"\\u00e9", b"", b"criteria_set2"):
            for data in (extra(b'"' + name + b'":1'), extra(b'"' + name + b'":{"q":[1,{"r":null}]}', "item"),
                         extra(b'"x":{"' + name + b'":{"' + name + b'x":1}}'), extra(b'"x":[{"' + name + b'":true}]', "item")):
                for opts in self.OPTS:
                    self.assertEqual(self.closed(data, opts, (name, opts)), [], (name, opts))

    def test_repeated_members_at_every_level(self):
        doc = json.loads(RAW)
        for m in sorted(doc):                                                        # each member of the root, twice
            data = RAW[:-1] + b',"' + m.encode() + b'":' + json.dumps(doc[m]).encode() + b"}"
            for opts in self.OPTS:
                self.assertEqual(self.closed(data, opts, m), [UNREADABLE], (m, opts))
        for m in sorted(doc["criteria"][0]):                                          # each member of a criterion, twice
            data = extra(b'"' + m.encode() + b'":' + json.dumps(doc["criteria"][0][m]).encode(), "item")
            self.assertEqual(self.closed(data, None, m), [UNREADABLE], m)
        for depth in range(1, 60, 7):
            data = extra(b'"x":' + b"[" * depth + b'{"a":1,"a":1}' + b"]" * depth)
            self.assertEqual(self.closed(data, None, depth), [UNREADABLE], depth)

    def test_wrong_types_for_every_known_member(self):
        others = [b"null", b"0", b"1.5", b'"s"', b"true", b"[]", b"{}"]
        read = {("top", "criteria"): b"[]", ("item", "id"): b'"s"', ("item", "required"): b"true"}
        known = {("top", "criteria_set"): b'"s"', ("top", "title"): b'"s"', ("top", "version"): b'"s"', ("top", "result_vocabulary"): b"[]",
                 ("item", "title"): b'"s"', ("item", "requirement"): b'"s"'}
        doc = json.loads(RAW)
        for (where, m), good in sorted({**read, **known}.items()):
            for val in others:
                if val == good:
                    continue
                if where == "top":
                    d = dict(doc, **{m: json.loads(val)})
                else:
                    d = copy.deepcopy(doc)
                    d["criteria"][0][m] = json.loads(val)
                data = json.dumps(d).encode()
                want = [UNREADABLE] if (where, m) in read else []                    # W6; the others: Q34
                self.assertEqual(self.closed(data, None, (m, val)), want, (m, val))
                if not want:
                    self.assertEqual(self.closed(data, {"criteria_types": "known"}, (m, val)), [UNREADABLE], (m, val))

    def test_encodings(self):
        text = RAW.decode()
        for label, data in (("UTF-16 LE with a BOM", b"\xff\xfe" + text.encode("utf-16-le")), ("UTF-16 BE with a BOM", b"\xfe\xff" + text.encode("utf-16-be")),
                            ("UTF-16 LE", text.encode("utf-16-le")), ("UTF-32", text.encode("utf-32")), ("Latin-1", text.replace("first", "f\xefrst").encode("latin-1")),
                            ("CESU-8 pair", RAW.replace(b"The first", b"The \xed\xa0\xbd\xed\xb8\x80first")), ("lone surrogate escape", extra(b'"x":"\\udc00"')),
                            ("a pair escaped", extra(b'"x":"\\ud83d\\ude00"')), ("a pair as UTF-8", extra('"x":"\U0001f600"'.encode()))):
            want = [] if label.startswith("a pair") else [UNREADABLE]
            for opts in self.OPTS:
                self.assertEqual(self.closed(data, opts, label), want, (label, opts))

    def test_outside_the_grammar(self):
        for label, data in (("trailing comma", RAW[:-1] + b",}"), ("comment", RAW + b"//c"), ("block comment", b"/**/" + RAW), ("NaN", extra(b'"x":NaN')),
                            ("single quotes", RAW.replace(b'"version"', b"'version'")), ("leading zero", extra(b'"x":007')), ("-01", extra(b'"x":-01')),
                            ("Infinity", extra(b'"x":Infinity')), ("unquoted", extra(b"x:1")), ("tab in a string", extra(b'"x":"\t"')),
                            ("empty", b""), ("only a BOM", b"\xef\xbb\xbf")):
            for opts in self.OPTS:
                self.assertEqual(self.closed(data, opts, label), [UNREADABLE], (label, opts))

    def test_the_table_of_1_4_8_and_the_generated_documents(self):
        for label, data, want, fam in w.table():
            for opts in self.OPTS:
                self.closed(data, opts, label)
        for k, data in enumerate(w.generated(1411, 400)):
            self.closed(data, None, k)

class Profiles(unittest.TestCase):
    def test_the_values(self):
        self.assertEqual(sorted(wv.PROFILES), ["1.2.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.7", "1.4.8"])
        self.assertEqual(P148, {"criteria_noncharacters": "readable"})
        self.assertEqual(wv.PROFILE_1_4_7, {"criteria_noncharacters": "readable", "sig_r": "not-small", "criteria_unreadable": "mismatch"})
        self.assertEqual(wv.DEFAULT_OPTIONS["criteria_noncharacters"], "report")
        self.assertEqual(wv.OPTION_VALUES["criteria_noncharacters"], ("report", "unreadable", "readable"))
        self.assertEqual((wv.DEFAULT_OPTIONS["criteria_limits"], wv.DEFAULT_OPTIONS["rp_point"]), ("unreadable", "step12"))

    def test_version(self):
        self.assertEqual(wv.VERSION, "war_verify 0.12.0")
        self.assertIn("draft profile 1.4.11", wv.__doc__.splitlines()[0])


class CommandLine(unittest.TestCase):
    run_cli = v.CommandLine.run_cli

    def setUp(self):
        self.files = score.vector_files(SET)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_the_vectors(self):
        for n in range(119, 127):
            self.assertEqual(self.run_cli("--vector", self.files[n - 1])[0], 0, n)
            self.assertEqual(self.run_cli("--vector", "--profile", "1.4.8", self.files[n - 1])[0], 0, n)
        for n in (121, 122, 123, 124, 126):
            self.assertEqual(self.run_cli("--vector", "--criteria-limits", "readable", self.files[n - 1])[0], 3, n)
        for n in (119, 120):
            self.assertEqual(self.run_cli("--vector", "--rp-point", "always", self.files[n - 1])[0], 3, n)

    def report(self, doc, *args):
        g = os.path.join(self.tmp.name, "r.json")
        with open(g, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return json.loads(self.run_cli(*args, g)[1])["report"]

    def test_the_switch_and_the_profile(self):
        doc = record(extra(b'"x":"\\uffff"'))
        crit = lambda *a: sorted(c for c in self.report(doc, *a)["problem_codes"] if c.startswith("CRITERIA_") and "TIMESTAMP" not in c)
        self.assertEqual(crit(), [])
        self.assertEqual(sum(n.startswith(NOTE) for n in self.report(doc)["notes"]), 1)
        self.assertEqual(sum(n.startswith(NOTE) for n in self.report(doc, "--profile", "1.4.8")["notes"]), 0)
        self.assertEqual(crit("--criteria-noncharacters", "unreadable"), [UNREADABLE])
        self.assertEqual(crit("--criteria-noncharacters", "report"), [])
        self.assertEqual(crit("--criteria-noncharacters", "readable"), [])
        self.assertEqual(crit("--profile", "1.4.8"), [])
        self.assertEqual(crit("--profile", "1.4.8", "--criteria-noncharacters", "unreadable"), [UNREADABLE])
        self.assertEqual(crit("--profile", "1.4.7"), [])
        self.assertEqual(self.report(doc, "--profile", "1.4.8")["options"]["criteria_noncharacters"], "readable")

    def test_usage_errors(self):
        f = self.files[120]
        for args in (("--criteria-noncharacters", "bogus"), ("--criteria-noncharacters", ""), ("--criteria-noncharacters", "Report"),
                     ("--criteria-noncharacters", "readable", "--criteria-noncharacters", "readable"),
                     ("--criteria-noncharacters=readable",), ("--profile", "1.4.11"), ("--profile", "1.4.9"), ("--profile", "1.4.10"),
                     ("--profile", "1.4.8", "--profile", "1.4.8")):
            self.assertEqual(self.run_cli(*args, f)[0], 64, args)
        self.assertEqual(self.run_cli("--criteria-noncharacters")[0], 64)
        self.assertIn("1.4.8, 1.4.7, 1.4.5", self.run_cli("--profile", "1.4.11", f)[2])

    def test_usage_text(self):
        rc, out, _ = self.run_cli("--help")
        self.assertEqual(rc, 0)
        for words in ("--criteria-noncharacters report|unreadable|readable   (default report)", "defaults follow profile 1.4.11",
                      "  --profile 1.4.8              the reading 0.11.0 gave to 1.4.8"):
            self.assertIn(words, out)


if __name__ == "__main__":
    unittest.main()
