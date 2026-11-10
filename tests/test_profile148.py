"""Profile 1.4.8 (maximusrufus/work-acceptance-record@3e53aac, steps 2, 4 and 8, vectors 116-118). Oracle: the vectors, the
hand-written labels of the tables below, and for the generated documents a JSON reader written in this file, which uses neither
the module `json` nor a line of war_verify.py; the Edwards arithmetic is that of tests/test_profile147.py. Expectations come from
the sentences of the profile (README of this project, "Profile 1.4.8 rules", W1-W8), never from running the verifier. Positive
control: run on 0.10.0 (70d2df7), these tests fail (README, "Tests")."""
import base64
import copy
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import unittest

import _paths  # noqa: F401
import build
import score
import test_profile147 as v
import war_verify as wv

SET = "3e53aac"
UNREADABLE, RESULTS, HASH, SIG = "CRITERIA_UNREADABLE", "CRITERIA_RESULTS_MISMATCH", "CRITERIA_HASH_MISMATCH", "SIGNATURE_INVALID"
P147 = wv.PROFILE_1_4_7
BASE = build.base()
RAW = base64.b64decode(BASE["criteria_file_base64"])
DOC = wv.strict_json_loads(RAW)
assert [c["id"] for c in DOC["criteria"]] == ["c1", "c2", "c3"]
FL, ZERO, add, mul, dec, enc = v.FL, v.ZERO, v.add, v.mul, v.dec, v.enc
BASEPOINT = dec((4 * pow(5, -1, v.FP) % v.FP).to_bytes(32, "little"))


def doc_with(**members):
    d = copy.deepcopy(DOC)
    d.update(members)
    return d


def crit_with(index=0, drop=(), **members):
    d = copy.deepcopy(DOC)
    d["criteria"][index].update(members)
    for m in drop:
        del d["criteria"][index][m]
    return d


def text(d):
    return json.dumps(d, ensure_ascii=True).encode()


def extra(body, into="top"):
    """The base document with the raw JSON text `body` spliced in as members; the rest stays as it was."""
    if into == "top":
        return RAW[:1] + body + b"," + RAW[1:]
    i = RAW.index(b'{"id":"c1"')
    return RAW[:i + 1] + body + b"," + RAW[i + 1:]


def record(data, matches=True):
    i = copy.deepcopy(BASE)
    i["criteria_file_base64"] = base64.b64encode(data).decode()
    if matches:
        i["receipt"]["receipt"]["criteria"]["sha256"] = hashlib.sha256(data).hexdigest()
        build.criteria_token(i)
    else:
        i["receipt"]["receipt"]["criteria"]["sha256"] = hashlib.sha256(b"another document").hexdigest()
    build.refresh(i)
    return i


# ---- the table: (label, bytes, expected under the defaults: "unreadable", "mismatch" or "ok", family), by hand
def table():
    rows = []

    def row(label, data, want, fam):
        rows.append((label, data, want, fam))

    for label, b in (("latin-1 byte in a string", RAW.replace(b"The first", b"The f\xefrst")),
                     ("overlong encoding of a slash", RAW.replace(b"The first", b"The \xc0\xaffirst")),
                     ("surrogate as bytes (CESU-8)", RAW.replace(b"The first", b"The \xed\xa0\x80first")),
                     ("truncated sequence at the end of a string", RAW.replace(b'first requirement."', b'first requirement.\xe2\x82"')),
                     ("code point past U+10FFFF", RAW.replace(b"The first", b"The \xf4\x90\x80\x80first")),
                     ("UTF-16 with a byte order mark", b"\xff\xfe" + RAW.decode().encode("utf-16-le")),
                     ("UTF-16 without one", RAW.decode().encode("utf-16-be")),
                     ("0xff alone", b"\xff")):
        row(label, b, "unreadable", "not UTF-8")
    for label, b in (("empty", b""), ("white space only", b" \n\t"), ("trailing text", RAW + b"x"), ("two values", RAW + b" " + RAW),
                     ("trailing comma in the object", RAW[:-1] + b",}"), ("trailing comma in an array", RAW.replace(b'"error"]', b'"error",]')),
                     ("single quotes", RAW.replace(b'"version"', b"'version'")), ("comment", b"/* c */" + RAW),
                     ("name without quotes", RAW.replace(b'"version"', b"version")), ("leading zero", extra(b'"x":01')),
                     ("leading plus", extra(b'"x":+1')), ("hexadecimal number", extra(b'"x":0x10')), ("bare fraction", extra(b'"x":.5')),
                     ("no digit after the point", extra(b'"x":1.')), ("no digit in the exponent", extra(b'"x":1e')),
                     ("raw line feed in a string", RAW.replace(b"The first", b"The\nfirst")), ("raw NUL in a string", RAW.replace(b"The first", b"The\x00first")),
                     ("unknown escape", RAW.replace(b"The first", b"The\\xfirst")), ("short unicode escape", RAW.replace(b"The first", b"The\\u12first")),
                     ("not hexadecimal in an escape", RAW.replace(b"The first", b"The\\u12G4first")), ("unterminated string", RAW[:40]),
                     ("unterminated object", RAW[:-1]), ("lower-case nan", extra(b'"x":nan')), ("lower-case infinity", extra(b'"x":infinity')),
                     ("True", extra(b'"x":True')), ("None", extra(b'"x":None'))):
        row(label, b, "unreadable", "not JSON")
    for label, tok in (("NaN", b"NaN"), ("Infinity", b"Infinity"), ("-Infinity", b"-Infinity")):
        row(label + " at the top", extra(b'"x":' + tok), "unreadable", "NaN or Infinity")
        row(label + " in a criterion", extra(b'"x":' + tok, "item"), "unreadable", "NaN or Infinity")
        row(label + " in an array", extra(b'"x":[1,[' + tok + b"]]"), "unreadable", "NaN or Infinity")
        row(label + " as the document", tok, "unreadable", "NaN or Infinity")
    for label, b in (("top, two values", extra(b'"x":1,"x":2')), ("top, one value twice", extra(b'"x":1,"x":1')),
                     ("top, three times", extra(b'"x":1,"x":1,"x":1')), ("the member criteria_set", extra(b'"criteria_set":"other"')),
                     ("the member criteria itself", extra(b'"criteria":[]')), ("in a criterion", extra(b'"y":1,"y":2', "item")),
                     ("id in a criterion", extra(b'"id":"c9"', "item")), ("required in a criterion", extra(b'"required":false', "item")),
                     ("in a nested object", extra(b'"x":{"a":{"b":1,"b":2}}')), ("in an object in an array", extra(b'"x":[1,{"a":1,"a":2}]')),
                     ("in an array in an array", extra(b'"x":[[[{"a":1,"a":2}]]]')), ("after an escape", extra(b'"x":{"a":1,"\\u0061":2}')),
                     ("upper-case hex in the escape", extra(b'"x":{"J":1,"\\u004A":2}')), ("two escapes of one name", extra(b'"x":{"\\u0061":1,"\\u0061":2}')),
                     ("escape of a non-ASCII name", extra('"x":{"é":1,"\\u00e9":2}'.encode())),
                     ("pair against the character", extra('"x":{"\U0001f600":1,"\\ud83d\\ude00":2}'.encode())),
                     ("short escape against the character", extra(b'"x":{"\\n":1,"\\u000a":2}')), ("slash and its escape", extra(b'"x":{"/":1,"\\/":2}')),
                     ("the empty name", extra(b'"x":{"":1,"":2}'))):
        row(label, b, "unreadable", "repeated name")
    for label, b in (("two cases of a letter", extra(b'"x":{"a":1,"A":2}')), ("NFC against NFD", extra('"x":{"é":1,"é":2}'.encode())),
                     ("sibling objects", extra(b'"x":[{"a":1},{"a":2}]')), ("two levels", extra(b'"a":{"a":{"a":1}}')),
                     ("equal values in an array", extra(b'"x":["a","a",1,1]')), ("a name equal to a value", extra(b'"x":"x"')),
                     ("trailing space in a name", extra(b'"x":{"a":1,"a ":2}'))):
        row(label, b, "ok", "no repeated name")
    two_ids = doc_with(criteria=DOC["criteria"] + [DOC["criteria"][0]])
    row("two criteria with one id", text(two_ids), "mismatch", "no repeated name")
    for label, esc in (("high", b"\\ud800"), ("low", b"\\udc00"), ("last high", b"\\udbff"), ("last low", b"\\udfff"), ("upper-case hex", b"\\uD800"),
                       ("high before a letter", b"\\ud800a"), ("high before an escape of a letter", b"\\ud800\\u0041"),
                       ("two highs", b"\\ud800\\ud800"), ("two lows", b"\\udc00\\udc00"), ("reversed pair", b"\\ude00\\ud83d"),
                       ("high after a pair", b"\\ud83d\\ude00\\ud83d")):
        row(label + " in a value", extra(b'"x":"a' + esc + b'"'), "unreadable", "lone surrogate")
        row(label + " in a name", extra(b'"a' + esc + b'":1'), "unreadable", "lone surrogate")
    for label, b in (("in a read id", RAW.replace(b'"id":"c1"', b'"id":"c1\\ud800"')), ("in a criterion title", RAW.replace(b"First required", b"\\ud800First required")),
                     ("in an array", extra(b'"x":["\\ud800"]')), ("in a nested name", extra(b'"x":[{"y":{"\\udc00":1}}]')), ("in a criterion member", extra(b'"\\udc00":1', "item"))):
        row(label, b, "unreadable", "lone surrogate")
    for label, esc in (("pair", b"\\ud83d\\ude00"), ("pair, upper-case hex", b"\\uD83D\\uDE00"), ("first pair", b"\\ud800\\udc00"), ("the last pair that holds no noncharacter, U+10FFFD", b"\\udbff\\udffd"),
                       ("an escaped backslash before the text", b"\\\\ud800"), ("U+FFFD", b"\\ufffd"), ("U+0000", b"\\u0000"), ("U+D7FF", b"\\ud7ff"), ("U+E000", b"\\ue000")):
        row(label + " in a value", extra(b'"x":"a' + esc + b'"'), "ok", "no lone surrogate")
        row(label + " in a name", extra(b'"a' + esc + b'":1'), "ok", "no lone surrogate")
    row("a character past the BMP as bytes", extra('"x":"\U0001f600"'.encode()), "ok", "no lone surrogate")
    others = (("null", None), ("a number", 5), ("a string", "x"), ("true", True), ("false", False), ("an array", []), ("an object", {}))
    for label, val in others:
        if label != "an array":
            row("criteria is " + label, text(doc_with(criteria=val)), "unreadable", "wrongly typed")
        if label != "an object":
            row("an element of criteria is " + label, text(doc_with(criteria=DOC["criteria"] + [val])), "unreadable", "wrongly typed")
            row("the first element of criteria is " + label, text(doc_with(criteria=[val] + DOC["criteria"])), "unreadable", "wrongly typed")
        if label != "a string":
            for index in (0, 2):
                row("id of criterion %d is %s" % (index, label), text(crit_with(index, id=val)), "unreadable", "wrongly typed")
        if label not in ("true", "false"):
            for index in (0, 2):
                row("required of criterion %d is %s" % (index, label), text(crit_with(index, required=val)), "unreadable", "wrongly typed")
    row("required is 1", text(crit_with(0, required=1)), "unreadable", "wrongly typed")
    row("required is the string true", text(crit_with(0, required="true")), "unreadable", "wrongly typed")
    for label, val in (("an array", []), ("a number", 0), ("a string", "criteria"), ("true", True), ("null", None)):
        row("the document is " + label, text(val), "mismatch", "absent")
    without = copy.deepcopy(DOC)
    del without["criteria"]
    row("no member criteria", text(without), "mismatch", "absent")
    row("an empty object", b"{}", "mismatch", "absent")
    row("no id", text(crit_with(0, drop=("id",))), "mismatch", "absent")
    row("no required", text(crit_with(1, drop=("required",))), "mismatch", "absent")
    row("an empty list of criteria", text(doc_with(criteria=[])), "mismatch", "readable")
    row("a criterion with no result", text(doc_with(criteria=DOC["criteria"] + [dict(DOC["criteria"][0], id="c9")])), "mismatch", "readable")
    row("required differs", text(crit_with(0, required=False)), "mismatch", "readable")
    row("the document itself", RAW, "ok", "readable")
    row("white space around it", b" \r\n\t" + RAW + b"\n ", "ok", "readable")
    for label, d in (("criteria_set is a number", doc_with(criteria_set=1)), ("title is null", doc_with(title=None)), ("version is a number", doc_with(version=1)),
                     ("result_vocabulary is a string", doc_with(result_vocabulary="pass")), ("result_vocabulary holds a number", doc_with(result_vocabulary=["pass", 1])),
                     ("a criterion title is a number", crit_with(1, title=1)), ("a requirement is an array", crit_with(2, requirement=[]))):
        row(label, text(d), "ok", "other member")
    nest = lambda n: b"[" * n + b"]" * n
    for label, b in (("a byte order mark", b"\xef\xbb\xbf" + RAW), ("the integer 2^53", extra(b'"x":9007199254740992')), ("the integer -2^53", extra(b'"x":-9007199254740992')),
                     ("an integer of 5,000 digits", extra(b'"x":' + b"9" * 5000)), ("1e400", extra(b'"x":1e400')), ("-1e400", extra(b'"x":-1e400')),
                     ("1E99999 in a criterion", extra(b'"x":1E99999', "item")), ("depth 65", extra(b'"x":' + nest(65))), ("depth 500", extra(b'"x":' + nest(500)))):
        row(label, b, "unreadable", "limit")
    for label, b in (("the integer 2^53 - 1", extra(b'"x":9007199254740991')), ("the integer 1 - 2^53", extra(b'"x":-9007199254740991')), ("1e308", extra(b'"x":1e308')),
                     ("1e-400", extra(b'"x":1e-400')), ("depth 64", extra(b'"x":' + nest(64))), ("-0", extra(b'"x":-0')), ("1.0", extra(b'"x":1.0'))):
        row(label, b, "ok", "within the limits")
    return rows


# ---- a JSON reader of this file: RFC 8259 on the text, escapes kept as UTF-16 code units until a string ends
class Bad(Exception):
    pass


NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?")
ESCAPES = {'"': 0x22, "\\": 0x5C, "/": 0x2F, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9}


def ws(s, i):
    while i < len(s) and s[i] in " \t\n\r":
        i += 1
    return i


def string(s, i):
    units, i = [], i + 1
    while True:
        if i >= len(s):
            raise Bad("syntax")
        c = s[i]
        if c == '"':
            break
        if ord(c) < 0x20:
            raise Bad("syntax")
        if c == "\\":
            e = s[i + 1:i + 2]
            if e == "u":
                h = s[i + 2:i + 6]
                if len(h) != 4 or any(x not in "0123456789abcdefABCDEF" for x in h):
                    raise Bad("syntax")
                units.append(int(h, 16))
                i += 6
                continue
            if e not in ESCAPES or e == "":
                raise Bad("syntax")
            units.append(ESCAPES[e])
            i += 2
            continue
        units.append(ord(c))
        i += 1
    out, k = [], 0
    while k < len(units):
        u = units[k]
        if 0xD800 <= u < 0xDC00 and k + 1 < len(units) and 0xDC00 <= units[k + 1] < 0xE000:
            out.append(0x10000 + ((u - 0xD800) << 10) + (units[k + 1] - 0xDC00))
            k += 2
            continue
        if 0xD800 <= u < 0xE000:
            raise Bad("surrogate")
        out.append(u)
        k += 1
    return "".join(map(chr, out)), i + 1


def value(s, i):
    i = ws(s, i)
    c = s[i:i + 1]
    if c == "{":
        obj, i = {}, ws(s, i + 1)
        if s[i:i + 1] == "}":
            return obj, i + 1
        while True:
            i = ws(s, i)
            if s[i:i + 1] != '"':
                raise Bad("syntax")
            name, i = string(s, i)
            i = ws(s, i)
            if s[i:i + 1] != ":":
                raise Bad("syntax")
            val, i = value(s, i + 1)
            if name in obj:
                raise Bad("repeated")
            obj[name] = val
            i = ws(s, i)
            if s[i:i + 1] == ",":
                i += 1
                continue
            if s[i:i + 1] == "}":
                return obj, i + 1
            raise Bad("syntax")
    if c == "[":
        arr, i = [], ws(s, i + 1)
        if s[i:i + 1] == "]":
            return arr, i + 1
        while True:
            val, i = value(s, i)
            arr.append(val)
            i = ws(s, i)
            if s[i:i + 1] == ",":
                i += 1
                continue
            if s[i:i + 1] == "]":
                return arr, i + 1
            raise Bad("syntax")
    if c == '"':
        return string(s, i)
    for word, val in (("true", True), ("false", False), ("null", None)):
        if s.startswith(word, i):
            return val, i + len(word)
    for word in ("NaN", "Infinity", "-Infinity"):
        if s.startswith(word, i):
            raise Bad("constant")
    m = NUMBER.match(s, i)
    if not m:
        raise Bad("syntax")
    return 0, m.end()


def oracle(data):
    """The sentence of step 4 and W6, on bytes: the kind of defect, or None."""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return "utf-8"
    try:
        d, i = value(s, 0)
        if ws(s, i) != len(s):
            return "syntax"
    except Bad as e:
        return e.args[0]
    if isinstance(d, dict) and "criteria" in d:
        if type(d["criteria"]) is not list:
            return "type"
        for c in d["criteria"]:
            if type(c) is not dict:
                return "type"
            if "id" in c and type(c["id"]) is not str:
                return "type"
            if "required" in c and type(c["required"]) is not bool:
                return "type"
    return None


NAMES = [b"a", b"b", b"\\u0061", 'é'.encode(), b"\\u00e9", 'é'.encode(), b"\\ud83d\\ude00", '\U0001f600'.encode(), b"\\ud800", b"\\udc00",
         b"\\\\ud800", b"x\\ud800y", b"\\ude00\\ud83d", b"", b"id", b"required", b"title"]


def gen(rng, depth=0):
    n = rng.randrange(9 if depth < 5 else 6)
    if n == 0:
        return b'"' + rng.choice(NAMES) + b'"'
    if n in (1, 2):
        return rng.choice((b"0", b"1", b"-1", b"1.5", b"2e3", b"-0"))
    if n == 3:
        return rng.choice((b"true", b"false", b"null"))
    if n == 4:
        return rng.choice((b"NaN", b"Infinity", b"-Infinity", b"[]", b"{}", b'"ok"'))
    if n == 5:
        return b'"' + rng.choice(NAMES) + rng.choice(NAMES) + b'"'
    if n in (6, 7):
        return b"[" + b",".join(gen(rng, depth + 1) for _ in range(rng.randrange(4))) + b"]"
    return b"{" + b",".join(b'"' + rng.choice(NAMES) + b'":' + gen(rng, depth + 1) for _ in range(rng.randrange(4))) + b"}"


def generated(seed, count):
    rng = random.Random(seed)
    for k in range(count):
        if k % 3 == 0:                                       # the value of a member with a type
            old = rng.choice((b'"id":"c2"', b'"required":true', b'"criteria":['))
            data = RAW.replace(old, old.split(b":")[0] + b":" + gen(rng) + (b",\"x\":[" if old.endswith(b"[") else b""), 1)
        else:
            data = extra(b'"x":' + gen(rng), rng.choice(("top", "item")))
        if k % 5 == 0:                                       # a byte changed: outside the grammar as often as not
            p = rng.randrange(len(data))
            data = data[:p] + bytes([rng.randrange(256)]) + data[p + 1:]
        yield data


class Vectors3e53aac(unittest.TestCase):
    def test_119_of_119(self):
        rows = score.score(which=SET)
        self.assertEqual((len(rows), sum(r["agree"] for r in rows)), (119, 119), v.nums(rows))
        self.assertEqual((sum(r["fields_agree"] for r in rows), sum(r["fields"] for r in rows)), (1085, 1085))

    def test_the_default_set_is_3e53aac(self):
        self.assertEqual(score.vector_files()[:118], score.vector_files(SET)[:118])       # 0.12.0: the default is 8ce7f42
        self.assertEqual(len(score.vector_files(SET)), 119)

    def test_older_sets_unchanged(self):
        for which, n in (("6f7a075", 116), ("c4b4bd4", 112), ("1b81ec9", 110), ("6bb7d0b", 108), ("85a310d", 88), ("bc5a138", 58),
                         ("48ab8c9", 60), ("1.4.1", 48), ("1.4", 37), ("1.3", 28)):
            rows = score.score(which=which)
            self.assertEqual((len(rows), sum(r["agree"] for r in rows)), (n, n), which)

    def test_profile_1_4_7_disagrees_on_117_and_118(self):
        rows = score.score(dict(P147), which=SET)
        self.assertEqual(v.nums(rows), ["117", "118"])
        self.assertEqual(sum(r["fields_agree"] for r in rows), 1083)

    def test_each_reading_alone(self):
        for opts, bad in (({"criteria_unreadable": "mismatch"}, ["117", "118"]), ({"sig_r": "not-small"}, []),
                          ({"ed25519": "rfc8032"}, ["116"]), ({"criteria_read": "always"}, []), ({"criteria_shape": "absent"}, []),
                          ({"criteria_types": "known"}, []), ({"criteria_limits": "readable"}, [])):
            self.assertEqual(v.nums(score.score(opts, which=SET)), bad, opts)

    def test_no_outcome_of_01_to_115_changes(self):
        """The changelog of 1.4.8: the whole report, not only the fields of `expected`, but the member `options`."""
        for f in score.vector_files("6f7a075"):
            raw = v.read(f)
            a, b = wv.run_vector_bytes(raw)[0], wv.run_vector_bytes(raw, dict(P147))[0]
            a.pop("options", None)
            b.pop("options", None)
            self.assertEqual(a, b, f)

    def test_116(self):
        f = score.vector_files(SET)[115]
        rep = wv.run_vector_bytes(v.read(f))[0]
        self.assertEqual((rep["problem_codes"], rep["signature_valid"]), ([SIG], False))
        self.assertEqual(rep["details"]["signature_reason"], "R has small order (strict mode)")
        rep = wv.run_vector_bytes(v.read(f), {"ed25519": "rfc8032"})[0]        # a verifier that checks only the equation accepts it
        self.assertEqual((rep["problem_codes"], rep["signature_valid"]), ([], True))

    def test_117_and_118(self):
        for n, why in ((117, "duplicate JSON member name"), (118, "lone surrogate")):
            f = score.vector_files(SET)[n - 1]
            rep = wv.run_vector_bytes(v.read(f))[0]
            self.assertEqual(rep["problem_codes"], [UNREADABLE])
            self.assertIn(why, rep["details"]["criteria_unreadable"])
            self.assertEqual((rep["criteria_hash"], rep["signature_valid"], rep["accepted_as_stated"]), ("match", True, False))
            self.assertNotIn("criteria_results_mismatch", rep["details"])


class Criteria(unittest.TestCase):
    def outcome(self, data, opts=None, matches=True):
        rep = v.run(record(data, matches), opts)
        self.assertFalse(rep.get("refused"), rep)
        return rep

    def codes(self, data, opts=None, matches=True):
        rep = self.outcome(data, opts, matches)
        return sorted(c for c in rep["problem_codes"] if c.startswith("CRITERIA_") and c not in ("CRITERIA_TIMESTAMP_MISMATCH",))

    WANT = {"unreadable": [UNREADABLE], "mismatch": [RESULTS], "ok": []}

    def test_the_table_is_what_the_reader_of_this_file_says(self):
        for label, data, want, fam in table():
            if fam in ("limit", "within the limits"):
                continue
            self.assertEqual(oracle(data) is not None, want == "unreadable", label)

    def test_every_row_under_the_defaults(self):
        seen = {}
        for label, data, want, fam in table():
            rep = self.outcome(data)
            self.assertEqual(self.codes(data), self.WANT[want], label)
            self.assertEqual(rep["criteria_hash"], "match", label)
            self.assertEqual(rep["signature_valid"], True, label)
            self.assertEqual("criteria_unreadable" in rep["details"], want == "unreadable", label)
            self.assertEqual(rep["accepted_as_stated"], want == "ok", label)
            seen[fam] = seen.get(fam, 0) + 1
        self.assertEqual(sorted(seen), sorted({"not UTF-8", "not JSON", "NaN or Infinity", "repeated name", "no repeated name", "lone surrogate", "no lone surrogate",
                                               "wrongly typed", "absent", "readable", "other member", "limit", "within the limits"}))

    def test_0_10_0_is_results_mismatch_on_every_unreadable_row(self):
        for label, data, want, fam in table():
            self.assertEqual(self.codes(data, {"criteria_unreadable": "mismatch"}), [] if want == "ok" else [RESULTS], label)
            self.assertEqual(self.codes(data, dict(P147)), [] if want == "ok" else [RESULTS], label)

    def test_a_hash_that_does_not_match_comes_first(self):                  # W7, Q32
        for label, data, want, fam in table():
            rep = self.outcome(data, None, False)
            self.assertEqual((self.codes(data, None, False), rep["criteria_hash"]), ([HASH], "mismatch"), label)
            self.assertNotIn("criteria_unreadable", rep["details"])

    def test_q32_always(self):
        for label, data, want, fam in table():
            self.assertEqual(self.codes(data, {"criteria_read": "always"}, False), sorted([HASH] + ([UNREADABLE] if want == "unreadable" else [])), label)
            self.assertEqual(self.codes(data, {"criteria_read": "always"}), self.WANT[want], label)

    def test_q33_absent(self):
        for label, data, want, fam in table():
            exp = [UNREADABLE] if fam == "absent" else self.WANT[want]
            self.assertEqual(self.codes(data, {"criteria_shape": "absent"}), exp, label)
        no_title = copy.deepcopy(DOC)                                       # a member of Q34 absent is no defect under Q33
        del no_title["criteria"][0]["title"], no_title["title"]
        self.assertEqual(self.codes(text(no_title), {"criteria_shape": "absent", "criteria_types": "known"}), [])

    def test_q34_known(self):
        for label, data, want, fam in table():
            exp = [UNREADABLE] if fam == "other member" else self.WANT[want]
            self.assertEqual(self.codes(data, {"criteria_types": "known"}), exp, label)

    def test_q34_every_published_criteria_file_has_the_known_form(self):
        count = 0
        for f in score.vector_files(SET):
            d = wv.strict_json_loads(v.read(f))
            c = d.get("inputs", d).get("criteria_file_base64")
            if c is None or " " in c:
                continue
            data = base64.b64decode(c)
            if os.path.basename(f)[:3] not in ("117", "118"):
                self.assertIsNone(wv._criteria_unreadable(data, dict(wv.DEFAULT_OPTIONS, criteria_types="known")), f)
                count += 1
        self.assertGreater(count, 100)

    def test_q35_readable(self):
        for label, data, want, fam in table():
            exp = [] if fam == "limit" else self.WANT[want]
            self.assertEqual(self.codes(data, {"criteria_limits": "readable"}), exp, label)

    def test_0_10_0_whatever_the_new_switches_say(self):                    # W8
        for label, data, want, fam in table():
            for key, val in (("criteria_limits", "readable"), ("criteria_shape", "absent"), ("criteria_types", "known")):
                self.assertEqual(self.codes(data, dict(P147, **{key: val})), [] if want == "ok" else [RESULTS], (label, key))
            self.assertEqual(self.codes(data, dict(P147, criteria_read="always"), False), [HASH], label)

    def test_q35_a_number_is_never_used_as_a_type(self):
        data = text(crit_with(0, id=9007199254740993))
        self.assertEqual(self.codes(data), [UNREADABLE])
        self.assertEqual(self.codes(data, {"criteria_limits": "readable"}), [UNREADABLE])
        self.assertIn("criteria[0].id", self.outcome(data, {"criteria_limits": "readable"})["details"]["criteria_unreadable"])

    def test_q35_deeper_than_the_parser_can_go(self):
        data = extra(b'"x":' + b"[" * 300000 + b"]" * 300000)
        self.assertEqual(self.codes(data), [UNREADABLE])
        self.assertEqual(self.codes(data, {"criteria_limits": "readable"}), [UNREADABLE])

    def test_the_reason_names_the_defect(self):
        for data, words in ((b"\xff", "UTF-8"), (b"", "not JSON"), (extra(b'"x":NaN'), "non-finite number NaN"), (extra(b'"x":[1,-Infinity]'), "non-finite number -Infinity"), (extra(b'"x":1,"x":2'), "duplicate"), (extra(b'"x":"\\ud800"'), "surrogate"),
                            (text(doc_with(criteria=1)), "`criteria` is not an array"), (text(doc_with(criteria=[1])), "criteria[0] is not an object"),
                            (text(crit_with(1, id=1)), "criteria[1].id is not a string"), (text(crit_with(2, required="x")), "criteria[2].required is not a boolean"),
                            (b"\xef\xbb\xbf" + RAW, "byte order mark"), (extra(b'"x":9007199254740992'), "I-JSON"), (extra(b'"x":1e400'), "non-finite")):
            self.assertIn(words, self.outcome(data)["details"]["criteria_unreadable"], data[:30])

    def test_every_defect_at_once_gives_one_code(self):
        data = text(doc_with(criteria=[{"id": 1, "required": "x"}, {"id": "c9", "required": True}]))
        self.assertEqual(self.codes(data), [UNREADABLE])

    def test_not_supplied_is_not_read(self):
        i = copy.deepcopy(BASE)
        del i["criteria_file_base64"]
        rep = v.run(i)
        self.assertEqual((rep["criteria_hash"], rep["problem_codes"]), ("not-supplied", []))
        i["criteria_file_base64"] = None
        self.assertEqual(v.run(i)["problem_codes"], [])

    def test_base64_that_is_not_canonical_matches_nothing(self):            # 89, step 10
        for opts in (None, {"criteria_read": "always"}):
            i = copy.deepcopy(BASE)
            i["criteria_file_base64"] = "e30 ="
            rep = v.run(i, opts)
            self.assertEqual((rep["criteria_hash"], rep["problem_codes"]), ("mismatch", [HASH]))

    def test_an_empty_file_whose_hash_matches(self):
        i = record(b"")
        self.assertEqual(i["receipt"]["receipt"]["criteria"]["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(i["criteria_file_base64"], "")
        self.assertEqual(v.run(i)["problem_codes"], [UNREADABLE])

    def test_correspondence_strict_is_not_reached(self):
        self.assertEqual(self.codes(extra(b'"x":1,"x":2'), {"correspondence": "strict"}), [UNREADABLE])
        self.assertEqual(self.codes(RAW, {"correspondence": "strict"}), [])

    def test_the_notes_of_a_readable_document_stay(self):
        notes = self.outcome(RAW)["notes"]
        self.assertIn("criteria document member 'title' not interpreted", notes)
        self.assertFalse([n for n in self.outcome(extra(b'"x":1,"x":2'))["notes"] if "not interpreted" in n])

    def test_generated_documents_against_the_reader_of_this_file(self):
        kinds, lax = {}, 0
        opts = dict(wv.DEFAULT_OPTIONS)
        for data in generated(20261107, 6000):
            want = oracle(data)
            kinds[want] = kinds.get(want, 0) + 1
            self.assertEqual(wv._criteria_unreadable(data, opts) is not None, want is not None, data)
            if want in ("repeated", "surrogate", "constant"):
                try:
                    json.loads(data)
                    lax += 1
                except ValueError:
                    pass
        self.assertEqual(sorted(k for k in kinds if k), ["constant", "repeated", "surrogate", "syntax", "type", "utf-8"])
        self.assertGreater(kinds[None], 1000)
        self.assertGreater(lax, 1000)                         # a plain parser reads them: the cases discriminate

    def test_generated_documents_through_the_whole_verifier(self):
        for data in generated(1107, 120):
            want = oracle(data)
            codes = self.codes(data)
            self.assertEqual(UNREADABLE in codes, want is not None, data)
            if want is not None:
                self.assertEqual(codes, [UNREADABLE])


class SignatureR(unittest.TestCase):
    """W1, W2. The signer is omega-test-1; a, k, S are computed here, with the arithmetic of tests/test_profile147.py."""
    SEED = bytes.fromhex(build.SEEDS["omega-test-1"])
    PUB = base64.b64decode(build.pub_b64("omega-test-1"))

    @classmethod
    def setUpClass(cls):
        h = hashlib.sha512(cls.SEED).digest()
        cls.a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
        assert enc(mul(cls.a, BASEPOINT)) == cls.PUB
        cls.i = copy.deepcopy(BASE)
        cls.msg = wv.jcs(cls.i["receipt"]["receipt"])

    def forged(self, r_bytes, r=0, pub=None, a=None, msg=None):
        """S = r + k*a mod L: the S that meets the equation when R = r*B."""
        pub, a, msg = pub or self.PUB, self.a if a is None else a, msg or self.msg
        k = int.from_bytes(hashlib.sha512(r_bytes + pub + msg).digest(), "little") % FL
        return r_bytes + ((r + k * a) % FL).to_bytes(32, "little")

    def signed(self, sig):
        i = copy.deepcopy(self.i)
        i["receipt"]["signature"]["value"] = base64.b64encode(sig).decode()
        return i

    def classes(self):
        """(label, R bytes, r, class by hand: `small`, `mixed`, `encoding`, reason words)."""
        out = [(lb, bytes.fromhex(h), 0, "small", "R has small order") for lb, h, _o in v.TORSION]
        out += [(lb, bytes.fromhex(h), 0, "encoding", "R: ") for lb, h in v.NONCANONICAL]
        out.append(("no curve point", v.NO_POINT, 0, "encoding", "R: not a curve point"))
        for n, (lb, h, _o) in enumerate(v.TORSION[1:]):
            r = 1000 + n
            out.append(("r*B + " + lb, enc(add(mul(r, BASEPOINT), dec(bytes.fromhex(h)))), r, "mixed", "R has mixed order"))
        return out

    def test_control_a_signature_of_prime_order_passes(self):
        r = 12345
        sig = self.forged(enc(mul(r, BASEPOINT)), r)
        rep = v.run(self.signed(sig))
        self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (True, []))

    def test_every_class_is_signature_invalid(self):
        n = 0
        for label, rb, r, cls, why in self.classes():
            rep = v.run(self.signed(self.forged(rb, r)))
            self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (False, [SIG]), label)
            self.assertIn(why, rep["details"]["signature_reason"], label)
            n += 1
        self.assertEqual(n, 22)

    def test_the_neutral_point_is_the_one_r_that_meets_the_equation(self):
        """W1: with a key of prime order. rfc8032 applies no rule on R, so only the equation and the encoding answer."""
        met = []
        for label, rb, r, cls, why in self.classes():
            rep = v.run(self.signed(self.forged(rb, r)), {"ed25519": "rfc8032"})
            if rep["signature_valid"]:
                met.append(label)
            self.assertEqual(wv.ed_verify_pure(self.PUB, self.msg, self.forged(rb, r)), bool(rep["signature_valid"]), label)
        self.assertEqual(met, ["neutral point"])

    def test_0_10_0_differs_in_the_reason_only(self):
        for label, rb, r, cls, why in self.classes():
            a, b = v.run(self.signed(self.forged(rb, r))), v.run(self.signed(self.forged(rb, r)), dict(P147))
            self.assertEqual((a["signature_valid"], a["problem_codes"]), (b["signature_valid"], b["problem_codes"]), label)
            if cls == "mixed":
                self.assertEqual(b["details"]["signature_reason"], "signature does not verify", label)
            else:
                self.assertEqual(a["details"]["signature_reason"], b["details"]["signature_reason"], label)

    def test_the_rule_stands_without_the_equation(self):
        """The engine replaced by one that accepts everything: only the check of R stands between a mixed R and `valid`."""
        class Accepts(object):
            @staticmethod
            def from_public_bytes(_b):
                return Accepts()

            def verify(self, _s, _m):
                return None
        orig = wv.Ed25519PublicKey
        wv.Ed25519PublicKey = Accepts
        try:
            for label, rb, r, cls, why in self.classes():
                sig = self.forged(rb, r)
                self.assertEqual(wv.ed25519_verify(self.PUB, self.msg, sig, "strict")[0], False, label)
                self.assertEqual(wv.ed25519_verify(self.PUB, self.msg, sig, "strict", "not-small")[0], cls == "mixed", label)
                self.assertEqual(wv.ed25519_verify(self.PUB, self.msg, sig, "rfc8032")[0], cls != "encoding", label)
            rep = v.run(self.signed(self.forged(self.classes()[-1][1], self.classes()[-1][2])), {"sig_r": "not-small"})
            self.assertEqual(rep["signature_valid"], True)
        finally:
            wv.Ed25519PublicKey = orig

    def test_a_mixed_r_meets_the_equation_under_a_mixed_key(self):
        """W1, the converse: with A + T, T of order 2, an odd k makes R = r*B + T meet it. The key rule stops that key first."""
        t = dec(bytes.fromhex(v.TORSION[1][1]))
        pub = enc(add(mul(self.a, BASEPOINT), t))
        for r in range(1, 200):
            rb = enc(add(mul(r, BASEPOINT), t))
            if int.from_bytes(hashlib.sha512(rb + pub + self.msg).digest(), "little") % FL % 2:
                sig = self.forged(rb, r, pub)
                if wv.ed_verify_pure(pub, self.msg, sig):
                    break
        else:
            self.fail("no r found")
        self.assertEqual(wv.ed25519_verify(pub, self.msg, sig, "strict"), (False, "R has mixed order (profile 1.4.8 step 2)"))
        self.assertEqual(wv.ed25519_verify(pub, self.msg, sig, "strict", "not-small"), (False, "public key is mixed-order (strict mode)"))
        i = self.signed(sig)
        i["keys"]["keys"][0]["public_key_base64"] = base64.b64encode(pub).decode()
        rep = v.run(i)
        self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (False, ["KEY_REJECTED"]))
        self.assertNotIn("R has", rep["details"]["signature_reason"])

    def test_a_rejected_key_reads_no_r(self):                               # W2
        calls = []
        orig = wv.ed25519_verify
        wv.ed25519_verify = lambda *a: calls.append(a) or orig(*a)
        try:
            for label, h, _o in v.TORSION:
                i = self.signed(bytes.fromhex(v.TORSION[0][1]) + bytes(32))
                i["keys"]["keys"][0]["public_key_base64"] = base64.b64encode(bytes.fromhex(h)).decode()
                rep = v.run(i)
                self.assertEqual((rep["signature_valid"], rep["problem_codes"]), (False, ["KEY_REJECTED"]), label)
        finally:
            wv.ed25519_verify = orig
        self.assertEqual(calls, [])

    def test_s_and_the_value_stay_what_they_were(self):                     # W2
        r = 777
        sig = self.forged(enc(mul(r, BASEPOINT)), r)
        s = int.from_bytes(sig[32:], "little")
        rep = v.run(self.signed(sig[:32] + (s + FL).to_bytes(32, "little")))
        self.assertEqual(rep["problem_codes"], [SIG])
        self.assertIn("S >= L", rep["details"]["signature_reason"])
        i = self.signed(sig)
        i["receipt"]["signature"]["value"] = i["receipt"]["signature"]["value"][:-1] + "\n"
        self.assertEqual(v.run(i)["problem_codes"], [SIG])

    def test_generated_r(self):
        rng = random.Random(148)
        torsion = [dec(bytes.fromhex(h)) for _l, h, _o in v.TORSION]
        for _ in range(60):
            r = rng.randrange(1, FL)
            n = rng.randrange(8)
            rb = enc(add(mul(r, BASEPOINT), torsion[n]))
            got = wv.ed25519_verify(self.PUB, self.msg, self.forged(rb, r), "strict")
            self.assertEqual(got, (True, None) if n == 0 else (False, "R has mixed order (profile 1.4.8 step 2)"))
        for _ in range(60):                                                  # 32 random bytes: no point, or mixed by far the most often
            rb = bytes(rng.randrange(256) for _ in range(32))
            self.assertEqual(wv.ed25519_verify(self.PUB, self.msg, rb + bytes(32), "strict")[0], False)


class Notes(unittest.TestCase):
    def test_b5_the_note_says_nothing_of_the_derived_value(self):
        for stated, name in (("independent", None), ("independent", "Example Vendor")):
            rep = v.run(v.record(stated, name, v.NEUTRAL, [v.entry("a", v.K2)]))
            note = [n for n in rep["notes"] if n.startswith("X_RP_PRODUCER_KEY_POINT_RULE")]
            self.assertEqual(len(note), 1)
            self.assertNotIn("derived", note[0])
            self.assertIn("establishes no producer (profile 1.4.7 step 12", note[0])
            self.assertEqual(rep["details"]["independence_derived"], "undeclared" if name is None else "self-checked")


class Profiles(unittest.TestCase):
    def test_the_values(self):
        self.assertEqual(sorted(wv.PROFILES), ["1.2.1", "1.4.2", "1.4.3", "1.4.4", "1.4.5", "1.4.7", "1.4.8"])
        self.assertEqual(P147, {"sig_r": "not-small", "criteria_unreadable": "mismatch", "criteria_noncharacters": "readable"})
        self.assertEqual(wv.DEFAULT_OPTIONS["sig_r"], "prime-order")
        self.assertEqual(wv.DEFAULT_OPTIONS["criteria_unreadable"], "step4")
        self.assertEqual({k: wv.DEFAULT_OPTIONS[k] for k in ("criteria_read", "criteria_shape", "criteria_types", "criteria_limits")},
                         {"criteria_read": "matched", "criteria_shape": "typed", "criteria_types": "read", "criteria_limits": "unreadable"})

    def test_every_older_profile_keeps_them(self):
        for name, p in wv.PROFILES.items():
            if name == "1.4.8":
                continue
            self.assertEqual((p["sig_r"], p["criteria_unreadable"]), ("not-small", "mismatch"), name)
            self.assertEqual(sum(1 for k in p if k.startswith("criteria_")), 2, name)       # 0.12.0 adds criteria_noncharacters

    def test_the_code_is_in_the_closed_list(self):
        self.assertIn(UNREADABLE, wv.PROBLEM_CODES)


class CommandLine(unittest.TestCase):
    run_cli = v.CommandLine.run_cli

    def setUp(self):
        self.files = score.vector_files(SET)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_the_vectors(self):
        for n in (116, 117, 118):
            self.assertEqual(self.run_cli("--vector", self.files[n - 1])[0], 0, n)
            self.assertEqual(self.run_cli(self.files[n - 1])[0], 1, n)
        self.assertEqual(self.run_cli("--vector", "--profile", "1.4.7", self.files[115])[0], 0)
        for n in (117, 118):
            self.assertEqual(self.run_cli("--vector", "--profile", "1.4.7", self.files[n - 1])[0], 3, n)
            self.assertEqual(self.run_cli("--vector", "--criteria-unreadable", "mismatch", self.files[n - 1])[0], 3, n)
            self.assertEqual(self.run_cli("--vector", "--profile", "1.4.7", "--criteria-unreadable", "step4", self.files[n - 1])[0], 0, n)
        self.assertEqual(self.run_cli("--vector", "--ed25519", "rfc8032", self.files[115])[0], 3)

    def report(self, doc, *args):
        g = os.path.join(self.tmp.name, "r.json")
        with open(g, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return json.loads(self.run_cli(*args, g)[1])["report"]

    def test_each_switch(self):
        def codes(doc, *args):
            return sorted(c for c in self.report(doc, *args)["problem_codes"] if c.startswith("CRITERIA_") and "TIMESTAMP" not in c)
        for doc, flag, value, before, after in ((record(text(crit_with(0, drop=("id",)))), "--criteria-shape", "absent", [RESULTS], [UNREADABLE]),
                                                (record(text(doc_with(title=1))), "--criteria-types", "known", [], [UNREADABLE]),
                                                (record(extra(b'"x":1e400')), "--criteria-limits", "readable", [UNREADABLE], []),
                                                (record(b"\xff", False), "--criteria-read", "always", [HASH], sorted([HASH, UNREADABLE]))):
            self.assertEqual(codes(doc), before, flag)
            self.assertEqual(codes(doc, flag, value), after, flag)
        t = SignatureR()
        SignatureR.setUpClass()
        doc = t.signed(t.forged(enc(add(mul(1000, BASEPOINT), dec(bytes.fromhex(v.TORSION[1][1])))), 1000))
        self.assertEqual(self.report(doc)["details"]["signature_reason"], "R has mixed order (profile 1.4.8 step 2)")
        for args in (("--sig-r", "not-small"), ("--profile", "1.4.7")):
            self.assertEqual(self.report(doc, *args)["details"]["signature_reason"], "signature does not verify", args)

    def test_usage_errors(self):
        f = self.files[116]
        for flag, good in (("--sig-r", "not-small"), ("--criteria-unreadable", "mismatch"), ("--criteria-read", "always"), ("--criteria-shape", "absent"),
                           ("--criteria-types", "known"), ("--criteria-limits", "readable")):
            for args in ((flag, "bogus"), (flag, ""), (flag, good, flag, good), (flag + "=" + good,), (flag.upper(), good)):
                self.assertEqual(self.run_cli(*args, f)[0], 64, args)
            self.assertEqual(self.run_cli(flag)[0], 64, flag)
        self.assertEqual(self.run_cli("--profile", "1.4.11", f)[0], 64)
        self.assertEqual(self.run_cli("--profile", "1.4.6", f)[0], 64)
        self.assertIn("1.4.7, 1.4.5", self.run_cli("--profile", "1.4.6", f)[2])

    def test_usage_text_names_every_flag(self):
        rc, out, _ = self.run_cli("--help")
        self.assertEqual(rc, 0)
        for words in ("--sig-r prime-order|not-small       (default prime-order)", "--criteria-unreadable step4|mismatch   (default step4)",
                      "--criteria-read matched|always      (default matched)", "--criteria-shape typed|absent       (default typed)",
                      "--criteria-types read|known         (default read)", "--criteria-limits unreadable|readable   (default unreadable)",
                      "  --profile 1.4.7              the readings 0.10.0 gave", "defaults follow profile 1.4.11"):
            self.assertIn(words, out)


if __name__ == "__main__":
    unittest.main()
