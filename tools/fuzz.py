#!/usr/bin/env python3
"""Generative attack over the input space (part c). Every case carries an expectation written from the README /
RFC text (not from running the verifier): "refused", or a subset of report fields. The same cases are run against
war_verify and against tools/lax_verify.py (positive control: the attack must catch the lax verifier).

usage: nice -n 10 python3 -B tools/fuzz.py [--json OUT]"""
import base64
import copy
import hashlib
import itertools
import json
import os
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import build  # noqa: E402
import lax_verify  # noqa: E402
import testpki as tp  # noqa: E402
import war_verify as wv  # noqa: E402

REF = "refused"
OK_EXPECT = {"problem_codes": [], "warning_codes": [], "signature_valid": True}
# war_verify 0.5.0: "the unsigned timestamp.digest_sha256 field is informative and never decides the outcome" (README
# step 6); the record token does. The other members of the envelope timestamp keep the issuer's form.
ENVELOPE_TS_EXPECT = dict(OK_EXPECT, receipt_timestamp="imprint_match")


# Profile 1.4.4 step 8: "a name that is null, `false`, a number equal to zero, or an empty string, array or object
# counts as absent, and any other value that is not a string counts as declared" (README T2, T4, reading Q19).
UNDECLARED_EXPECT = {"problem_codes": ["INDEPENDENCE_INCONSISTENT"], "warning_codes": ["PRODUCER_UNDECLARED"],
                     "signature_valid": True}


def _exp_for(path, value=None):
    if tuple(path) == ("receipt", "timestamp", "digest_sha256"):
        return ENVELOPE_TS_EXPECT
    if tuple(path) == ("receipt", "receipt", "parties", "checker", "name"):
        return OK_EXPECT
    if tuple(path) == ("receipt", "receipt", "parties", "producer", "name"):
        return UNDECLARED_EXPECT if value in (0, [], {}) and value is not True else OK_EXPECT
    return REF


# ---------------------------------------------------------------------------------------------- text helpers
def enc(v, dup_at=None, path=(), surrogate_at=None):
    """JSON text writer that can (a) add a duplicate member in front of the object at path `dup_at`, (b) put a
    lone surrogate escape into the string at path `surrogate_at`."""
    if isinstance(v, dict):
        items = []
        if dup_at == path and v:
            k0 = sorted(v)[0]
            alt = "dup" if v[k0] != "dup" else "dup2"
            items.append(json.dumps(k0) + ":" + json.dumps(alt))
        for k in sorted(v):
            items.append(json.dumps(k) + ":" + enc(v[k], dup_at, path + (k,), surrogate_at))
        return "{" + ",".join(items) + "}"
    if isinstance(v, list):
        return "[" + ",".join(enc(x, dup_at, path + (i,), surrogate_at) for i, x in enumerate(v)) + "]"
    if isinstance(v, str) and surrogate_at == path:
        return json.dumps(v)[:-1] + "\\ud800\""
    return json.dumps(v)


def walk(v, path=()):
    yield path, v
    if isinstance(v, dict):
        for k in sorted(v):
            for x in walk(v[k], path + (k,)):
                yield x
    elif isinstance(v, list):
        for i, x in enumerate(v):
            for y in walk(x, path + (i,)):
                yield y


def get(v, path):
    for p in path:
        v = v[p]
    return v


def put(v, path, val):
    for p in path[:-1]:
        v = v[p]
    v[path[-1]] = val


def in_receipt(path):
    return path[:2] == ("receipt", "receipt")


def finish(inp, path):
    """Re-sign if the receipt changed so that only the mutation under test can explain the outcome."""
    if in_receipt(path):
        try:
            build.refresh(inp)
        except Exception:
            pass
    return inp


# ------------------------------------------------------------------------------------------------- families
NULLABLE = {("criteria_file_base64",), ("criteria_tsr_base64",), ("receipt_tsr_base64",), ("receipt", "timestamp"),
            ("receipt", "receipt", "parties", "checker", "key_id"), ("receipt", "receipt", "parties", "checker", "name"),
            ("receipt", "receipt", "parties", "producer", "key_id"), ("receipt", "receipt", "parties", "producer", "name")}


def fam_unknown_member(base):
    for path, v in walk(base):
        if isinstance(v, dict):
            inp = copy.deepcopy(base)
            get(inp, path)["x_unknown_member"] = "1"
            # vectors 52 and 57 add one named member to receipt.tools; any other member stays unknown (refused)
            yield "unknown member at /%s" % "/".join(map(str, path)), {"inputs": finish(inp, path)}, REF


def fam_duplicate_member(base):
    for path, v in walk(base):
        if isinstance(v, dict) and v:
            text = enc({"inputs": base}, dup_at=("inputs",) + path)
            yield "duplicate member at /%s" % "/".join(map(str, path)), text, REF


def fam_wrong_type(base):
    alts = [0, "0", True, None, [], {}, 1.5]
    for path, v in walk(base):
        if not path or isinstance(v, (dict, list)) and path[-1] not in ("timestamp",):
            continue
        for a in alts:
            if type(a) is type(v):
                continue
            if a is None and path in NULLABLE:
                continue
            if isinstance(a, str) and v is None:
                continue
            inp = copy.deepcopy(base)
            put(inp, path, a)
            yield "type %s -> %s at /%s" % (type(v).__name__, type(a).__name__, "/".join(map(str, path))), \
                {"inputs": finish(inp, path)}, _exp_for(path, a)


def fam_surrogate(base):
    for path, v in walk(base):
        if isinstance(v, str) and in_receipt(path):
            yield "lone surrogate at /%s" % "/".join(map(str, path)), enc({"inputs": base}, surrogate_at=("inputs",) + path), REF


def fam_numbers(base):
    for p in (("receipt", "receipt", "revision"), ("receipt", "receipt", "files", "remediated", "bytes"),
              ("receipt", "receipt", "files", "original", "pages")):
        for tok, exp in (("1e21", REF), ("5e-324", REF), ("1.0", REF), ("9007199254740993", REF), ("-1", REF),
                         ("1E2", REF), ("-0", dict(OK_EXPECT)), ("0", dict(OK_EXPECT))):
            inp = copy.deepcopy(base)
            # sign over the JCS form of the value the parser will produce, so that only the grammar decides
            try:
                val = json.loads(tok)
                put(inp, p, val)
                build.refresh(inp)
            except Exception:
                pass
            put(inp, p, "__NUM__")
            text = enc({"inputs": inp}).replace('"__NUM__"', tok)
            yield "number %s at /%s" % (tok, "/".join(p)), text, exp


def fam_parties(base):
    """Profile 1.4.4 step 8 and vector 109: what may be absent from parties, and what stays refused (README T3, Q20)."""
    def case(fn):
        inp = copy.deepcopy(base)
        fn(inp["receipt"]["receipt"]["parties"])
        build.refresh(inp)
        return {"inputs": inp}
    for name, fn in (("no producer", lambda p: p.pop("producer")),
                     ("producer without members", lambda p: p.__setitem__("producer", {})),
                     ("producer with a key_id only", lambda p: p.__setitem__("producer", {"key_id": "omega-test-2"})),
                     ("producer named unknown", lambda p: p["producer"].__setitem__("name", " UNKNOWN ")),
                     ("producer named unspecified", lambda p: p["producer"].__setitem__("name", "Unspecified"))):
        yield name, case(fn), UNDECLARED_EXPECT
    yield "producer named by case and spaces", case(lambda p: p["producer"].__setitem__("name", " example CHECKER\n")), \
        {"problem_codes": ["INDEPENDENCE_INCONSISTENT"], "warning_codes": [], "signature_valid": True}
    for v in (None, 0, 1, True, False, "x", [], [{}]):
        yield "producer is %r" % (v,), case(lambda p: p.__setitem__("producer", v)), REF
    for v in (None, 0, True, "x", [], {}):
        yield "checker is %r" % (v,), case(lambda p: p.__setitem__("checker", v)), REF
    yield "no checker", case(lambda p: p.pop("checker")), REF
    yield "checker without a name member", case(lambda p: p["checker"].pop("name")), REF
    yield "unknown member beside no producer", case(lambda p: (p.pop("producer"), p.__setitem__("third", {}))), REF
    yield "unknown member in a bare producer", case(lambda p: p.__setitem__("producer", {"role": "x"})), REF


def _crit_tsr(inp, raw):
    inp["criteria_tsr_base64"] = base64.b64encode(raw).decode()
    return {"inputs": inp}


def fam_der(base):
    d = bytes.fromhex(base["receipt"]["receipt"]["criteria"]["sha256"])
    good_tst = tp.tstinfo(d)
    good = tp.unsigned_tsr(good_tst)
    MISM = {"problem_codes": ["CRITERIA_TIMESTAMP_MISMATCH"], "warning_codes": ["CRITERIA_COMMITMENT_UNVERIFIED"]}
    cases = []
    # outer TimeStampResp length in non-minimal long form
    cases.append(("non-minimal long-form length", b"\x30\x81" + good[1:], REF))
    cases.append(("indefinite length", b"\x30\x80" + good[2:] + b"\x00\x00", REF))
    cases.append(("trailing byte after TimeStampResp", good + b"\x00", REF))
    cases.append(("two TSTInfo in one eContent", tp.unsigned_tsr(good_tst + good_tst), REF))
    cases.append(("TSTInfo trailing byte", tp.unsigned_tsr(good_tst + b"\x00"), REF))
    for name, o in sorted(tp.SHA.items()):
        if name == "sha256":
            continue
        cases.append(("imprint OID swapped to %s, same 32 bytes" % name, tp.unsigned_tsr(tp.tstinfo(d, hash_oid=o)), MISM))
    cases.append(("SHA-256 params absent", tp.unsigned_tsr(tp.tstinfo(d, params=None)), {"problem_codes": [], "warning_codes": []}))
    cases.append(("SHA-256 params OCTET STRING", tp.unsigned_tsr(tp.tstinfo(d, params=tp.octets(b""))), MISM))
    cases.append(("hashedMessage 31 bytes", tp.unsigned_tsr(tp.tstinfo(d[:31])), MISM))
    cases.append(("hashedMessage 33 bytes", tp.unsigned_tsr(tp.tstinfo(d + b"\x00")), MISM))
    cases.append(("digest smuggled in nonce, imprint over other bytes",
                  tp.unsigned_tsr(tp.tstinfo(b"\x11" * 32, nonce=int.from_bytes(b"\x01" + d, "big"))), MISM))
    cases.append(("digest smuggled in a non-critical extension, imprint over other bytes",
                  tp.unsigned_tsr(tp.tstinfo(b"\x11" * 32, extensions=[tp.seq(tp.oid("1.2.3.99"), tp.octets(d))])), MISM))
    cases.append(("unknown critical extension", tp.unsigned_tsr(tp.tstinfo(d, extensions=[tp.seq(tp.oid("1.2.3.99"), tp.boolean(True), tp.octets(b"x"))])), REF))
    cases.append(("unknown non-critical extension", tp.unsigned_tsr(tp.tstinfo(d, extensions=[tp.seq(tp.oid("1.2.3.99"), tp.octets(b"x"))])), {"problem_codes": [], "warning_codes": []}))
    # profile 1.4.2 R4 (85a310d, vectors 70-74, 78): a genTime in another form is no usable time, the token gives
    # none: fallback to committed_at with CRITERIA_COMMITMENT_UNVERIFIED and no problem (until 0.5.0: refused)
    GT_NONE = {"problem_codes": [], "warning_codes": ["CRITERIA_COMMITMENT_UNVERIFIED"]}
    for g, exp in (("20260301000000", GT_NONE), ("20260301000000.0Z", GT_NONE), ("20260301000000.Z", GT_NONE),
                   ("20260301000060Z", GT_NONE), ("202603010000Z", GT_NONE), ("20260301000000+0000", GT_NONE),
                   ("20260301000000z", GT_NONE), ("20260230000000Z", GT_NONE), ("20260301240000Z", GT_NONE),
                   ("20260301000000.5Z", {"problem_codes": [], "warning_codes": []}),
                   ("20260301000001Z", {"problem_codes": ["CRITERIA_TIME_MISMATCH"], "warning_codes": []})):
        cases.append(("genTime %r" % g, tp.unsigned_tsr(tp.tstinfo(d, gen=g)), exp))
    cases.append(("ordering FALSE encoded", tp.unsigned_tsr(tp.tstinfo(d, ordering=False)), REF))
    cases.append(("ordering TRUE", tp.unsigned_tsr(tp.tstinfo(d, ordering=True)), {"problem_codes": [], "warning_codes": []}))
    cases.append(("TSTInfo version 2", tp.unsigned_tsr(tp.tstinfo(d, version=2)), REF))
    cases.append(("accuracy millis 0", tp.unsigned_tsr(tp.tstinfo(d, accuracy=(None, 0, None))), REF))
    cases.append(("accuracy millis 1000", tp.unsigned_tsr(tp.tstinfo(d, accuracy=(None, 1000, None))), REF))
    cases.append(("PKIStatus rejection with a token", tp.unsigned_tsr(good_tst, status=2), REF))
    cases.append(("PKIStatus 99", tp.unsigned_tsr(good_tst, status=99), REF))
    cases.append(("BOOLEAN 0x01 for ordering", tp.unsigned_tsr(tp.tstinfo(d, ordering=True).replace(b"\x01\x01\xff", b"\x01\x01\x01")), REF))
    for name, raw, exp in cases:
        yield "criteria token: " + name, _crit_tsr(copy.deepcopy(base), raw), exp


def fam_ed25519(base):
    ident = (1).to_bytes(32, "little")
    P = wv._P
    # universal forgery with the identity key: any record, R = identity, S = 0
    inp = copy.deepcopy(base)
    inp["keys"]["keys"].append({"alg": "Ed25519", "key_id": "forge", "public_key_base64": base64.b64encode(ident).decode(), "status": "test"})
    r = inp["receipt"]["receipt"]
    r["key_id"] = "forge"
    r["parties"]["checker"]["key_id"] = "forge"
    r["verdict"] = "pass"
    inp["receipt"]["signature"]["key_id"] = "forge"
    inp["receipt"]["signature"]["value"] = base64.b64encode(ident + bytes(32)).decode()
    build.record_token(inp)
    # profile 1.3 step 2 key rule: "any other key ... is `KEY_REJECTED` and no signature check is run"
    yield "identity public key + (R=identity, S=0) forgery", {"inputs": inp}, \
        {"signature_valid": False, "problem_codes": ["KEY_REJECTED"]}
    inp = copy.deepcopy(base)
    inp["keys"]["keys"][1]["public_key_base64"] = base64.b64encode((1 + P).to_bytes(32, "little")).decode()
    # 1.3: the key rule applies to the key named by receipt.key_id; an unused bad entry is a local block only
    yield "non-canonical public key (y = 1 + p) in the key file", {"inputs": inp}, \
        {"signature_valid": True, "problem_codes": [], "local_blocks_include": "X_UNUSED_KEY_REJECTED"}
    inp = copy.deepcopy(base)
    sig = base64.b64decode(inp["receipt"]["signature"]["value"])
    S = int.from_bytes(sig[32:], "little") + wv._L
    inp["receipt"]["signature"]["value"] = base64.b64encode(sig[:32] + S.to_bytes(32, "little")).decode()
    yield "S + L", {"inputs": inp}, {"signature_valid": False, "problem_codes": ["SIGNATURE_INVALID"]}
    # mixed-order key in the key file
    A = wv.ed_decode(base64.b64decode(inp["keys"]["keys"][1]["public_key_base64"]))
    y8 = 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7
    T8 = wv.ed_decode(y8.to_bytes(32, "little"))
    inp = copy.deepcopy(base)
    inp["keys"]["keys"][1]["public_key_base64"] = base64.b64encode(wv._encode_point(wv._padd(A, T8))).decode()
    yield "mixed-order public key in the key file", {"inputs": inp}, \
        {"signature_valid": True, "problem_codes": [], "local_blocks_include": "X_UNUSED_KEY_REJECTED"}
    inp = copy.deepcopy(base)
    inp["receipt"]["signature"]["value"] = base64.b64encode(sig[:63]).decode()
    yield "63-byte signature", {"inputs": inp}, {"signature_valid": False, "problem_codes": ["SIGNATURE_INVALID"]}


def fam_keyid(base):
    def mk(sig_kid, rec_kid, ck, pk=None, signer=None, keys=None):
        inp = copy.deepcopy(base)
        if keys:
            inp["keys"] = keys
        r = inp["receipt"]["receipt"]
        r["key_id"] = rec_kid
        r["parties"]["checker"]["key_id"] = ck
        r["parties"]["producer"]["key_id"] = pk
        inp["receipt"]["signature"]["key_id"] = sig_kid
        build.refresh(inp, sign_with=signer or sig_kid)
        return {"inputs": inp}
    # 1.3 step 2: the key is the one the signed receipt.key_id names; "The envelope's `signature.key_id` must equal
    # it, else `SIGNATURE_INVALID`"; "whether that key is `parties.checker.key_id` is a separate check"
    yield "sig=k2 receipt=k1 checker=k1 (vector 12 shape)", mk("omega-test-2", "omega-test-1", "omega-test-1"), \
        {"signature_valid": False, "problem_codes": ["SIGNATURE_INVALID"]}
    yield "sig=k2 receipt=k2 checker=k1", mk("omega-test-2", "omega-test-2", "omega-test-1"), \
        {"signature_valid": True, "problem_codes": ["CHECKER_NOT_SIGNER"]}
    yield "sig=k1 receipt=k2 checker=k1 (receipt names another key)", mk("omega-test-1", "omega-test-2", "omega-test-1"), \
        {"signature_valid": False, "problem_codes": ["SIGNATURE_INVALID", "CHECKER_NOT_SIGNER"]}
    yield "checker key_id null", mk("omega-test-1", "omega-test-1", None), \
        {"signature_valid": True, "problem_codes": ["CHECKER_NOT_SIGNER"]}
    yield "signature key_id not in key file", mk("omega-test-9", "omega-test-1", "omega-test-1", signer="omega-test-1"), \
        {"signature_valid": False}
    kf = build.keyfile()
    kf["keys"].append(dict(kf["keys"][0], key_id="alias-of-1"))
    yield "producer key_id is an alias (same public key, other id)", \
        mk("omega-test-1", "omega-test-1", "omega-test-1", pk="alias-of-1", keys=kf), \
        {"signature_valid": True, "problem_codes": ["INDEPENDENCE_INCONSISTENT", "KEY_COLLISION"]}
    yield "producer key_id = signing key, checker key_id = other", mk("omega-test-1", "omega-test-1", "omega-test-2", pk="omega-test-1"), \
        {"signature_valid": True, "problem_codes": ["CHECKER_NOT_SIGNER", "INDEPENDENCE_INCONSISTENT", "KEY_COLLISION"]}


def fam_time(base):
    def mk(committed_at, issued, crit_gen=None, rec_gen=None):
        inp = copy.deepcopy(base)
        r = inp["receipt"]["receipt"]
        r["criteria"]["committed_at"] = committed_at
        r["issued_utc"] = issued
        if crit_gen is None:
            inp["criteria_tsr_base64"] = None
        else:
            build.criteria_token(inp, gen=crit_gen)
        if rec_gen is None:
            inp["receipt_tsr_base64"] = None
            inp["receipt"]["timestamp"] = {"reason": "not requested", "status": "none"}
            build.sign(inp)
        else:
            build.sign(inp)
            build.record_token(inp, gen=rec_gen)
        return {"inputs": inp}
    no = {"criteria_committed_before_check": "no"}
    yes = {"criteria_committed_before_check": "yes"}
    yield "criteria genTime == record genTime", mk("2026-06-01T12:00:05Z", "2026-06-01T12:00:00Z", "20260601120005Z", "20260601120005Z"), no
    # 1.3 step 5: reference = the earlier of issued_utc and the covering token; issued_utc 12:00:06 keeps the token
    # profile 1.4.2 R4/R5: stated times carry at most milliseconds ([.fff]); the token time is rounded up to the ms
    yield "criteria genTime 1 millisecond before record genTime", mk("2026-06-01T12:00:04.999Z", "2026-06-01T12:00:06Z", "20260601120004.999Z", "20260601120005Z"), yes
    yield "criteria genTime 1 microsecond before record genTime (rounds up to it)", mk("2026-06-01T12:00:04.999Z", "2026-06-01T12:00:06Z", "20260601120004.999999Z", "20260601120005Z"), no
    yield "criteria before record genTime, after issued_utc (earlier-of)", mk("2026-06-01T12:00:04.999Z", "2026-06-01T12:00:00Z", "20260601120004.999Z", "20260601120005Z"), no
    yield "criteria genTime 0.5 s after a seconds-precision issued_utc", mk("2026-06-01T12:00:00Z", "2026-06-01T12:00:00Z", "20260601120000.5Z"), no
    yield "committed_at == issued_utc, no tokens", mk("2026-06-01T12:00:00Z", "2026-06-01T12:00:00Z"), dict(no, warning_codes=["CRITERIA_COMMITMENT_UNVERIFIED"])
    yield "committed_at 1 millisecond before issued_utc, no tokens", mk("2026-06-01T11:59:59.999Z", "2026-06-01T12:00:00Z"), dict(yes, warning_codes=["CRITERIA_COMMITMENT_UNVERIFIED"])
    # profile 1.4.2 R5 (vector 76): a stated time in another form is RECEIPT_TIME_UNREADABLE and "no" (until 0.5.0: refused)
    unread = dict(no, problem_codes=["RECEIPT_TIME_UNREADABLE"])
    yield "committed_at with microseconds", mk("2026-06-01T11:59:59.999999Z", "2026-06-01T12:00:00Z"), dict(unread, warning_codes=["CRITERIA_COMMITMENT_UNVERIFIED"])
    yield "committed_at with +00:00 offset", mk("2026-03-01T00:00:00+00:00", "2026-06-01T12:00:00Z"), unread
    yield "committed_at lower-case z", mk("2026-03-01T00:00:00z", "2026-06-01T12:00:00Z"), unread
    yield "issued_utc leap second", mk("2026-03-01T00:00:00Z", "2026-06-30T23:59:60Z"), unread
    yield "criteria token 0.5 s later than a seconds-precision committed_at (truncate agrees)", \
        mk("2026-03-01T00:00:00Z", "2026-06-01T12:00:00Z", "20260301000000.5Z"), dict(yes, problem_codes=[])


def fam_criteria_bytes(base):
    raw = base64.b64decode(base["criteria_file_base64"])
    doc = json.loads(raw)
    variants = {
        "BOM prefix": b"\xef\xbb\xbf" + raw,
        "CRLF line ends": json.dumps(doc, indent=1, sort_keys=True).replace("\n", "\r\n").encode(),
        "trailing newline": raw + b"\n",
        "NFD title": raw.decode().replace("Example", unicodedata.normalize("NFD", "Exampl\u00e9")).encode(),
        "NFC title": raw.decode().replace("Example", "Exampl\u00e9").encode(),
    }
    for name, b in sorted(variants.items()):
        inp = copy.deepcopy(base)
        inp["criteria_file_base64"] = base64.b64encode(b).decode()
        yield "criteria file %s, record hash of the original" % name, {"inputs": inp}, \
            {"criteria_hash": "mismatch", "problem_codes": ["CRITERIA_HASH_MISMATCH"]}
        inp = copy.deepcopy(base)
        inp["criteria_file_base64"] = base64.b64encode(b).decode()
        inp["receipt"]["receipt"]["criteria"]["sha256"] = hashlib.sha256(b).hexdigest()
        build.criteria_token(inp)
        build.refresh(inp)
        # 1.4.8: a byte order mark is what this parser cannot read (README W3, reading Q35)
        exp = {"criteria_hash": "match", "problem_codes": ["CRITERIA_UNREADABLE"] if name == "BOM prefix" else []}
        yield "criteria file %s, record re-hashed to it" % name, {"inputs": inp}, exp


def fam_148(base):
    """Profile 1.4.8 steps 2 and 4 (README W1-W7): expectations from the sentences, not from running the verifier."""
    bad_sig = {"signature_valid": False, "problem_codes": ["SIGNATURE_INVALID"]}
    seed = bytes.fromhex(build.SEEDS["omega-test-1"])
    h = hashlib.sha512(seed).digest()
    a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    msg = wv.jcs(base["receipt"]["receipt"])
    pub = base64.b64decode(build.pub_b64("omega-test-1"))
    torsion = ["01" + "00" * 31, "ec" + "ff" * 30 + "7f", "00" * 32, "00" * 31 + "80",
               "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
               "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
               "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
               "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"]

    def forged(rb, r=0):
        k = int.from_bytes(hashlib.sha512(rb + pub + msg).digest(), "little") % wv._L
        i = copy.deepcopy(base)
        i["receipt"]["signature"]["value"] = base64.b64encode(rb + ((r + k * a) % wv._L).to_bytes(32, "little")).decode()
        return {"inputs": i}

    for t in torsion:
        yield "1.4.8: R of small order %s" % t[:8], forged(bytes.fromhex(t)), bad_sig
        if t != torsion[0]:
            rb = wv._encode_point(wv._padd(wv._pmul(1000, wv._BASE), wv.ed_decode(bytes.fromhex(t))))
            yield "1.4.8: R of mixed order, r*B + %s" % t[:8], forged(rb, 1000), bad_sig
    for name, hx in (("y = p", "ed" + "ff" * 30 + "7f"), ("y = p + 1", "ee" + "ff" * 30 + "7f"), ("x = 0, sign bit", "01" + "00" * 30 + "80")):
        yield "1.4.8: R with %s" % name, forged(bytes.fromhex(hx)), bad_sig
    yield "1.4.8: R of prime order, S = r + k*a", forged(wv._encode_point(wv._pmul(1000, wv._BASE)), 1000), \
        dict(OK_EXPECT, criteria_hash="match")
    raw = base64.b64decode(base["criteria_file_base64"])

    def put(body):
        return raw[:1] + body + b"," + raw[1:]

    unread = {"criteria_hash": "match", "problem_codes": ["CRITERIA_UNREADABLE"], "signature_valid": True}
    fine = {"criteria_hash": "match", "problem_codes": [], "signature_valid": True}
    results = {"criteria_hash": "match", "problem_codes": ["CRITERIA_RESULTS_MISMATCH"], "signature_valid": True}
    docs = [("not UTF-8", b'{"criteria":[],"\xff":1}', unread), ("surrogate as bytes", put(b'"x":"\xed\xa0\x80"'), unread), ("empty", b"", unread),
            ("trailing text", raw + b"x", unread), ("NaN", put(b'"x":NaN'), unread), ("Infinity", put(b'"x":[Infinity]'), unread), ("-Infinity", put(b'"x":-Infinity'), unread),
            ("repeated name, top", put(b'"title":"x"'), unread), ("repeated name, nested", put(b'"x":[{"a":{"b":1,"b":1}}]'), unread),
            ("repeated name after an escape", put(b'"x":{"a":1,"\\u0061":1}'), unread), ("two cases of a letter", put(b'"x":{"a":1,"A":1}'), fine),
            ("lone high in a value", put(b'"x":"\\ud800"'), unread), ("lone low in a name", put(b'"\\udc00":1'), unread), ("reversed pair", put(b'"x":"\\ude00\\ud83d"'), unread),
            ("valid pair", put(b'"x":"\\ud83d\\ude00"'), fine), ("escaped backslash", put(b'"x":"\\\\ud800"'), fine),
            ("criterion id a number", raw.replace(b'"id":"c1"', b'"id":1'), unread), ("required a string", raw.replace(b'"required":true', b'"required":"true"', 1), unread),
            ("required null", raw.replace(b'"required":true', b'"required":null', 1), unread), ("criteria an object", raw.replace(b'"criteria":[', b'"x":[', 1)[:-1] + b',"criteria":{}}', unread),
            ("no required", raw.replace(b'"required":true,', b"", 1), results), ("the document an array", b"[]", results),
            ("integer past 2^53", put(b'"x":9007199254740992'), unread), ("1e400", put(b'"x":1e400'), unread), ("depth 65", put(b'"x":' + b"[" * 65 + b"]" * 65), unread),
            ("depth 64", put(b'"x":' + b"[" * 64 + b"]" * 64), fine)]
    for name, b, exp in docs:
        i = copy.deepcopy(base)
        i["criteria_file_base64"] = base64.b64encode(b).decode()
        yield "1.4.8: criteria file %s, record hash of the original" % name, {"inputs": i}, \
            {"criteria_hash": "mismatch", "problem_codes": ["CRITERIA_HASH_MISMATCH"]}
        i = copy.deepcopy(i)
        i["receipt"]["receipt"]["criteria"]["sha256"] = hashlib.sha256(b).hexdigest()
        build.criteria_token(i)
        build.refresh(i)
        yield "1.4.8: criteria file %s" % name, {"inputs": i}, exp



def fam_1411(base):
    """Profile 1.4.11 step 4 (README X1-X4): expectations from the sentences and RFC 7493, not from running the verifier."""
    raw = base64.b64decode(base["criteria_file_base64"])

    def put(body):
        return raw[:1] + body + b"," + raw[1:]

    unread = {"criteria_hash": "match", "problem_codes": ["CRITERIA_UNREADABLE"], "signature_valid": True}
    fine = {"criteria_hash": "match", "problem_codes": [], "signature_valid": True}
    docs = []
    for c in (0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x2FFFF, 0x10FFFE, 0x10FFFF):     # X4: noncharacters, Unicode 23.7; read (Q36)
        ch = chr(c).encode("utf-8")
        esc = (json.dumps(chr(c), ensure_ascii=True)[1:-1]).encode()
        docs += [("noncharacter U+%04X as bytes in a value" % c, put(b'"x":"a' + ch + b'"'), fine),
                 ("noncharacter U+%04X escaped in a value" % c, put(b'"x":"' + esc + b'"'), fine),
                 ("noncharacter U+%04X in a name" % c, put(b'"' + ch + b'":1'), fine),
                 ("noncharacter U+%04X in an array, 40 levels down" % c, put(b'"x":' + b"[" * 40 + b'"' + esc + b'"' + b"]" * 40), fine)]
    for c in (0xFDCF, 0xFDF0, 0xFFFD, 0xFEFF, 0x1FFFD, 0x10FFFD, 0xE000):              # their neighbours are characters
        docs.append(("U+%04X in a value" % c, put(b'"x":"' + (json.dumps(chr(c), ensure_ascii=True)[1:-1]).encode() + b'"'), fine))
    nest = lambda n, v: b"[" * (n - 1) + v + b"]" * (n - 1)
    for v in (b"0", b'"s"', b"null", b"true", b"{}", b"[]"):                           # X1: the member's value is level 1
        docs += [("%s at level 64" % v.decode(), put(b'"x":' + nest(64, v)), fine),
                 ("%s at level 65" % v.decode(), put(b'"x":' + nest(65, v)), unread)]
    docs += [("2^53 written 9007199254740992.0", put(b'"x":9007199254740992.0'), fine),           # X2, Q37
             ("2^53 written 9.007199254740992e15", put(b'"x":9.007199254740992e15'), fine),
             ("1e16", put(b'"x":1e16'), fine), ("-2^53", put(b'"x":-9007199254740992'), unread),
             ("2^53 + 1", put(b'"x":9007199254740993'), unread), ("2^53 - 1", put(b'"x":9007199254740991'), fine),
             ("the largest double", put(b'"x":1.7976931348623157e308'), fine),                 # X3, Q38
             ("halfway past the largest double", put(b'"x":1.7976931348623159e308'), unread),
             ("-1e400", put(b'"x":-1e400'), unread), ("1e-400", put(b'"x":1e-400'), fine),
             ("thirty digits of pi", put(b'"x":3.141592653589793238462643383279'), fine)]
    for name, b, exp in docs:
        i = copy.deepcopy(base)
        i["criteria_file_base64"] = base64.b64encode(b).decode()
        yield "1.4.11: criteria file %s, record hash of the original" % name, {"inputs": i}, \
            {"criteria_hash": "mismatch", "problem_codes": ["CRITERIA_HASH_MISMATCH"]}
        i = copy.deepcopy(i)
        i["receipt"]["receipt"]["criteria"]["sha256"] = hashlib.sha256(b).hexdigest()
        build.criteria_token(i)
        build.refresh(i)
        yield "1.4.11: criteria file %s" % name, {"inputs": i}, exp

def fam_rp(base):
    """Profile 1.4.5 step 12 (README U1-U9): expectations from the sentences, not from running the verifier."""
    inp = copy.deepcopy(base)
    inp["receipt"]["receipt"]["parties"]["producer"]["key_id"] = "omega-test-2"
    build.refresh(inp)
    k2 = build.pub_b64("omega-test-2")
    k1 = build.pub_b64("omega-test-1")
    entry = lambda kid, pub: {"alg": "Ed25519", "key_id": kid, "public_key_base64": pub, "status": "test"}  # noqa: E731
    held = {"keys": [entry("p", k2)]}
    not_held = {"problem_codes": ["INDEPENDENCE_INCONSISTENT"], "warning_codes": [], "signature_valid": True}

    def case(name, value, exp):
        return "relying_party_keys: %s" % name, {"inputs": dict(copy.deepcopy(inp), relying_party_keys=value)}, exp

    yield "relying_party_keys: absent", {"inputs": copy.deepcopy(inp)}, OK_EXPECT
    yield case("holds the key", held, OK_EXPECT)
    yield case("another identifier, same bytes", {"keys": [entry("zz", k2), entry("omega-test-1", k1)]}, OK_EXPECT)
    yield case("the key file itself", inp["keys"], OK_EXPECT)
    yield case("empty list", {"keys": []}, not_held)
    yield case("another key", {"keys": [entry("omega-test-2", k1)]}, not_held)
    yield case("repeated identifier", {"keys": [entry("a", k2), entry("a", k2)]}, OK_EXPECT)      # 1.4.7, vector 113
    yield case("not canonical base64", {"keys": [entry("p", k2[:-2] + "B=")]}, not_held)
    for v in (None, True, 0, 1, "x", [], [held["keys"][0]], {}):
        yield case("value %r" % (v,), v, REF)
    for m in ("alg", "key_id", "public_key_base64", "status"):
        e = dict(held["keys"][0])
        del e[m]
        yield case("entry without %s" % m, {"keys": [e]}, REF)
        yield case("entry with null %s" % m, {"keys": [dict(held["keys"][0], **{m: None})]}, REF)
    yield case("unknown member", dict(held, x_unknown_member="1"), REF)
    yield case("unknown member of an entry", {"keys": [dict(held["keys"][0], x_unknown_member="1")]}, REF)
    yield case("entry of another algorithm", {"keys": [dict(held["keys"][0], alg="RS256")]}, REF)
    yield case("entry of another status", {"keys": [dict(held["keys"][0], status="revoked")]}, REF)
    yield case("empty key_id", {"keys": [dict(held["keys"][0], key_id="")]}, REF)


def fam_rp_147(base):
    """Profile 1.4.7 step 12 (README V1, V3, V4): expectations from the sentences, not from running the verifier."""
    inp = copy.deepcopy(base)
    inp["receipt"]["receipt"]["parties"]["producer"]["key_id"] = "omega-test-2"
    build.refresh(inp)
    k2, k1 = build.pub_b64("omega-test-2"), build.pub_b64("omega-test-1")
    k3 = base64.b64encode(hashlib.sha256(b"not the producer").digest()[:31] + b"\x00").decode()
    entry = lambda kid, pub: {"alg": "Ed25519", "key_id": kid, "public_key_base64": pub, "status": "test"}  # noqa: E731
    fails = {"problem_codes": ["INDEPENDENCE_INCONSISTENT"], "warning_codes": [], "signature_valid": True}
    k2raw = base64.b64decode(k2)
    torsion = ["01" + "00" * 31, "ec" + "ff" * 30 + "7f", "00" * 32, "00" * 31 + "80",
               "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
               "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
               "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
               "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"]
    bad = [("torsion " + h[:8] + h[-2:], bytes.fromhex(h)) for h in torsion]
    bad += [("mixed " + h[:8] + h[-2:], wv._encode_point(wv._padd(wv.ed_decode(k2raw), wv.ed_decode(bytes.fromhex(h)))))
            for h in torsion[1:]]
    bad += [("y = p + 1", bytes.fromhex("ee" + "ff" * 30 + "7f")), ("x = 0, sign bit", bytes.fromhex("01" + "00" * 30 + "80")),
            ("31 bytes", b"\x01" * 31), ("33 bytes", b"\x01" * 33)]

    def case(name, pub, value, exp):
        i = copy.deepcopy(inp)
        i["keys"]["keys"][1]["public_key_base64"] = pub
        if value is not None:
            i["relying_party_keys"] = value
        return "1.4.7: %s" % name, {"inputs": i}, exp

    for name, raw in bad:
        pub = base64.b64encode(raw).decode()
        yield case("%s in both lists" % name, pub, {"keys": [entry("omega-test-2", pub)]}, fails)
        yield case("%s under an unrelated identifier" % name, pub, {"keys": [entry("unrelated", pub)]}, fails)
        yield case("%s, repeated identifier" % name, pub, {"keys": [entry("a", pub), entry("a", pub)]}, fails)
        yield case("%s, no list" % name, pub, None, OK_EXPECT)
    for order in itertools.permutations((k2, k1, k3)):
        yield case("repeated identifier, order %d %d %d" % tuple((k2, k1, k3).index(x) for x in order), k2,
                   {"keys": [entry("a", x) for x in order]}, OK_EXPECT)
    yield case("repeated identifier, other keys only", k2, {"keys": [entry("a", k1), entry("a", k3)]}, fails)


FAMILIES = [("parties", fam_parties), ("unknown member", fam_unknown_member), ("duplicate member", fam_duplicate_member),
            ("wrong type", fam_wrong_type), ("lone surrogate", fam_surrogate), ("numbers", fam_numbers),
            ("DER / TSTInfo", fam_der), ("Ed25519", fam_ed25519), ("key_id confusion", fam_keyid),
            ("time ties and grammar", fam_time), ("criteria bytes", fam_criteria_bytes),
            ("relying party keys", fam_rp), ("relying party keys 1.4.7", fam_rp_147), ("1.4.8", fam_148),
            ("1.4.11", fam_1411)]


def _ours(case):
    if isinstance(case, str):
        try:
            doc = wv.strict_json_loads(case.encode("utf-8", "surrogatepass"))
        except wv.Refusal as e:
            return {"refused": True, "reason": e.reason}
        return wv.run_vector(doc)[0]
    return wv.run_vector(json.loads(json.dumps(case)))[0]


def _lax(case):
    text = case if isinstance(case, str) else json.dumps(case)
    try:
        return lax_verify.verify_text(text)
    except Exception as e:
        return {"crashed": True, "reason": "%s: %s" % (type(e).__name__, e)}


def meets(rep, exp):
    if exp == REF:
        return bool(rep.get("refused"))
    if rep.get("refused") or rep.get("crashed"):
        return False
    for k, v in exp.items():
        if k == "local_blocks_include":
            if v not in (rep.get("local_blocks") or []):
                return False
            continue
        mine = rep.get(k)
        if isinstance(v, list):
            if not isinstance(mine, list) or set(mine) != set(v):
                return False
        elif mine != v:
            return False
    return True


def run():
    base = build.base()
    out = []
    for fname, fam in FAMILIES:
        for name, case, exp in fam(base):
            o, l = _ours(case), _lax(case)
            out.append({"family": fname, "case": name, "expected": exp, "ours_ok": meets(o, exp),
                        "lax_ok": meets(l, exp), "ours": {k: o.get(k) for k in ("refused", "reason", "problem_codes",
                        "warning_codes", "signature_valid", "criteria_committed_before_check")},
                        "lax_accepted_as_stated": bool(l.get("accepted_as_stated"))})
    return out


if __name__ == "__main__":
    rows = run()
    fams = []
    for fname, _ in FAMILIES:
        rs = [r for r in rows if r["family"] == fname]
        fams.append((fname, len(rs), sum(r["ours_ok"] for r in rs), sum(not r["lax_ok"] for r in rs),
                     sum(r["lax_accepted_as_stated"] and not r["lax_ok"] for r in rs)))
    print("%-24s %6s %8s %12s %22s" % ("family", "cases", "ours ok", "lax caught", "lax wrongly accepts"))
    for f in fams:
        print("%-24s %6d %8d %12d %22d" % f)
    print("TOTAL cases %d, ours meets expectation %d, lax caught %d, lax wrongly accepted-as-stated %d" % (
        len(rows), sum(r["ours_ok"] for r in rows), sum(not r["lax_ok"] for r in rows),
        sum(r["lax_accepted_as_stated"] and not r["lax_ok"] for r in rows)))
    for r in rows:
        if not r["ours_ok"]:
            print("OURS FAILS:", r["family"], "|", r["case"], "| expected", r["expected"], "| got", r["ours"])
    if len(sys.argv) > 2 and sys.argv[1] == "--json":
        with open(sys.argv[2], "w") as fh:
            json.dump(rows, fh, indent=1, sort_keys=True, default=str)
