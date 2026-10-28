#!/usr/bin/env python3
"""Generative attack over the input space (part c). Every case carries an expectation written from the README /
RFC text (not from running the verifier): "refused", or a subset of report fields. The same cases are run against
war_verify and against tools/lax_verify.py (positive control: the attack must catch the lax verifier).

usage: nice -n 10 python3 -B tools/fuzz.py [--json OUT]"""
import base64
import copy
import hashlib
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


def _exp_for(path):
    if tuple(path) == ("receipt", "timestamp", "digest_sha256"):
        return ENVELOPE_TS_EXPECT
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
                {"inputs": finish(inp, path)}, _exp_for(path)


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
        exp = {"criteria_hash": "match", "problem_codes": ["CRITERIA_RESULTS_MISMATCH"] if name == "BOM prefix" else []}
        yield "criteria file %s, record re-hashed to it" % name, {"inputs": inp}, exp


FAMILIES = [("unknown member", fam_unknown_member), ("duplicate member", fam_duplicate_member),
            ("wrong type", fam_wrong_type), ("lone surrogate", fam_surrogate), ("numbers", fam_numbers),
            ("DER / TSTInfo", fam_der), ("Ed25519", fam_ed25519), ("key_id confusion", fam_keyid),
            ("time ties and grammar", fam_time), ("criteria bytes", fam_criteria_bytes)]


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
