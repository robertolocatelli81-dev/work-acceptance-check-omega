"""NEMESIS round 1: kills for the 14 surviving mutants + regressions for the findings.
usage: python3 tests/nemesis_r1_check.py DIR_WITH_war_verify.py FONTI_DIR"""
import sys, os, json, copy, base64, hashlib, subprocess, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
D, FONTI = sys.argv[1], sys.argv[2]
sys.path.insert(0, D); import war_verify as wv
from _nemesis_forge import *
V01 = os.path.join(FONTI, "upstream_f7d8984/vectors/01-valid.json")
k = Key(7, "ck")
def base():
    i = copy.deepcopy(json.load(open(V01))["inputs"]); r = i["receipt"]["receipt"]
    r["key_id"] = "ck"; r["parties"]["checker"]["key_id"] = "ck"; return i, r
def mk(r=None, i=None, **kw):
    if i is None: i, r0 = base(); r = r if r is not None else r0
    kw.setdefault("crit_gen", "20260301000000Z"); kw.setdefault("rec_gen", "20260601120005Z")
    return build(i, k, receipt=r, **kw)
def run(x, opts=None, keys=None):
    try: return wv.verify(wv.strict_json_loads(json.dumps(x).encode()), opts, keys)   # the CLI path: strict loader first
    except wv.Refusal as e: return {"refused": True, "reason": e.reason}
def cli(args, doc=None):
    with tempfile.TemporaryDirectory() as t:
        f = os.path.join(t, "in.json")
        if doc is not None: json.dump(doc, open(f, "w"))
        # adapted by the author: "-I" -> "-B" with PYTHONPATH removed ("-I" hides a user-site cryptography)
        env = dict(os.environ); env.pop("PYTHONPATH", None)
        p = subprocess.run([sys.executable, "-B", os.path.join(D, "war_verify.py")] + [a if a != "@" else f for a in args],
                           capture_output=True, text=True, env=env)
        try: out = json.loads(p.stdout)
        except Exception: out = None
        return p.returncode, out
FAILS = []
def check(name, cond):
    print(("ok   " if cond else "FAIL ") + name); cond or FAILS.append(name)
# ---------------------------------------------------------------- vectors (24, 22 under its proposed rule)
for sub in ("upstream_f7d8984/vectors", "tetsurohhori_4f6cf49", "babyblueviper1_431525f", "issuer_274159c"):
    for f in sorted(os.listdir(os.path.join(FONTI, sub))):
        if not f.endswith(".json") or f in ("TEST_KEY.json", "checker-keys-live.json"): continue
        d = wv.strict_json_loads(open(os.path.join(FONTI, sub, f), "rb").read())
        rep, cmp_ = wv.run_vector(d, {"reference_time": "earlier"} if f.startswith("22-") else None)
        check("vector " + f, cmp_["agree"])
# ---------------------------------------------------------------- kills
# M06: R = identity (nonce 0), a signature RFC 8032 cofactorless accepts; strict must refuse it
i, r = base(); x = mk(r, i)
h = hashlib.sha512(bytes([7]) * 32).digest(); a = int.from_bytes(h[:32], "little")
a &= (1 << 254) - 8; a |= 1 << 254
ident = wv._encode_point(wv._IDENT); canon = wv.jcs(x["receipt"]["receipt"])
kk = int.from_bytes(hashlib.sha512(ident + k.pub + canon).digest(), "little") % wv._L
x["receipt"]["signature"]["value"] = b64(ident + ((kk * a) % wv._L).to_bytes(32, "little"))
check("M06 R=identity refused in strict", run(x)["signature_valid"] is False)
check("M06 control: same signature valid under rfc8032 (RFC 8032 5.1.7)", run(x, {"ed25519": "rfc8032"})["signature_valid"] is True)
# M18: required fail + required error -> fail (property 4: fail takes precedence)
for order in (("fail", "error"), ("error", "fail")):
    i, r = base(); r["results"][0]["result"], r["results"][1]["result"] = order; r["verdict"] = "fail"
    rep = run(mk(r, i)); check("M18 verdict %s/%s -> fail" % order, rep["verdict_recomputed"] == "fail" and "VERDICT_MISMATCH" not in rep["problem_codes"])
# M23: producer and checker name the same (unknown) key id
i, r = base(); r["parties"]["checker"]["key_id"] = "ghost"; r["parties"]["producer"]["key_id"] = "ghost"
check("M23 same key_id -> KEY_COLLISION", "KEY_COLLISION" in run(mk(r, i))["problem_codes"])
# M41: producer key id = signature key id (not in the key file)
i, r = base(); r["parties"]["producer"]["key_id"] = "ghost"; x = mk(r, i, sig_kid="ghost")
check("M41 producer = signing key id -> KEY_COLLISION", "KEY_COLLISION" in run(x)["problem_codes"])
# M30: base64 with non-zero padding bits
x = mk(); kb = x["keys"]["keys"][0]["public_key_base64"]; A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
x["keys"]["keys"][0]["public_key_base64"] = kb[:42] + A[A.index(kb[42]) + 1] + "="
check("M30 non-canonical base64 refused", run(x).get("refused") is True and base64.b64decode(x["keys"]["keys"][0]["public_key_base64"]) == k.pub)
# M34: SET OF out of DER order (two digest algorithms, larger first)
i, r = base(); x = mk(r, i); dig = bytes.fromhex(r["criteria"]["sha256"])
algs = tlv(0x31, seq(oid("2.16.840.1.101.3.4.2.3")) + seq(oid("2.16.840.1.101.3.4.2.1")))
sd = seq(integer(3), algs, seq(oid("1.2.840.113549.1.9.16.1.4"), tlv(0xA0, tlv(4, tst(dig, "20260301000000Z")))))
x["criteria_tsr_base64"] = b64(seq(seq(integer(0)), seq(oid("1.2.840.113549.1.7.2"), tlv(0xA0, sd))))
check("M34 unordered SET OF refused", run(x).get("refused") is True)
# M36: duplicate key_id in the key file
x = mk(); x["keys"]["keys"].append(Key(9, "ck").entry())
check("M36 duplicate key_id refused", run(x).get("refused") is True)
# M44 / F9: integers at and beyond 2^53
for v in (2 ** 53, 2 ** 60):
    i, r = base(); r["revision"] = v
    check("M44/F9 revision %d refused" % v, run(mk(r, i)).get("refused") is True)
# M49: PKIStatus granted without a token
x = mk(); x["criteria_tsr_base64"] = b64(seq(seq(integer(0))))
check("M49 granted without token refused", run(x).get("refused") is True)
# M51: nesting deeper than 64 in a vector metadata member
doc = {"inputs": mk(), "reading": json.loads("[" * 70 + "]" * 70)}
try: wv.run_vector(wv.strict_json_loads(json.dumps(doc).encode())); r51 = False
except wv.Refusal: r51 = True
check("M51 depth 70 refused", r51)
# M53: upper-case hex
i, r = base(); r["criteria"]["sha256"] = r["criteria"]["sha256"].upper()
check("M53 upper-case hex refused", run(mk(r, i)).get("refused") is True)
# M59 / M60: non-canonical encodings of small-order points, rfc8032 mode
for nm, enc in (("M59 x=0 with sign bit", (1 | (1 << 255)).to_bytes(32, "little")), ("M60 y>=p", (wv._P + 1).to_bytes(32, "little"))):
    x = mk(); x["keys"]["keys"].append({"alg": "Ed25519", "key_id": "weak", "public_key_base64": b64(enc), "status": "active"})
    check(nm + " refused in rfc8032", run(x, {"ed25519": "rfc8032"}).get("refused") is True)
# M66: criteria document says not required, result says required
i, r = base(); cd = json.loads(base64.b64decode(i["criteria_file_base64"])); cd["criteria"][0]["required"] = False
cdb = json.dumps(cd, separators=(",", ":")).encode(); i["criteria_file_base64"] = b64(cdb); r["criteria"]["sha256"] = hashlib.sha256(cdb).hexdigest()
check("M66 required differs -> CRITERIA_RESULTS_MISMATCH", "CRITERIA_RESULTS_MISMATCH" in run(mk(r, i))["problem_codes"])
# ---------------------------------------------------------------- findings (fail on the snapshot = positive control)
junk = tlv(0x31, seq(integer(1), seq(), seq(oid("2.16.840.1.101.3.4.2.1")), seq(oid("1.2.840.113549.1.1.11")), tlv(4, b"\0" * 8)))
i, r = base(); x = mk(r, i); x["criteria_tsr_base64"] = b64(tsr(tst(bytes.fromhex(r["criteria"]["sha256"]), "20260301000000Z"), junk))
check("F1 self-made token -> X_TSA_NOT_VERIFIED", "X_TSA_NOT_VERIFIED" in run(x)["extension_codes"])
check("F2 --keys '' -> 64", cli(["--keys", "", "@"], mk())[0] == 64)
# adapted by the author for 0.3.0: --tsa-roots without pkix is now valid (profile 1.4 anchors); an unreadable one is 74
check("F3 --tsa-roots without readable roots -> 74", cli(["--tsa-roots", "/nonexistent", "@"], mk())[0] == 74)
check("F3 repeated option -> 64", cli(["--tokens", "structural", "--tokens", "structural", "@"], mk())[0] == 64)
rep = run(mk()); check("F4 key from input reported", "X_KEY_FROM_INPUT" in rep["extension_codes"])
rep = run(json.load(open(V01))["inputs"]); check("F4 test key reported", "X_TEST_KEY" in rep["extension_codes"])
x = mk(); x["delivered_file_base64"] = b64(b"not the delivered file"); rc, out = cli(["@"], x)
check("F5 delivered mismatch -> exit 1", rc == 1 and out["report"]["accepted_as_stated"] is True)
i, r = base(); r["criteria"]["committed_at"] = "2026-06-01T12:30:00Z"; r["issued_utc"] = "2026-06-01T13:00:00Z"
for meta in ("absent", "none"):
    x = build(copy.deepcopy(i), k, receipt=copy.deepcopy(r), crit_gen="20260601123000Z", rec_gen="20260601120000Z", ts_meta=meta)
    check("F6 covering token used with metadata " + meta, "CRITERIA_COMMITTED_AFTER_CHECK" in run(x)["problem_codes"])
i, r = base(); r["key_id"] = "other"; x = mk(r, i, sig_kid="ck", keys={"issuer": "x", "keys": [k.entry(), Key(9, "other").entry()]})
check("F7 receipt.key_id not the signer -> exit 1", cli(["@"], x)[0] == 1)
i, r = base(); cd = json.loads(base64.b64decode(i["criteria_file_base64"])); cd["criteria"][0]["weight"] = 1
cdb = json.dumps(cd, separators=(",", ":")).encode(); i["criteria_file_base64"] = b64(cdb); r["criteria"]["sha256"] = hashlib.sha256(cdb).hexdigest()
check("F8 per-criterion member reported", any("criteria[0].weight" in n for n in run(mk(r, i))["notes"]))
x = mk(); x["keys"] = {"issuer": "x", "keys": [{"alg": "Ed25519", "key_id": "ck", "public_key_base64": b64(ident), "status": "active"}]}
x["receipt"]["signature"]["value"] = b64(ident + b"\0" * 32)
check("F11 X_WEAK_KEY in extension codes", "X_WEAK_KEY" in run(x, {"ed25519": "rfc8032"})["extension_codes"])
print("FAILED:", len(FAILS)); sys.exit(1 if FAILS else 0)
