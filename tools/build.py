"""Builders for new test inputs: fresh TEST keys (seeds published, NEVER trust), re-signing, structural tokens.
Starting point is upstream vector 01's inputs (CC0)."""
import base64
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import war_verify as wv  # noqa: E402
import testpki as tp  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

SEEDS = {
    "omega-test-1": hashlib.sha256(b"war-verify-omega TEST key 1 - published seed, never trust").hexdigest(),
    "omega-test-2": hashlib.sha256(b"war-verify-omega TEST key 2 - published seed, never trust").hexdigest(),
}
TEST_KEY_WARNING = "TEST keys: the private seeds are published in this file. Never trust a record signed by them."


def priv(kid):
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEEDS[kid]))


def pub_b64(kid):
    raw = priv(kid).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def keyfile(kids=("omega-test-1", "omega-test-2")):
    return {"issuer": "war-verify-omega (TEST keys, never trust)",
            "keys": [{"alg": "Ed25519", "key_id": k, "public_key_base64": pub_b64(k), "status": "test"} for k in kids]}


def b64(b):
    return base64.b64encode(b).decode()


def load(path):
    with open(path, "rb") as fh:
        return wv.strict_json_loads(fh.read())


def upstream(n):
    import glob
    return load(glob.glob(os.path.join(ROOT, "fonti/upstream_f7d8984/vectors/%02d-*.json" % n))[0])


def sign(inputs, kid=None, sign_with=None):
    """Re-sign the receipt with the TEST key named by signature.key_id (or sign_with)."""
    env = inputs["receipt"]
    kid = sign_with or env["signature"]["key_id"]
    env["signature"]["value"] = b64(priv(kid).sign(wv.jcs(env["receipt"])))
    return inputs


def record_token(inputs, gen="20260601120005Z", digest=None, **kw):
    env = inputs["receipt"]
    d = digest if digest is not None else hashlib.sha256(wv.jcs(env["receipt"])).digest()
    inputs["receipt_tsr_base64"] = b64(tp.unsigned_tsr(tp.tstinfo(d, gen=gen, **kw)))
    env["timestamp"] = {"covers": wv.COVERS, "digest_sha256": d.hex(), "gen_time": gen, "status": "granted",
                        "tsa": "test-tsa.invalid", "tsr_file": "receipt.tsr"}
    return inputs


def criteria_token(inputs, gen="20260301000000Z", digest=None, **kw):
    d = digest if digest is not None else bytes.fromhex(inputs["receipt"]["receipt"]["criteria"]["sha256"])
    inputs["criteria_tsr_base64"] = b64(tp.unsigned_tsr(tp.tstinfo(d, gen=gen, **kw)))
    return inputs


def base(token=True):
    """Vector 01 re-keyed to omega-test-1, re-signed, record token rebuilt over the new receipt."""
    inp = copy.deepcopy(upstream(1)["inputs"])
    inp["keys"] = keyfile()
    r = inp["receipt"]["receipt"]
    r["key_id"] = "omega-test-1"
    r["parties"]["checker"]["key_id"] = "omega-test-1"
    inp["receipt"]["signature"]["key_id"] = "omega-test-1"
    sign(inp)
    if token:
        record_token(inp)
    else:
        inp["receipt_tsr_base64"] = None
        inp["receipt"]["timestamp"] = {"reason": "not requested", "status": "none"}
    return inp


def refresh(inp, token_gen=None, sign_with=None):
    """After editing the receipt: re-sign, and rebuild the record token if one is declared."""
    sign(inp, sign_with=sign_with)
    ts = inp["receipt"].get("timestamp")
    if ts and ts.get("status") == "granted" and inp.get("receipt_tsr_base64"):
        record_token(inp, gen=token_gen or ts["gen_time"])
    return inp


def vector(name, description, inputs, expected, kills=None, extra=None):
    d = {"vector": name, "title": name, "description": description, "inputs": inputs, "expected": expected,
         "license": "CC0-1.0", "warning": TEST_KEY_WARNING,
         "test_key": {k: {"private_seed_hex": v, "public_key_base64": pub_b64(k)} for k, v in SEEDS.items()},
         "contributed_by": "war-verify-omega (Roberto Locatelli), CC0; expected = this verifier's reading of profile 1.3 "
                           "(README 42b4ed0); expected_1_2_1 (where present): its reading of 1.2.1 (README f7d8984)"}
    if kills:
        d["kills"] = kills
    if extra:
        d.update(extra)
    return d


def dumps(doc):
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
