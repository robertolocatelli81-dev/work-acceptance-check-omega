"""A DELIBERATELY LAX verifier, used only as the positive control of the generative attack: if the attack cannot
catch this one, the attack proves nothing. It follows the README's rules on the happy path but takes every
shortcut a hurried implementation takes: plain json.loads (last duplicate wins, lone surrogates kept, floats
accepted), json.dumps as "JCS", signature.key_id only, the digest searched as a substring of the token, genTime
found with a regular expression, unknown members and wrong types ignored."""
import base64
import hashlib
import json
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VOCAB = ("pass", "fail", "not-evaluated", "error")


def _t(s):
    s = s.replace("Z", "")
    for f in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y%m%d%H%M%S.%f", "%Y%m%d%H%M%S"):
        try:
            return datetime.strptime(s, f).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _gentime(raw):
    m = re.search(rb"\x18\x0f([0-9]{14}Z)", raw) or re.search(rb"\x18.([0-9]{14}[0-9.]*Z?)", raw)
    return _t(m.group(1).decode()) if m else None


def verify_text(text):
    doc = json.loads(text)
    inp = doc.get("inputs", doc)
    env = inp["receipt"]
    r = env["receipt"]
    if r.get("schema") != "trilatic.acceptance-receipt/1.2":
        return {"refused": True, "reason": "unknown schema, canonicalization or suite"}
    canon = json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    keys = {k["key_id"]: k for k in inp["keys"]["keys"]}
    kid = env["signature"]["key_id"]
    ok = False
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[kid]["public_key_base64"])).verify(
            base64.b64decode(env["signature"]["value"]), canon)
        ok = True
    except (KeyError, InvalidSignature, ValueError, TypeError):
        pass
    probs, warns = set(), set()
    if not ok:
        probs.add("SIGNATURE_INVALID")
    ch = "not-supplied"
    if inp.get("criteria_file_base64"):
        ch = "match" if hashlib.sha256(base64.b64decode(inp["criteria_file_base64"])).hexdigest() == r["criteria"]["sha256"] else "mismatch"
        if ch == "mismatch":
            probs.add("CRITERIA_HASH_MISMATCH")
    rec_digest = hashlib.sha256(canon).digest()
    rts, ref = "none", _t(r["issued_utc"])
    if inp.get("receipt_tsr_base64") and (env.get("timestamp") or {}).get("status") == "granted":
        raw = base64.b64decode(inp["receipt_tsr_base64"])
        if rec_digest in raw:
            rts = "imprint_match"
            ref = _gentime(raw) or ref
        else:
            rts = "imprint_mismatch"
    commit = None
    if inp.get("criteria_tsr_base64"):
        raw = base64.b64decode(inp["criteria_tsr_base64"])
        if bytes.fromhex(r["criteria"]["sha256"]) in raw:
            commit = _gentime(raw)
            if commit != _t(r["criteria"]["committed_at"]):
                probs.add("CRITERIA_TIME_MISMATCH")
        else:
            probs.add("CRITERIA_TIMESTAMP_MISMATCH")
    if commit is None:
        warns.add("CRITERIA_COMMITMENT_UNVERIFIED")
        commit = _t(r["criteria"]["committed_at"])
    before = "yes" if commit and ref and commit < ref else "no"
    if before == "no":
        probs.add("CRITERIA_COMMITTED_AFTER_CHECK")
    req = [x.get("result") for x in r.get("results", []) if x.get("required")]
    v = "fail" if "fail" in req else ("pass" if all(x == "pass" for x in req) else "incomplete")
    if any(x.get("result") not in VOCAB for x in r.get("results", [])):
        probs.add("RESULT_VOCABULARY")
    if v != r.get("verdict"):
        probs.add("VERDICT_MISMATCH")
    p = r.get("parties", {})
    ck, pk = p.get("checker", {}).get("key_id"), p.get("producer", {}).get("key_id")
    if ck != kid:
        probs.add("CHECKER_NOT_SIGNER")
    if pk and pk == ck:
        probs.add("KEY_COLLISION")
    if r.get("independence") == "self-checked":
        warns.add("SELF_CHECKED")
    elif p.get("checker", {}).get("name") == p.get("producer", {}).get("name") or (pk and pk == ck):
        probs.add("INDEPENDENCE_INCONSISTENT")
    if not p.get("producer", {}).get("name") and not pk:
        warns.add("PRODUCER_UNDECLARED")
    return {"signature_valid": ok, "criteria_hash": ch, "independence": r.get("independence"),
            "problem_codes": sorted(probs), "warning_codes": sorted(warns), "receipt_timestamp": rts,
            "verdict_recomputed": v, "verdict_stated": r.get("verdict"), "criteria_committed_before_check": before,
            "accepted_as_stated": ok and not probs}
