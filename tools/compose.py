#!/usr/bin/env python3
"""Part (e): a counterparty acceptance that references a work-acceptance record by digest, checked UNCHANGED by
~/progetti/x402-acceptance-check-omega/acceptance_check.py (our own acceptance-record checker), plus the glue
check that neither checker does alone. Writes cases to compose/ and prints a table. Run with python3 -B (the other
checker is executed with -B so that nothing is written into its directory)."""
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import build  # noqa: E402
import war_verify as wv  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

X402 = os.path.expanduser("~/progetti/x402-acceptance-check-omega/acceptance_check.py")
CP_SEED = hashlib.sha256(b"war-verify-omega TEST counterparty key - published seed, never trust").digest()
CP = Ed25519PrivateKey.from_private_bytes(CP_SEED)
OUT = os.path.join(ROOT, "compose")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def raw_pub(k):
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def jcs_strings(obj):
    return wv.jcs(obj)        # for an all-string object RFC 8785 is the same function


def projection(war_inputs):
    """The only shape the x402 checker accepts: a flat object of strings (its README A-section)."""
    r = war_inputs["receipt"]["receipt"]
    inst = wv.parse_rfc3339z(r["issued_utc"], "issued_utc")
    if inst["digits"]:
        raise ValueError("projection only written for seconds-precision issued_utc")
    return {"issuer": r["issuer"], "issuer_kid": r["key_id"], "terms_sha256": r["criteria"]["sha256"],
            "outcome_sha256": r["files"]["remediated"]["sha256"],
            "outcome_at": r["issued_utc"][:-1] + ".000Z",
            "record_id": "war-sha256:" + hashlib.sha256(wv.jcs(r)).hexdigest()}


def acceptance(rec, accepted_at="2026-06-02T09:00:00.000Z", disposition="accepted"):
    hdr = b64u(json.dumps({"alg": "EdDSA", "kid": "cp-1"}, separators=(",", ":")).encode())
    pl = {"acceptance_version": "acceptance-record-v0", "accepted_at": accepted_at,
          "accepted_record_sha256": hashlib.sha256(jcs_strings(rec)).hexdigest(), "confirming_party": "Example Client",
          "disposition": disposition, "outcome_sha256": rec["outcome_sha256"], "terms_sha256": rec["terms_sha256"]}
    p = b64u(json.dumps(pl, separators=(",", ":"), sort_keys=True).encode())
    sig = CP.sign((hdr + "." + p).encode())
    return {"protected": hdr, "payload": p, "signature": b64u(sig)}


def case(rec, acc):
    return {"accepted_record": rec, "acceptance": acc,
            "trust_material": {"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "cp-1", "x": b64u(raw_pub(CP))},
                                        {"kty": "OKP", "crv": "Ed25519", "kid": "omega-test-1",
                                         "x": b64u(raw_pub(build.priv("omega-test-1")))}]},
            "delegation": {"Example Client": ["cp-1"]}, "trust_material_complete": True}


def run_x402(name, c):
    path = os.path.join(OUT, name + ".json")
    with open(path, "w") as fh:
        json.dump(c, fh, indent=1, sort_keys=True)
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    p = subprocess.run([sys.executable, "-B", X402, path], capture_output=True, text=True, env=env)
    try:
        rep = json.loads(p.stdout)
    except ValueError:
        rep = {"result": "unparseable output", "stderr": p.stderr[-300:]}
    return p.returncode, rep


def glue(case_doc, war_inputs):
    """What neither checker does: (1) the WAR verifies; (2) record_id = sha256 of the WAR's canonical receipt;
    (3) terms/outcome/issuer in the projection equal the WAR's fields."""
    rep = wv.verify(copy.deepcopy(war_inputs))
    rec = case_doc["accepted_record"]
    proj = projection(war_inputs)
    return {"war_accepted_as_stated": rep["accepted_as_stated"], "war_verdict": rep["verdict_recomputed"],
            "record_id_binds_war": rec.get("record_id") == proj["record_id"],
            "projection_equal": all(rec.get(k) == proj[k] for k in proj)}


def main():
    os.makedirs(OUT, exist_ok=True)
    war = build.base()
    war_fail = build.base()
    rr = war_fail["receipt"]["receipt"]
    rr["results"][0]["result"] = "fail"
    rr["verdict"] = "fail"
    build.refresh(war_fail)
    rows = []
    # 1. the WAR receipt itself as accepted_record
    raw_rec = war["receipt"]["receipt"]
    rc, rep = run_x402("1-war-receipt-as-is", case(raw_rec, acceptance(projection(war))))
    rows.append(("WAR receipt object passed unchanged as accepted_record", rc, rep.get("result"), rep.get("reasons"), None))
    # 2. string projection of a valid WAR
    rec = projection(war)
    c2 = case(rec, acceptance(rec))
    rc, rep = run_x402("2-projection", c2)
    rows.append(("string projection of a valid WAR", rc, rep.get("result"), rep.get("conditions"), glue(c2, war)))
    # 3. same acceptance, presented with ANOTHER WAR (verdict fail) as the evidence
    rc, rep = run_x402("3-projection-other-war", c2)
    rows.append(("same acceptance, relying party holds a different WAR (verdict fail)", rc, rep.get("result"),
                 rep.get("conditions"), glue(c2, war_fail)))
    # 4. projection of the failing WAR, accepted by the counterparty: x402 verifies; the WAR says fail
    recf = projection(war_fail)
    c4 = case(recf, acceptance(recf))
    rc, rep = run_x402("4-acceptance-of-failed-war", c4)
    rows.append(("counterparty 'accepted' a WAR whose recomputed verdict is fail", rc, rep.get("result"),
                 rep.get("conditions"), glue(c4, war_fail)))
    # 5. issued_utc with seconds precision cannot be used as outcome_at unchanged
    rec5 = dict(rec, outcome_at=raw_rec["issued_utc"])
    rc, rep = run_x402("5-outcome-at-unconverted", case(rec5, acceptance(rec5)))
    rows.append(("outcome_at = issued_utc copied unchanged (seconds precision)", rc, rep.get("result"), rep.get("reasons"), None))
    # 6. checker signs the acceptance (same key as the WAR): x402 must flag acceptance_signer_is_issuer
    hdr = b64u(json.dumps({"alg": "EdDSA", "kid": "omega-test-1"}, separators=(",", ":")).encode())
    a6 = acceptance(rec)
    pl = a6["payload"]
    a6 = {"protected": hdr, "payload": pl,
          "signature": b64u(build.priv("omega-test-1").sign((hdr + "." + pl).encode()))}
    c6 = case(rec, a6)
    c6["delegation"] = {"Example Client": ["cp-1", "omega-test-1"]}
    rc, rep = run_x402("6-checker-signs-acceptance", c6)
    rows.append(("the checker's own key signs the counterparty acceptance", rc, rep.get("result"), rep.get("conditions"), None))
    with open(os.path.join(OUT, "RESULTS.json"), "w") as fh:
        json.dump([{"case": a, "x402_exit": b, "x402_result": c, "x402_detail": d, "glue": e} for a, b, c, d, e in rows],
                  fh, indent=1, sort_keys=True)
    for r in rows:
        print("%-72s x402 exit=%s result=%s %s glue=%s" % r)


if __name__ == "__main__":
    main()
