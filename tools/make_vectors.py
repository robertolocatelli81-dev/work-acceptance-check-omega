#!/usr/bin/env python3
"""Build the new vectors in vectors/ (CC0). Every `expected` object below is written by hand from the README text
(the sentence is in `reading`), never copied from a run of the verifier. Signed with the omega-test-* TEST keys
whose private seeds are published in every vector. usage: python3 -B tools/make_vectors.py"""
import base64
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import build  # noqa: E402
import testpki as tp  # noqa: E402
import war_verify as wv  # noqa: E402

OUT = os.path.join(ROOT, "vectors")
E = {"criteria_committed_before_check": "yes", "criteria_hash": "match", "independence": "independent",
     "problem_codes": [], "receipt_timestamp": "imprint_match", "signature_valid": True,
     "verdict_recomputed": "pass", "verdict_stated": "pass", "warning_codes": []}
REF = {"refused": True}


def exp(**kw):
    d = dict(E)
    d.update(kw)
    return d


def crit_doc(base, edit):
    doc = json.loads(base64.b64decode(base["criteria_file_base64"]))
    edit(doc)
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def set_criteria(inp, raw):
    inp["criteria_file_base64"] = base64.b64encode(raw).decode()
    inp["receipt"]["receipt"]["criteria"]["sha256"] = hashlib.sha256(raw).hexdigest()
    build.criteria_token(inp)
    build.refresh(inp)
    return inp


def R(inp):
    return inp["receipt"]["receipt"]


V = []


def vec(name, desc, reading, inputs, expected, ext=None, raw_text=None):
    V.append((name, desc, reading, inputs, expected, ext, raw_text))


def build_all():
    B = build.base()

    # ---------------------------------------------------------------- criteria correspondence (step 4)
    i = copy.deepcopy(B)
    R(i)["results"][1]["required"] = False
    R(i)["results"][1]["result"] = "not-evaluated"
    build.refresh(i)
    vec("required-downgraded-in-results", "c2 is required in the criteria document; the record lists it as optional "
        "and not-evaluated, so the recomputed verdict is pass.",
        "step 4: 'check the results correspond to the criteria'", i, exp(problem_codes=["CRITERIA_RESULTS_MISMATCH"]))

    i = copy.deepcopy(B)
    del R(i)["results"][2]
    build.refresh(i)
    vec("criterion-without-result", "The criteria document has c3; the record has no result for it.",
        "step 4: 'check the results correspond to the criteria'", i, exp(problem_codes=["CRITERIA_RESULTS_MISMATCH"]))

    i = copy.deepcopy(B)
    R(i)["results"].insert(2, copy.deepcopy(R(i)["results"][1]))
    build.refresh(i)
    vec("duplicate-result-id", "Two results carry id c2.", "step 4: 'check the results correspond to the criteria'",
        i, exp(problem_codes=["CRITERIA_RESULTS_MISMATCH"]), {"include": ["X_DUPLICATE_RESULT_ID"]})

    i = set_criteria(copy.deepcopy(B), b"[]")
    vec("criteria-document-not-a-criteria-list", "The criteria file hashes to criteria.sha256 but is the JSON text [].",
        "step 4: results cannot be shown to correspond to a document that lists no criteria", i,
        exp(problem_codes=["CRITERIA_RESULTS_MISMATCH"]))

    i = set_criteria(copy.deepcopy(B), crit_doc(B, lambda d: d["criteria"][0].pop("required")))
    vec("criterion-without-required-flag", "Criterion c1 in the criteria document has no boolean `required`.",
        "step 4: correspondence includes whether a criterion is required (property 4 recomputes from it)", i,
        exp(problem_codes=["CRITERIA_RESULTS_MISMATCH"]))

    i = set_criteria(copy.deepcopy(B), crit_doc(B, lambda d: d["criteria"].append(dict(d["criteria"][0]))))
    vec("duplicate-criterion-id", "The criteria document lists c1 twice.",
        "step 4: 'check the results correspond to the criteria'", i, exp(problem_codes=["CRITERIA_RESULTS_MISMATCH"]))

    def all_optional(d):
        for c in d["criteria"]:
            c["required"] = False
    i = set_criteria(copy.deepcopy(B), crit_doc(B, all_optional))
    for x in R(i)["results"]:
        x["required"] = False
    build.refresh(i)
    vec("no-required-criterion", "No criterion is required. Property 4 makes the verdict pass vacuously.",
        "property 4: 'The overall verdict is pass only if every required criterion is pass'", i, exp(),
        {"include": ["X_NO_REQUIRED_CRITERION"]})

    i = copy.deepcopy(B)
    R(i)["results"][0]["result"] = "error"
    R(i)["results"][2]["result"] = "fail"
    R(i)["verdict"] = "incomplete"
    build.refresh(i)
    vec("required-error-optional-fail", "A required error and an optional fail: incomplete (an optional fail does "
        "not make the verdict fail).", "property 4: 'Any required fail makes it fail ... otherwise any required "
        "not-evaluated or error makes it incomplete'", i, exp(verdict_recomputed="incomplete", verdict_stated="incomplete"))

    # ---------------------------------------------------------------- key identity (property 3, step 8)
    def keyed(sig_kid, rec_kid, ck, pk=None, signer=None, keys=None):
        i = copy.deepcopy(B)
        if keys:
            i["keys"] = keys
        R(i)["key_id"] = rec_kid
        R(i)["parties"]["checker"]["key_id"] = ck
        R(i)["parties"]["producer"]["key_id"] = pk
        i["receipt"]["signature"]["key_id"] = sig_kid
        build.refresh(i, sign_with=signer or sig_kid)
        return i

    kf = build.keyfile()
    kf["keys"].append(dict(kf["keys"][0], key_id="omega-test-1-alias"))
    vec("producer-key-is-checker-key-under-another-id", "parties.producer.key_id names an entry whose public key "
        "is the checker's key; the ids differ.", "property 3: 'The checker key must not equal the producer key' "
        "(keys, not identifiers)", keyed("omega-test-1", "omega-test-1", "omega-test-1", pk="omega-test-1-alias", keys=kf),
        exp(problem_codes=["KEY_COLLISION", "INDEPENDENCE_INCONSISTENT"]))
    vec("producer-key-is-signing-key", "The record is signed with the producer's key; parties.checker names another key.",
        "property 3 and step 8 CHECKER_NOT_SIGNER", keyed("omega-test-1", "omega-test-1", "omega-test-2", pk="omega-test-1"),
        exp(problem_codes=["CHECKER_NOT_SIGNER", "KEY_COLLISION", "INDEPENDENCE_INCONSISTENT"]))
    vec("receipt-key-id-names-another-key", "signature.key_id and parties.checker.key_id name the signing key; the "
        "signed receipt.key_id names the other published key.", "step 2: 'the key identified by `key_id`' (this "
        "verifier reads signature.key_id; see README, switches)", keyed("omega-test-1", "omega-test-2", "omega-test-1"),
        exp(), {"include": ["X_KEY_ID_SPLIT", "X_RECEIPT_KEY_ID_NOT_SIGNER"]})
    vec("signing-key-not-in-key-file", "signature.key_id names no key in the key file.",
        "step 2: the signature cannot be verified with 'the key identified by key_id'",
        keyed("omega-test-9", "omega-test-9", "omega-test-1", signer="omega-test-1"),
        exp(signature_valid=False, problem_codes=["SIGNATURE_INVALID", "CHECKER_NOT_SIGNER"]))
    vec("checker-key-id-null", "parties.checker.key_id is null.", "step 8 CHECKER_NOT_SIGNER: the checker is not "
        "shown to be the signer", keyed("omega-test-1", "omega-test-1", None), exp(problem_codes=["CHECKER_NOT_SIGNER"]))

    i = copy.deepcopy(B)
    R(i)["parties"]["producer"]["name"] = "example  CHECKER"
    build.refresh(i)
    vec("producer-name-equals-checker-name-after-normalisation", "Producer 'example  CHECKER', checker 'Example "
        "Checker', independence independent. Exact comparison sees two names.", "property 3 names the parties; "
        "the README does not define name equality", i, exp(), {"include": ["X_NAMES_EQUAL_AFTER_NORMALIZATION"]})

    # ---------------------------------------------------------------- tokens (steps 5 and 6)
    d = bytes.fromhex(R(B)["criteria"]["sha256"])
    for alg in ("sha3-256", "sha512-256"):
        i = copy.deepcopy(B)
        i["criteria_tsr_base64"] = base64.b64encode(tp.unsigned_tsr(tp.tstinfo(d, hash_oid=tp.SHA[alg]))).decode()
        vec("criteria-token-imprint-oid-%s" % alg, "The criteria token's hashAlgorithm is %s, a 32-byte hash: same "
            "length as SHA-256, so a length check alone does not catch it; the bytes equal criteria.sha256." % alg,
            "step 5: 'its imprint must equal criteria.sha256' (an imprint is algorithm + value, RFC 3161 2.4.1)", i,
            exp(problem_codes=["CRITERIA_TIMESTAMP_MISMATCH"], warning_codes=["CRITERIA_COMMITMENT_UNVERIFIED"]))
    i = copy.deepcopy(B)
    i["criteria_tsr_base64"] = base64.b64encode(tp.unsigned_tsr(tp.tstinfo(d, params=tp.octets(b"")))).decode()
    vec("criteria-token-sha256-with-parameters", "SHA-256 AlgorithmIdentifier with an OCTET STRING parameter.",
        "RFC 5754 2: SHA-256 parameters are absent (or NULL)", i,
        exp(problem_codes=["CRITERIA_TIMESTAMP_MISMATCH"], warning_codes=["CRITERIA_COMMITMENT_UNVERIFIED"]))
    i = copy.deepcopy(B)
    i["criteria_tsr_base64"] = base64.b64encode(tp.unsigned_tsr(tp.tstinfo(b"\x11" * 32, nonce=int.from_bytes(b"\x01" + d, "big")))).decode()
    vec("criteria-digest-only-in-nonce", "The criteria token's imprint is over other bytes; criteria.sha256 appears "
        "inside the nonce. A verifier that searches the token bytes for the digest calls it a match.",
        "step 5: the imprint, not any 32 bytes of the token", i,
        exp(problem_codes=["CRITERIA_TIMESTAMP_MISMATCH"], warning_codes=["CRITERIA_COMMITMENT_UNVERIFIED"]))
    i = copy.deepcopy(B)
    i["criteria_tsr_base64"] = base64.b64encode(tp.unsigned_tsr(tp.tstinfo(d, gen="20260301000000.5Z"))).decode()
    vec("criteria-gentime-fraction-same-second", "committed_at 2026-03-01T00:00:00Z, criteria token genTime "
        "20260301000000.5Z. At committed_at's own precision the two agree.", "step 5: 'a criteria.committed_at that "
        "disagrees' (this verifier: equal when genTime is truncated to committed_at's precision; switch "
        "--time-agreement exact disagrees)", i, exp())

    i = copy.deepcopy(B)
    i["receipt"]["timestamp"]["digest_sha256"] = "ab" * 32
    vec("timestamp-metadata-disagrees-with-token", "The unsigned envelope says the token covers other bytes; the "
        "token itself covers this receipt.", "step 6 compares the token's imprint, not the envelope's description",
        i, exp(), {"include": ["X_TIMESTAMP_METADATA_DISAGREES"]})

    i = copy.deepcopy(B)
    R(i)["issued_utc"] = "2026-06-01T12:00:00Z"
    R(i)["criteria"]["committed_at"] = "2026-06-01T12:30:00Z"
    build.criteria_token(i, gen="20260601123000Z")
    build.sign(i)
    build.record_token(i, gen="20260601130000Z")
    i["receipt"]["timestamp"] = {"reason": "not requested", "status": "none"}
    vec("token-supplied-record-declares-none", "The unsigned envelope says no timestamp; a token covering this "
        "receipt (13:00) is supplied anyway. Criteria committed 12:30, issued_utc 12:00. The supplied token decides, "
        "not the unsigned envelope (otherwise deleting an unsigned member would change the outcome).",
        "step 5: 'when a token covering the record is supplied'; step 6 imprint check on the supplied token", i,
        exp(receipt_timestamp="imprint_match"), {"include": ["X_TOKEN_SUPPLIED_RECORD_DECLARES_NONE"]})

    i = copy.deepcopy(B)
    i["criteria_tsr_base64"] = base64.b64encode(tp.seq(tp.seq(tp.integer(2)))).decode()
    vec("criteria-token-rejected", "The criteria TimeStampResp has status rejection and no token.",
        "step 5: 'Without a token, fall back to committed_at and warn'", i,
        exp(warning_codes=["CRITERIA_COMMITMENT_UNVERIFIED"]), {"include": ["X_CRITERIA_TOKEN_NOT_GRANTED"]})
    i = copy.deepcopy(B)
    i["receipt_tsr_base64"] = base64.b64encode(tp.seq(tp.seq(tp.integer(2)))).decode()
    vec("record-token-rejected", "The record's TimeStampResp has status rejection and no token.",
        "step 6: 'none (no timestamp or no token supplied)'", i, exp(receipt_timestamp="none"),
        {"include": ["X_RECORD_TOKEN_NOT_GRANTED"]})

    i = copy.deepcopy(B)
    build.criteria_token(i, gen="20260601120000Z", accuracy=(1, None, None))
    R(i)["criteria"]["committed_at"] = "2026-06-01T12:00:00Z"
    build.sign(i)
    build.record_token(i, gen="20260601120001Z", accuracy=(1, None, None))
    vec("ordering-not-provable-under-accuracy", "Criteria token 12:00:00 +-1 s, record token 12:00:01 +-1 s, no "
        "ordering flag. The profile's strict comparison says yes; RFC 3161 2.4.2 says these two tokens can be "
        "ordered only when the difference exceeds the sum of the accuracies.", "step 5 'strictly earlier' (profile); "
        "RFC 3161 2.4.2 accuracy/ordering (not in the profile)", i, exp(),
        {"include": ["X_ORDER_NOT_PROVABLE_UNDER_ACCURACY"]})
    i = copy.deepcopy(B)
    name = tp._name("war-verify TEST TSA").public_bytes()
    build.criteria_token(i, gen="20260601120000Z", ordering=True, tsa_name_der=name)
    R(i)["criteria"]["committed_at"] = "2026-06-01T12:00:00Z"
    build.sign(i)
    build.record_token(i, gen="20260601120001Z", ordering=True, tsa_name_der=name)
    vec("ordering-true-same-tsa", "Both tokens carry ordering TRUE and the same TSA name, one second apart.",
        "RFC 3161 2.4.2: with ordering TRUE, tokens from the same TSA can always be ordered", i, exp(),
        {"exclude": ["X_ORDER_NOT_PROVABLE_UNDER_ACCURACY"]})

    # ---------------------------------------------------------------- delivered file (step 3: no code in the profile)
    i = copy.deepcopy(B)
    i["delivered_file_base64"] = base64.b64encode(b"not the delivered file").decode()
    vec("delivered-file-differs", "A delivered file is supplied whose SHA-256 is not files.remediated.sha256. "
        "The profile has no code for this; the profile fields are unchanged.", "step 3: 'compare its SHA-256 with "
        "files.remediated.sha256' (no code listed in step 8)", i, exp(),
        {"include": ["X_REMEDIATED_FILE_HASH_MISMATCH"]})

    # ---------------------------------------------------------------- Ed25519 and key file
    ident = (1).to_bytes(32, "little")
    i = copy.deepcopy(B)
    i["keys"]["keys"].append({"alg": "Ed25519", "key_id": "forge", "public_key_base64": base64.b64encode(ident).decode(), "status": "test"})
    R(i)["key_id"] = "forge"
    R(i)["parties"]["checker"]["key_id"] = "forge"
    i["receipt"]["signature"]["key_id"] = "forge"
    i["receipt"]["signature"]["value"] = base64.b64encode(ident + bytes(32)).decode()
    build.record_token(i)
    vec("identity-key-universal-forgery", "The key file lists the identity point as a key; the 'signature' is "
        "R = identity, S = 0, which satisfies the cofactorless equation for every message.",
        "RFC 8032 5.1.7 does not exclude small-order keys; this verifier refuses them (--ed25519 strict)", i, REF)
    A = wv.ed_decode(base64.b64decode(build.pub_b64("omega-test-2")))
    T8 = wv.ed_decode((0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7).to_bytes(32, "little"))
    i = copy.deepcopy(B)
    i["keys"]["keys"][1]["public_key_base64"] = base64.b64encode(wv._encode_point(wv._padd(A, T8))).decode()
    vec("mixed-order-key-in-key-file", "A key-file entry is a valid key plus an 8-torsion point: the holder of the "
        "original scalar can produce signatures accepted under it (about 1 in 8 nonces).",
        "property 3 key equality; RFC 8032 5.1.7", i, REF)
    i = copy.deepcopy(B)
    i["keys"]["keys"][1]["public_key_base64"] = base64.b64encode((1 + wv._P).to_bytes(32, "little")).decode()
    vec("non-canonical-key-encoding", "A key-file entry encodes y = 1 + p.", "RFC 8032 5.1.3: decoding fails if y >= p",
        i, REF)

    # ---------------------------------------------------------------- grammar (closed by construction)
    def g(name, desc, edit, reading="this verifier: outside the grammar = refusal (README: 'refuse an unknown schema')",
          envelope=False):
        i = copy.deepcopy(B)
        if envelope:            # unsigned envelope edits go AFTER re-signing, or refresh() would rebuild them
            edit(i)
        else:
            edit(i)
            build.refresh(i)
        vec(name, desc, reading, i, REF)

    g("unknown-member-in-receipt", "The signed receipt carries a member the profile does not define.",
      lambda i: R(i).__setitem__("x_extra", "1"))
    g("commitment-not-rfc3161", "criteria.commitment is 'counterparty-terms'.",
      lambda i: R(i)["criteria"].__setitem__("commitment", "counterparty-terms"),
      "property 2 mentions 'a binding to terms the counterparty signed' without naming it: not implemented")
    g("independence-other-value", "independence is 'partially-independent'.",
      lambda i: R(i).__setitem__("independence", "partially-independent"))
    g("results-not-a-list", "results is an object.", lambda i: R(i).__setitem__("results", {}))
    g("required-not-boolean", "results[0].required is the string 'true'.",
      lambda i: R(i)["results"][0].__setitem__("required", "true"))
    g("human-review-scope-not-list", "human_review.scope is a string.",
      lambda i: R(i)["human_review"].__setitem__("scope", "all"))
    g("pages-not-integer", "files.remediated.pages is the string '1'.",
      lambda i: R(i)["files"]["remediated"].__setitem__("pages", "1"))
    g("original-bytes-not-integer", "files.original.bytes is the string '22'.",
      lambda i: R(i)["files"]["original"].__setitem__("bytes", "22"))
    g("timestamp-covers-other-object", "envelope.timestamp.covers names another object.",
      lambda i: i["receipt"]["timestamp"].__setitem__("covers", "sha256 of the delivered file"), envelope=True)
    g("timestamp-status-other", "envelope.timestamp.status is 'pending'.",
      lambda i: i["receipt"]["timestamp"].__setitem__("status", "pending"), envelope=True)
    g("signature-alg-other", "signature.alg is 'EdDSA'.", lambda i: i["receipt"]["signature"].__setitem__("alg", "EdDSA"),
      "step 1: refuse an unknown suite", envelope=True)
    i = copy.deepcopy(B)
    i["criteria_tsr_base64"] = base64.b64encode(tp.unsigned_tsr(tp.tstinfo(d, gen="20261231235960Z"))).decode()
    vec("criteria-gentime-leap-second", "Criteria token genTime 20261231235960Z (no leap second is scheduled).",
        "RFC 3161 2.4.2 GeneralizedTime; this verifier refuses second 60", i, REF)
    i = copy.deepcopy(B)
    vec("duplicate-member-in-receipt", "The receipt object has two 'verdict' members; JSON parsers that keep the "
        "last one see the signed value.", "RFC 8785 3.1 / RFC 7493 2.3: names MUST be unique", i, REF,
        raw_text="DUP_VERDICT")
    vec("lone-surrogate-in-finding", "A finding contains the escape \\ud800 (a lone surrogate).",
        "RFC 8785 3.2.2.2 / RFC 7493 2.1", copy.deepcopy(B), REF, raw_text="SURROGATE")


def write():
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT):
        if f.endswith(".json"):
            os.remove(os.path.join(OUT, f))
    for n, (name, desc, reading, inputs, expected, ext, raw) in enumerate(V, 1):
        vname = "omega-%02d-%s" % (n, name)
        doc = build.vector(vname, desc, inputs, expected)
        doc["reading"] = reading
        if ext:
            doc["expected_extensions"] = ext
        text = build.dumps(doc)
        if raw == "DUP_VERDICT":
            text = text.replace('"verdict": "pass"', '"verdict": "fail",\n     "verdict": "pass"', 1)
        elif raw == "SURROGATE":
            text = text.replace('"finding": "Met."', '"finding": "Met.\\ud800"', 1)
        with open(os.path.join(OUT, vname + ".json"), "w", encoding="utf-8") as fh:
            fh.write(text)
    print("wrote %d vectors to %s" % (len(V), OUT))


if __name__ == "__main__":
    build_all()
    write()
