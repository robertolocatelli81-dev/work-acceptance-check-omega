#!/usr/bin/env python3
"""Build the new vectors in vectors/ (CC0). Every `expected` object below is written by hand from the README text
(the sentence is in `reading`), never copied from a run of the verifier. Defaults follow profile 1.3
(maximusrufus/work-acceptance-record@42b4ed0); where this verifier's profile 1.2.1 reading (war_verify 0.1.0, selected
with --profile 1.2.1) gives other profile fields, they are in `expected_1_2_1`. Signed with the omega-test-* TEST keys
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


def vec(name, desc, reading, inputs, expected, ext=None, raw_text=None, old=None):
    V.append((name, desc, reading, inputs, expected, ext, raw_text, old))


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
        "signed receipt.key_id names the other published key.", "1.3 step 2: 'verify the Ed25519 signature with the "
        "key named by the signed `receipt.key_id`. The envelope's `signature.key_id` must equal it, else "
        "`SIGNATURE_INVALID`'; 'whether that key is `parties.checker.key_id` is a separate check "
        "(`CHECKER_NOT_SIGNER`)'. Changed at 1.3: under 1.2.1 this verifier read signature.key_id (no code).",
        keyed("omega-test-1", "omega-test-2", "omega-test-1"),
        exp(signature_valid=False, problem_codes=["SIGNATURE_INVALID", "CHECKER_NOT_SIGNER"]),
        {"include": ["X_KEY_ID_SPLIT"]}, old=exp())
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
        "1.3 step 5: 'the **earlier** of `issued_utc` and the genTime of the record's own token when a token covering "
        "the record is supplied' (12:00 < 12:30: not committed before); step 6 imprint check on the supplied token. "
        "Changed at 1.3: under 1.2.1 the covering token (13:00) was the reference (yes).", i,
        exp(receipt_timestamp="imprint_match", criteria_committed_before_check="no",
            problem_codes=["CRITERIA_COMMITTED_AFTER_CHECK"]), {"include": ["X_TOKEN_SUPPLIED_RECORD_DECLARES_NONE"]},
        old=exp(receipt_timestamp="imprint_match"))

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
        "ordering flag. Under profile 1.2.1 the strict comparison against the covering token said yes; RFC 3161 2.4.2 says these two tokens can be "
        "ordered only when the difference exceeds the sum of the accuracies. issued_utc is 12:00:00.", "1.3 step 5: "
        "the reference is the earlier of issued_utc (12:00:00) and the covering token (12:00:01), and the criteria "
        "token's accuracy widens 12:00:00 to 12:00:01: not strictly earlier. Changed at 1.3: under 1.2.1 the "
        "reference was the covering token and accuracy was ignored (yes). The accuracy cases with a later issued_utc "
        "are omega-46 to omega-49.", i,
        exp(criteria_committed_before_check="no", problem_codes=["CRITERIA_COMMITTED_AFTER_CHECK"]), old=exp())
    i = copy.deepcopy(B)
    name = tp._name("war-verify TEST TSA").public_bytes()
    build.criteria_token(i, gen="20260601120000Z", ordering=True, tsa_name_der=name)
    R(i)["criteria"]["committed_at"] = "2026-06-01T12:00:00Z"
    build.sign(i)
    build.record_token(i, gen="20260601120001Z", ordering=True, tsa_name_der=name)
    vec("ordering-true-same-tsa", "Both tokens carry ordering TRUE and the same TSA name, one second apart.",
        "1.3 step 5: the reference is the earlier of issued_utc (12:00:00, equal to the criteria token) and the "
        "covering token; `ordering` is ignored: not strictly earlier. Changed at 1.3: under 1.2.1 the covering token "
        "was the reference (yes; RFC 3161 2.4.2 ordering).", i,
        exp(criteria_committed_before_check="no", problem_codes=["CRITERIA_COMMITTED_AFTER_CHECK"]),
        {"exclude": ["X_ORDER_NOT_PROVABLE_UNDER_ACCURACY"]}, old=exp())

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
        "1.3 step 2 key rule: 'any other key (neutral point, small or mixed order, non-canonical) is `KEY_REJECTED` "
        "and no signature check is run'. Changed at 1.3: under 1.2.1 this verifier refused the input.", i,
        exp(signature_valid=False, problem_codes=["KEY_REJECTED"]), old=REF)
    A = wv.ed_decode(base64.b64decode(build.pub_b64("omega-test-2")))
    T8 = wv.ed_decode((0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7).to_bytes(32, "little"))
    i = copy.deepcopy(B)
    i["keys"]["keys"][1]["public_key_base64"] = base64.b64encode(wv._encode_point(wv._padd(A, T8))).decode()
    vec("mixed-order-key-in-key-file", "A key-file entry is a valid key plus an 8-torsion point: the holder of the "
        "original scalar can produce signatures accepted under it (about 1 in 8 nonces).",
        "1.3 step 2 key rule applies to 'the key named by the signed receipt.key_id'; this entry (omega-test-2) "
        "signs nothing here, so the profile fields are those of a valid record and this verifier blocks exit 0 "
        "(X_UNUSED_KEY_REJECTED; --key-rule all-keys gives KEY_REJECTED). Changed at 1.3: under 1.2.1 refused.", i,
        exp(), {"include": ["X_UNUSED_KEY_REJECTED"]}, old=REF)
    i = copy.deepcopy(B)
    i["keys"]["keys"][1]["public_key_base64"] = base64.b64encode((1 + wv._P).to_bytes(32, "little")).decode()
    vec("non-canonical-key-encoding", "A key-file entry (omega-test-2, not the signer) encodes y = 1 + p.",
        "1.3 step 2 key rule ('canonical encoding (y < p)') applies to the signer's key; this entry signs nothing: "
        "X_UNUSED_KEY_REJECTED, a local block. Changed at 1.3: under 1.2.1 refused.", i, exp(),
        {"include": ["X_UNUSED_KEY_REJECTED"]}, old=REF)

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

    # ---------------------------------------------------------------- profile 1.3 rulings (added 2026-10-18)
    vec("envelope-key-id-differs", "receipt.key_id and parties.checker.key_id name omega-test-1, which signed; the "
        "unsigned signature.key_id names omega-test-2.", "1.3 step 2: 'The envelope's `signature.key_id` must equal "
        "it, else `SIGNATURE_INVALID` (the envelope is unsigned, so it cannot choose the key)'",
        keyed("omega-test-2", "omega-test-1", "omega-test-1", signer="omega-test-1"),
        exp(signature_valid=False, problem_codes=["SIGNATURE_INVALID"]), {"include": ["X_KEY_ID_SPLIT"]},
        old=exp(signature_valid=False, problem_codes=["SIGNATURE_INVALID", "CHECKER_NOT_SIGNER"]))
    i = copy.deepcopy(B)
    A1 = wv.ed_decode(base64.b64decode(build.pub_b64("omega-test-1")))
    i["keys"]["keys"][0]["public_key_base64"] = base64.b64encode(wv._encode_point(wv._padd(A1, T8))).decode()
    vec("signer-key-mixed-order", "The signer's key-file entry (omega-test-1) is its key plus an 8-torsion point.",
        "1.3 step 2 key rule: 'small or mixed order ... is `KEY_REJECTED` and no signature check is run'", i,
        exp(signature_valid=False, problem_codes=["KEY_REJECTED"]), old=REF)

    def timed(issued, crit_gen, rec_gen, acc_c=None, acc_r=None, **kw):
        i = copy.deepcopy(B)
        R(i)["issued_utc"] = issued
        build.criteria_token(i, gen=crit_gen, accuracy=acc_c, **kw)
        R(i)["criteria"]["committed_at"] = "%s-%s-%sT%s:%s:%sZ" % (crit_gen[:4], crit_gen[4:6], crit_gen[6:8],
                                                                   crit_gen[8:10], crit_gen[10:12], crit_gen[12:14])
        build.sign(i)
        build.record_token(i, gen=rec_gen, accuracy=acc_r, **kw)
        return i
    W = "1.3 step 5: 'A token's stated `accuracy` widens its time against \"committed before\"; a token stating none " \
        "is taken at its genTime; `ordering` is ignored'"
    vec("accuracy-widens-to-no", "issued_utc 12:00:05; criteria token 12:00:00 +-1 s; covering record token "
        "12:00:01 +-1 s. The reference is the covering token (earlier than issued_utc).", W + ": 12:00:01 is not "
        "strictly earlier than 12:00:00", timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120001Z",
                                                 (1, None, None), (1, None, None)),
        exp(criteria_committed_before_check="no", problem_codes=["CRITERIA_COMMITTED_AFTER_CHECK"]), old=exp())
    vec("accuracy-apart-enough", "As omega-46 with the record token at 12:00:03 +-1 s.", W + ": 12:00:01 < "
        "12:00:02", timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120003Z", (1, None, None),
                          (1, None, None)), exp())
    vec("no-accuracy-taken-at-gentime", "issued_utc 12:00:05; criteria token 12:00:00 and record token 12:00:01, "
        "neither states accuracy.", W + " (this verifier's --accuracy interval would say undetermined)",
        timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120001Z"), exp())
    name = tp._name("war-verify TEST TSA").public_bytes()
    vec("ordering-true-ignored", "As omega-46 (+-1 s, one second apart) with ordering TRUE and the same TSA name on "
        "both tokens.", W + ": ordering does not narrow the comparison",
        timed("2026-06-01T12:00:05Z", "20260601120000Z", "20260601120001Z", (1, None, None), (1, None, None),
              ordering=True, tsa_name_der=name),
        exp(criteria_committed_before_check="no", problem_codes=["CRITERIA_COMMITTED_AFTER_CHECK"]), old=exp())
    vec("covering-token-lower-bound-before-issued", "issued_utc 12:00:07; criteria token 12:00:06 (no accuracy); "
        "covering record token 12:00:10 +-5 s, so the record may have existed from 12:00:05.", "this verifier's "
        "reading of 1.3 step 5 (not pinned by a published vector): the reference is taken at its earliest, "
        "min(issued_utc, genTime - accuracy) = 12:00:05, so 12:00:06 is not earlier. A literal reading that "
        "compares genTime 12:00:10 with issued_utc first and then ignores the token gives yes.",
        timed("2026-06-01T12:00:07Z", "20260601120006Z", "20260601120010Z", None, (5, None, None)),
        exp(criteria_committed_before_check="no", problem_codes=["CRITERIA_COMMITTED_AFTER_CHECK"]), old=exp())
    i = copy.deepcopy(B)
    R(i)["independence"] = "self-checked"
    build.refresh(i)
    vec("stated-self-checked-derived-independent", "independence self-checked; producer 'Example Vendor' with no "
        "key, checker 'Example Checker': the parties block derives independent.", "1.3 step 8: 'a stated "
        "`independence` that differs from the derived one is also `INDEPENDENCE_INCONSISTENT`'", i,
        exp(independence="self-checked", problem_codes=["INDEPENDENCE_INCONSISTENT"], warning_codes=["SELF_CHECKED"]),
        old=exp(independence="self-checked", warning_codes=["SELF_CHECKED"]))
    i = copy.deepcopy(B)
    R(i)["independence"] = "self-checked"
    R(i)["parties"]["producer"] = {"key_id": None, "name": None}
    build.refresh(i)
    vec("stated-self-checked-no-producer", "independence self-checked; no producer named.", "1.3 step 8: "
        "'`PRODUCER_UNDECLARED` follows the parties block (no producer named), whatever the record states; a stated "
        "`independence` that differs from the derived one is also `INDEPENDENCE_INCONSISTENT`' (derived: undeclared, "
        "as for vector 20)", i,
        exp(independence="self-checked", problem_codes=["INDEPENDENCE_INCONSISTENT"],
            warning_codes=["SELF_CHECKED", "PRODUCER_UNDECLARED"]),
        old=exp(independence="self-checked", warning_codes=["SELF_CHECKED", "PRODUCER_UNDECLARED"]))


def write():
    os.makedirs(OUT, exist_ok=True)
    for f in os.listdir(OUT):
        if f.endswith(".json"):
            os.remove(os.path.join(OUT, f))
    for n, (name, desc, reading, inputs, expected, ext, raw, old) in enumerate(V, 1):
        vname = "omega-%02d-%s" % (n, name)
        doc = build.vector(vname, desc, inputs, expected)
        doc["reading"] = reading
        if ext:
            doc["expected_extensions"] = ext
        if old is not None:
            doc["expected_1_2_1"] = old
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
