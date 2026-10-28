"""Targeted mutants of the 0.6.0 changes (profile 1.4.2 at 85a310d, README "Profile 1.4.2 rules" R1-R10): each one must
make at least one test fail. The unmutated copy is run first through the same driver (control): it must pass.
usage: python3 -B tools/mutate142.py PYTHON   (an interpreter with cryptography >= 40)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
M = [
 # R1 canonical base64
 ("R1 b64 re-encoding not compared", '    return raw if base64.b64encode(raw).decode("ascii") == s else None', '    return raw'),
 # removed as equivalent, "R1 b64 length not checked" (drop `or len(s) % 4` in b64_canonical): b64decode(validate=True)
 # and the re-encoding comparison already refuse every other length. Differential 2026-10-27: 2,675,076 strings (all
 # of length 0-3 over the 65 characters, all of length 4-7 over "AQgw/+=Z"), 0 differences; control (re-encoding
 # comparison removed) 168 differences over the lengths 0-7 of the small alphabet.
 ("R1 lax signature decode", '    sig_bytes = b64_canonical(_str(sig["value"], "signature.value"))', '    sig_bytes = base64.b64decode(_str(sig["value"], "signature.value") + "==")'),
 ("R1 non-canonical key not KEY_REJECTED", 'if any(v.get("dup") or v.get("noncanonical") for v in keytable.values()):', 'if any(v.get("dup") for v in keytable.values()):'),
 ("R1 non-canonical key compared", '                table[kid] = {"pub": None, "status": k["status"], "rejected": "public_key_base64 not canonical base64",', '                table[kid] = {"pub": base64.b64decode(k["public_key_base64"] + "=="), "status": k["status"], "rejected": "public_key_base64 not canonical base64",'),
 ("R1 criteria token noncanonical ignored", '    if "criteria_tsr_base64" in noncanon:', '    if False:'),
 ("R1 record token noncanonical none", '        rec_ts = "imprint_mismatch"', '        rec_ts = "none"'),
 ("R1 criteria file noncanonical not-supplied", '    if crit_file is not None or "criteria_file_base64" in noncanon:', '    if crit_file is not None:'),
 ("R1 delivered noncanonical not-supplied", '        if data is None and key not in noncanon:', '        if data is None:'),
 # R3 repeated key id
 ("R3 duplicate not rejected", '            table[kid].update({"pub": None, "rejected": "key_id listed more than once", "dup": True})', '            pass'),
 ("R3 duplicate keeps first key", '            table[kid].update({"pub": None, "rejected": "key_id listed more than once", "dup": True})', '            table[kid].update({"rejected": "key_id listed more than once", "dup": True})'),
 ("R3 unrelated duplicate not KEY_REJECTED", 'if any(v.get("dup") or v.get("noncanonical") for v in keytable.values()):', 'if any(v.get("noncanonical") for v in keytable.values()):'),
 # R2 digests
 ("R2 upper case lower-cased for the token", 'bytes.fromhex(crit_sha) if _HEX64.match(crit_sha) else None', 'bytes.fromhex(crit_sha)'),
 ("R2 upper case refused", '    if not _HEX64_ANYCASE.match(v):', '    if not _HEX64.match(v):'),
 ("R2 any string accepted", '    if not _HEX64_ANYCASE.match(v):\n        raise', '    if False:\n        raise'),
 # R4 genTime
 ("R4 unusable genTime refused", '    except Refusal as e:\n        # Profile 1.4.2 R4', '    except ZeroDivisionError as e:\n        # Profile 1.4.2 R4'),
 ("R4 unusable criteria time used", '        elif crit_tok is not None and cgen is not None:', '        elif crit_tok is not None:'),
 ("R4 unusable record time is a reference", 'if st == "match" and rec_tok is not None and rgen is not None:', 'if st == "match" and rec_tok is not None:'),
 ("R4 no rounding up", '    return -((-x) // q) * q', '    return x'),
 ("R4 criteria time rounded down", '    return -((-x) // q) * q', '    return (x // q) * q'),
 ("R4 no rounding down", '    return (x // q) * q\n\n\n_GENTIME', '    return x\n\n\n_GENTIME'),
 ("R4 not strict", '        before = "yes" if commit_hi < ref_lo else "no"', '        before = "yes" if commit_hi <= ref_lo else "no"'),
 ("R4 covering token not rounded", '            lo_tok = floor_ms(covering["gen"]["instant"]) - acc_r', '            lo_tok = covering["gen"]["instant"] - acc_r'),
 # R5 stated times
 ("R5 one to nine digits", '(?:\\.([0-9]{3}))?Z\\Z")\n\n\ndef parse_stated_time', '(?:\\.([0-9]{1,9}))?Z\\Z")\n\n\ndef parse_stated_time'),
 ("R5 calendar not checked", '    if _valid_date(y, mo, d, h, mi, s):\n        return None', '    if False:\n        return None'),
 ("R5 no RECEIPT_TIME_UNREADABLE", '        problems.add("RECEIPT_TIME_UNREADABLE")', '        pass'),
 ("R5 unreadable committed_at ignored with any token supplied", '                  if v is None and (n == "issued_utc" or commit_tst is None)]', '                  if v is None and (n == "issued_utc" or crit_tsr is None)]'),
 ("R5/88 unreadable committed_at not CRITERIA_TIME_MISMATCH with a usable token", '        if committed_at is None or not _times_agree(committed_at, commit_tst["gen"], opts["time_agreement"]):', '        if committed_at is not None and not _times_agree(committed_at, commit_tst["gen"], opts["time_agreement"]):'),
 # R6 independence by key
 ("R6 unlisted key_id not unresolved", '                  if kid is not None and (kid not in keytable or keytable[kid].get("dup") or', '                  if kid is not None and (keytable.get(kid, {}).get("dup") or'),
 ("R6 unresolved ignored", '    by_key = unresolved if opts["independence_rule"] == "derived" else []', '    by_key = []'),
 ("R6 key_id required again", '        ctx.members(p[role], "receipt.parties." + role, {"name"}, {"key_id"})', '        ctx.members(p[role], "receipt.parties." + role, {"name", "key_id"})'),
 # R7 checker is the signer
 ("R7 envelope key_id", '        if ck != r["key_id"]:', '        if ck != sig["key_id"]:'),
 ("R7 by public key", '    if opts["key_id_source"] == "receipt":\n        # Profile 1.4.2 R7', '    if False:\n        # Profile 1.4.2 R7'),
 # R8 types
 ("R8 type refusal keeps its own reason", '    return Refusal(STEP1_REASON, msg + " (profile 1.4.2: wrong type, refused as an unsupported schema)")', '    return Refusal(msg)'),
 ("R8 non-object step-1 receipt", '        raise TypeRefusal("receipt is not a JSON object")', '        raise Refusal("receipt is not a JSON object")'),
 # R10 tools members and vector metadata
 ("R10 keys_utf16_order unknown", '                  "keys_utf16_order"}', '                  }'),
 ("R10 keys_utf16_order values open", 'not all(isinstance(x, str) for x in ko.values())', 'False'),
 ("R10 test_key_seeds unknown", '               "test_key_seeds",   #', '               #'),
 ("cb7e8f1 proposed_by unknown", '               "proposed_by"}', '               }'),
 # Q3, the profile author's answer on tsc#4: a non-canonical token with anchors is failed
 ("tsc#4 non-canonical token with anchors not failed", '            tsa_sig[key] = "not_evaluated" if anchors is None else "failed"', '            tsa_sig[key] = "not_evaluated"'),
 ("tsc#4 non-canonical token member absent", '        if name in noncanon:\n            # A token that is not canonical base64', '        if False:\n            # A token that is not canonical base64'),
]
TESTS = ["tests/test_profile142.py", "tests/test_vectors.py", "tests/test_readings_20261024.py", "tests/test_fuzz.py",
         "tests/test_profile13.py", "tests/test_nemesis_wrapper.py"]


def run(text):
    d = tempfile.mkdtemp()
    try:
        for x in ("tests", "tools", "vectors"):
            shutil.copytree(os.path.join(REPO, x), os.path.join(d, x))
        for x in ("fonti", "roots"):
            os.symlink(os.path.join(REPO, x), os.path.join(d, x))
        open(os.path.join(d, "war_verify.py"), "w").write(text)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        return [t for t in TESTS if subprocess.run([PY, "-B", t], cwd=d, env=env, capture_output=True).returncode != 0]
    finally:
        shutil.rmtree(d)


ctl = run(src)
print("CONTROL (unmutated copy)", "FAILS %s" % ctl if ctl else "passes")
if ctl:
    sys.exit(1)
killed = not_applicable = 0
for name, o, n in M:
    if src.count(o) != 1:
        print("NOT APPLICABLE", name, src.count(o)); not_applicable += 1; continue
    dead = run(src.replace(o, n))
    print("KILLED " if dead else "ALIVE  ", name, [os.path.basename(t) for t in dead], flush=True)
    killed += bool(dead)
print("killed %d/%d" % (killed, len(M)))
sys.exit(0 if killed == len(M) and not not_applicable else 1)   # a mutant not applied is a bench defect, not a kill
