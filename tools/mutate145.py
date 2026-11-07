"""Targeted mutants of the 0.9.0 changes (profile 1.4.5 at c4b4bd4, README "Profile 1.4.5 rules" U1-U9, Q24-Q29): each one
must make at least one test fail. The unmutated copy is run first through the same driver (control): it must pass.
usage: python3 -B tools/mutate145.py PYTHON [I/N]   (an interpreter with cryptography >= 40; I/N runs every Nth mutant
from the Ith, counted from 0, so that N processes share the list: the totals are then the sum of their lines)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
APPLIES = 'if r["independence"] != "independent" or pk is None or opts["independence_rule"] != "derived":'
HELD = 'elif pk_pub is None or pk_pub not in rp["held"]:'
MEMBERS = '(INPUT_MEMBERS | ({RP_INPUT} if opts["rp_input"] == "step12" else set())) - {"keys", "receipt"})'
ROOT = 'ctx.members(kf, RP_INPUT, {"keys"}, KEYFILE_MEMBERS - {"keys"})'
RPP = '        p = "%s.keys[%d]" % (RP_INPUT, i)\n        '
ENTRY0 = RPP + 'ctx.members(k, p, {"alg", "key_id", "public_key_base64", "status"}, {"since"})\n        _str(k["alg"], p + ".alg")'
M = [
 # U1 the input
 ("U1 default unknown", '    "rp_input": "step12",', '    "rp_input": "unknown",'),
 ("U1 member accepted under every profile", MEMBERS, '(INPUT_MEMBERS | {RP_INPUT}) - {"keys", "receipt"})'),
 ("U1 member never accepted", MEMBERS, 'INPUT_MEMBERS - {"keys", "receipt"})'),
 ("U1 list never read", '    if opts["rp_input"] == "step12":\n        if rp_override', '    if False:\n        if rp_override'),
 # U2 form
 ("U2 issuer required", ROOT, 'ctx.members(kf, RP_INPUT, {"issuer", "keys"}, KEYFILE_MEMBERS - {"issuer", "keys"})'),
 ("U2 root open", ROOT, 'ctx.members(kf, RP_INPUT, {"keys"}, set(kf) if isinstance(kf, dict) else ())'),
 ("U2 key-file members closed", ROOT, 'ctx.members(kf, RP_INPUT, {"keys"}, ())'),
 ("U2 entry open", ENTRY0, RPP + 'ctx.members(k, p, {"alg", "key_id", "public_key_base64", "status"}, set(k) if isinstance(k, dict) else ())\n        _str(k["alg"], p + ".alg")'),
 ("U2 entry since closed", ENTRY0, RPP + 'ctx.members(k, p, {"alg", "key_id", "public_key_base64", "status"}, ())\n        _str(k["alg"], p + ".alg")'),
 ("U2 entry needs only the key", ENTRY0, RPP + 'ctx.members(k, p, {"public_key_base64"}, {"alg", "key_id", "status", "since"})\n        _str(k.get("alg", "Ed25519"), p + ".alg")'),
 ("U2 alg not checked", '        if k["alg"] != "Ed25519":\n            raise Refusal("%s.alg is not Ed25519" % p)\n        kid = _str(k["key_id"], p + ".key_id", nonempty=True)\n        _str(k["status"], p + ".status")\n        if k["status"] not in KEY_STATUSES:\n            raise Refusal("%s.status %r is not one of %s" % (p, k["status"], KEY_STATUSES))\n        if "since" in k:\n            _str(k["since"], p + ".since")\n        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed', '        kid = _str(k["key_id"], p + ".key_id", nonempty=True)\n        _str(k["status"], p + ".status")\n        if k["status"] not in KEY_STATUSES:\n            raise Refusal("%s.status %r is not one of %s" % (p, k["status"], KEY_STATUSES))\n        if "since" in k:\n            _str(k["since"], p + ".since")\n        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed'),
 ("U2 empty key_id read", 'kid = _str(k["key_id"], p + ".key_id", nonempty=True)\n        _str(k["status"], p + ".status")\n        if k["status"] not in KEY_STATUSES:\n            raise Refusal("%s.status %r is not one of %s" % (p, k["status"], KEY_STATUSES))\n        if "since" in k:\n            _str(k["since"], p + ".since")\n        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed', 'kid = _str(k["key_id"], p + ".key_id")\n        _str(k["status"], p + ".status")\n        if k["status"] not in KEY_STATUSES:\n            raise Refusal("%s.status %r is not one of %s" % (p, k["status"], KEY_STATUSES))\n        if "since" in k:\n            _str(k["since"], p + ".since")\n        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed'),
 ("U2 status not checked", '        if k["status"] not in KEY_STATUSES:\n            raise Refusal("%s.status %r is not one of %s" % (p, k["status"], KEY_STATUSES))\n        if "since" in k:\n            _str(k["since"], p + ".since")\n        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed', '        if "since" in k:\n            _str(k["since"], p + ".since")\n        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed'),
 ("U2 since not typed", '        if "since" in k:\n            _str(k["since"], p + ".since")\n        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed', '        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed'),
 ("U2 key not typed", '        _str(k["public_key_base64"], p + ".public_key_base64")\n        listed', '        listed'),
 ("U2 root members not typed", 'for m in ("issuer", "version", "purpose"):\n            if m in kf:\n                _str(kf[m], "%s.%s" % (RP_INPUT, m))', 'pass'),
 ("U2 also_published not typed", 'raise TypeRefusal("%s.also_published is not a list of strings" % RP_INPUT)', 'pass'),
 ("U2 keys not a list read", 'raise TypeRefusal("%s.keys is not a list" % RP_INPUT)', 'kf = {"keys": []}'),
 ("U2 null is absent", '        elif RP_INPUT in inputs:\n            rp = check_rp_keys(ctx, inputs[RP_INPUT])', '        elif inputs.get(RP_INPUT) is not None:\n            rp = check_rp_keys(ctx, inputs[RP_INPUT])'),
 # U3 when
 ("U3 self-checked too", APPLIES, 'if pk is None or opts["independence_rule"] != "derived":'),
 ("U3 producer key_id not needed", APPLIES, 'if r["independence"] != "independent" or opts["independence_rule"] != "derived":'),
 ("U3 under the 1.2.1 reading too", APPLIES, 'if r["independence"] != "independent" or pk is None:'),
 ("U3 never", APPLIES, 'if True:'),
 ("U3 no note", 'ctx.notes.append("X_RP_KEYS_NOT_APPLIED: step 12 needs', 'str("X_RP_KEYS_NOT_APPLIED: step 12 needs'),
 ("U3 note without the switch", '% ("" if opts["independence_rule"] == "derived" else ", under --independence-rule derived"))', '% "")'),
 # U4 same decoded key
 ("U4 by key_id", HELD, 'elif pk not in rp["ids"]:'),
 ("U4 by key_id too", HELD, 'elif (pk_pub is None or pk_pub not in rp["held"]) and pk not in rp["ids"]:'),
 ("U4 ed_same_key", HELD, 'elif pk_pub is None or not any(ed_same_key(pk_pub, q) for q in rp["held"]):'),
 ("U4 any key held", HELD, 'elif not rp["held"]:'),
 ("U4 a key is enough", HELD, 'elif pk_pub is None:'),
 # U5 outcome
 ("U5 no effect", '(profile 1.4.5 step 12, vector 110)" % (pk,))\n            by_key = by_key or ["producer"]', '(profile 1.4.5 step 12, vector 110)" % (pk,))\n            pass'),
 ("U5 no note", 'ctx.notes.append("X_RP_PRODUCER_KEY_NOT_HELD: relying_party_keys', 'str("X_RP_PRODUCER_KEY_NOT_HELD: relying_party_keys'),
 # U7 CLI
 ("U7 replaced list open", '                check_rp_keys(Ctx(opts), inputs[RP_INPUT])\n', ''),
 ("U7 no note on replacing", 'ctx.notes.append("inputs.%s not used: the list was supplied with --relying-party-keys" % RP_INPUT)', 'pass'),
 ("U7 the document wins", '            rp = check_rp_keys(ctx, rp_override)\n', '            rp = check_rp_keys(ctx, inputs.get(RP_INPUT, rp_override))\n'),
 ("U7 null file is no file", 'NOT_GIVEN = object()', 'NOT_GIVEN = None'),
 ("U7 option under a profile", 'if rpfile is not None and opts.get("rp_input") == "unknown":', 'if False:'),
 ("U7 repeated option", 'if rpfile is not None or args[0] == "":', 'if args[0] == "":'),
 ("U7 empty option", 'if rpfile is not None or args[0] == "":', 'if rpfile is not None:'),
 ("U7 --keys null kept", 'if override is None and opts.get("rp_input") != "unknown":', 'if False:'),
 ("U7 --keys null refused under 1.4.4", 'if override is None and opts.get("rp_input") != "unknown":', 'if override is None:'),
 ("U7 API override under 1.4.4", '    if rp_override is not NOT_GIVEN and opts["rp_input"] != "step12":\n        raise ValueError("a relying-party key list needs rp_input=step12")\n', ''),
 ("U7 CLI list unused in vector mode", 'rep, cmp_ = run_vector_bytes(raw, opts, override, rp_override=rp_override)', 'rep, cmp_ = run_vector_bytes(raw, opts, override)'),
 ("U7 CLI list unused in record mode", 'rep, cmp_ = run_vector(strict_json_loads(raw), opts, override, rp_override)', 'rep, cmp_ = run_vector(strict_json_loads(raw), opts, override)'),
 # U8 where it came from
 ("U8 no block", '"X_UNUSED_KEY_REJECTED", "X_RP_KEYS_FROM_INPUT"}', '"X_UNUSED_KEY_REJECTED"}'),
 ("U8 always marked", '        if rp_override is NOT_GIVEN:\n            ext.add("X_RP_KEYS_FROM_INPUT")', '        ext.add("X_RP_KEYS_FROM_INPUT")'),
 ("U8 never marked", '        if rp_override is NOT_GIVEN:\n            ext.add("X_RP_KEYS_FROM_INPUT")', '        pass'),
 ("U8 source always the input", '"--relying-party-keys (supplied by the relying party)" if rp_override is not NOT_GIVEN\n', '"--relying-party-keys (supplied by the relying party)" if False\n'),
 # U9 entries
 ("U9 non-canonical decoded", '        pub = b64_canonical(k["public_key_base64"])\n        repeated', '        pub = base64.b64decode(k["public_key_base64"])\n        repeated'),
 ("U9 non-canonical refused", '            why = "public_key_base64 is not canonical base64: holds no key (README U9)"', '            raise Refusal("%s not canonical" % p)'),
 ("U9 repeated not seen", 'repeated = listed[k["key_id"]] > 1', 'repeated = False'),
 ("U9 first of the repeated counts", 'repeated = listed[k["key_id"]] > 1', 'repeated = k is not entries[0] and listed[k["key_id"]] > 1'),
 ("U9 no block", 'ctx.notes.append("X_UNUSED_KEY_REJECTED: %s: %s" % (p, why))', 'ctx.notes.append("%s: %s" % (p, why))'),
 ("U9 class not read", 'cls = ed_point_class(pub)\n            if cls != "prime-order":\n                why = "the key is', 'cls = "prime-order"\n            if cls != "prime-order":\n                why = "the key is'),
 ("U9 bad class holds no key", '        if pub is not None and (not repeated or opts["rp_repeated"] == "bytes"):', '        if pub is not None and not (why and not repeated) and (not repeated or opts["rp_repeated"] == "bytes"):'),
 ("U9 defects not counted", '            defects += 1\n', ''),
 # Q24-Q28
 ("Q24 default bare-list", '    "rp_form": "object",', '    "rp_form": "bare-list",'),
 ("Q24 list read in every case", 'if isinstance(kf, list) and opts["rp_form"] == "bare-list":', 'if isinstance(kf, list):'),
 ("Q24 bare-list drops the object", 'if isinstance(kf, list) and opts["rp_form"] == "bare-list":', 'if opts["rp_form"] == "bare-list":'),
 ("Q25 default absent", '    "rp_empty": "holds-nothing",', '    "rp_empty": "absent",'),
 ("Q25 default refuse", '    "rp_empty": "holds-nothing",', '    "rp_empty": "refuse",'),
 ("Q25 refuse does nothing", '        if opts["rp_empty"] == "refuse":\n            raise Refusal("%s.keys is an empty list" % RP_INPUT)\n', ''),
 ("Q25 no note", 'ctx.notes.append("X_RP_KEYS_EMPTY: %s holds no entry', 'str("X_RP_KEYS_EMPTY: %s holds no entry'),
 ("Q25 note always says supplied", '"read as absent" if opts["rp_empty"] == "absent" else "supplied, and it holds no key"', '"supplied, and it holds no key"'),
 ("Q25 absent does nothing", '        if opts["rp_empty"] == "absent":\n            return None\n', ''),
 ("Q26 default no-key", '    "rp_repeated": "bytes",', '    "rp_repeated": "no-key",'),
 ("Q26 bytes does nothing", '(not repeated or opts["rp_repeated"] == "bytes")', 'not repeated'),
 ("Q26 note says no key", 'is listed more than once: matched by key, compared by "\n', 'is listed more than once: holds no key, not "\n'),
 ("Q26 ids hold the repeated", '            if not repeated:\n                ids[k["key_id"]] = pub', '            ids[k["key_id"]] = pub'),
 ("Q27 default key-rejected", '    "rp_entry_defect": "note",', '    "rp_entry_defect": "key-rejected",'),
 ("Q27 switch does nothing", '        if rp["defects"] and opts["rp_entry_defect"] == "key-rejected":      # Q27\n            problems.add("KEY_REJECTED")\n', ''),
 ("Q27 every list", 'if rp["defects"] and opts["rp_entry_defect"] == "key-rejected":', 'if opts["rp_entry_defect"] == "key-rejected":'),
 ("Q28 default both", '    "rp_lookup": "keys",', '    "rp_lookup": "both",'),
 ("Q28 switch does nothing", 'rp_found = rp is not None and opts["rp_lookup"] == "both" and pk not in keytable and pk in rp["ids"]', 'rp_found = False'),
 ("Q28 listed entry replaced", 'opts["rp_lookup"] == "both" and pk not in keytable and pk in rp["ids"]', 'opts["rp_lookup"] == "both" and pk in rp["ids"]'),
 ("Q28 still unresolved", '    if rp_found:\n        unresolved.remove("producer")\n', ''),
 ("Q28 key not used", '    if rp_found:\n        pk_pub = rp["ids"][pk]\n', ''),
 # profiles and CLI
 ("P profile 1.4.3 without 1.4.4", 'PROFILE_1_4_3 = dict(PROFILE_1_4_4, **{', 'PROFILE_1_4_3 = dict({}, **{'),
 ("P profile 1.4.4 empty", 'PROFILE_1_4_4 = dict(PROFILE_1_4_5, **{"rp_input": "unknown"})', 'PROFILE_1_4_4 = dict(PROFILE_1_4_5)'),
 ("P CLI --profile 1.4.4 unknown", '"1.4.4": PROFILE_1_4_4, ', ''),
 ("P CLI --rp-input unknown", '"--rp-input": "rp_input", ', ''),
 ("P CLI --rp-form unknown", '"--rp-form": "rp_form", ', ''),
 ("P CLI --rp-empty unknown", '"--rp-empty": "rp_empty",', ''),
 ("P CLI --rp-repeated unknown", '"--rp-repeated": "rp_repeated", ', ''),
 ("P CLI --rp-entry-defect unknown", '"--rp-entry-defect": "rp_entry_defect", ', ''),
 ("P CLI --rp-lookup unknown", ', "--rp-lookup": "rp_lookup"', ''),
 ("P version", 'VERSION = "war_verify 0.11.0"', 'VERSION = "war_verify 0.9.0"'),
]
TESTS = ["tests/test_profile145.py", "tests/test_vectors.py", "tests/test_cli.py", "tests/test_profile147.py"]


def run(text):
    d = tempfile.mkdtemp()
    try:
        for x in ("tests", "tools", "vectors"):
            shutil.copytree(os.path.join(REPO, x), os.path.join(d, x))
        for x in ("fonti", "roots"):
            os.symlink(os.path.join(REPO, x), os.path.join(d, x))
        open(os.path.join(d, "war_verify.py"), "w").write(text)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        dead = []
        for t in TESTS:                                 # stops at the first test file that fails
            if subprocess.run([PY, "-B", t, "-f"], cwd=d, env=env, capture_output=True).returncode != 0:
                dead.append(t)
                break
        return dead
    finally:
        shutil.rmtree(d)


if len(sys.argv) > 2:
    part, parts = map(int, sys.argv[2].split("/"))
    M = M[part::parts]
ctl = run(src)
print("CONTROL (unmutated copy)", "FAILS %s" % ctl if ctl else "passes", flush=True)
if ctl:
    sys.exit(1)
killed = not_applicable = 0
for name, o, n in M:
    if src.count(o) != 1:
        print("NOT APPLICABLE", name, src.count(o), flush=True); not_applicable += 1; continue
    dead = run(src.replace(o, n))
    print("KILLED " if dead else "ALIVE  ", name, [os.path.basename(t) for t in dead], flush=True)
    killed += bool(dead)
print("killed %d/%d" % (killed, len(M)))
sys.exit(0 if killed == len(M) and not not_applicable else 1)   # a mutant not applied is a bench defect, not a kill
