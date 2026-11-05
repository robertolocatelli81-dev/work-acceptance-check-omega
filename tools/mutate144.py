"""Targeted mutants of the 0.8.0 changes (profile 1.4.4 at 1b81ec9, README "Profile 1.4.4 rules" T1-T7): each one must
make at least one test fail. The unmutated copy is run first through the same driver (control): it must pass.
usage: python3 -B tools/mutate144.py PYTHON [I/N]   (an interpreter with cryptography >= 40; I/N runs every Nth mutant
from the Ith, counted from 0, so that N processes share the list: the totals are then the sum of their lines)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
UNDECL = '''        return _norm_name(name, "trim-lower") in ("", "unspecified", "unknown")'''
ABS = "    return not name             # JSON values"
M = [
 # T1 comparison
 ("T1 default exact", '    "name_compare": "trim-lower",', '    "name_compare": "exact",'),
 ("T1 no trim", 'return s.strip(_WHITE_SPACE).lower()', 'return s.lower()'),
 ("T1 no lower-casing", 'return s.strip(_WHITE_SPACE).lower()', 'return s.strip(_WHITE_SPACE)'),
 ("T1 casefold", 'return s.strip(_WHITE_SPACE).lower()', 'return s.strip(_WHITE_SPACE).casefold()'),
 ("T1 str.strip set", 'return s.strip(_WHITE_SPACE).lower()', 'return s.strip().lower()'),
 ("T1 white space without U+3000", '\\u205f\\u3000")', '\\u205f")'),
 ("T1 white space without U+0085", '\\r \\x85\\xa0', '\\r \\xa0'),
 ("T1 white space without U+00A0", '\\r \\x85\\xa0', '\\r \\x85'),
 ("T1 note only under exact", 'if opts["name_compare"] != "normalized" and not same_name', 'if opts["name_compare"] == "exact" and not same_name'),
 # T2 undeclared
 ("T2 default no-key", '    "undeclared": "step8",', '    "undeclared": "no-key",'),
 ("T2 unspecified not listed", UNDECL, UNDECL.replace('"unspecified", ', '')),
 ("T2 unknown not listed", UNDECL, UNDECL.replace(', "unknown"', '')),
 ("T2 empty not listed", UNDECL, UNDECL.replace('"", ', '')),
 ("T2 exact match of the words", UNDECL, UNDECL.replace('_norm_name(name, "trim-lower")', 'name')),
 ("T2 only null absent", ABS, ABS.replace('not name', 'name is None')),
 ("T2 every value absent", ABS, ABS.replace('not name', 'True')),
 ("T2 true absent", ABS, ABS.replace('not name', 'not name or name is True')),
 ("T2 false declared", ABS, ABS.replace('not name', 'not name and name is not False')),
 ("T2 zero declared", ABS, ABS.replace('not name', 'name is False or (not name and name != 0)')),
 ("T2 empty array declared", ABS, ABS.replace('not name', 'not name and name != []')),
 ("T2 empty object declared", ABS, ABS.replace('not name', 'not name and name != {}')),
 ("T2 no-key branch used", '    if opts["undeclared"] == "step8":', '    if False:'),
 ("T2 no-key branch crashes on a non-string", '(isinstance(pname, str) and pname.strip() == "")', 'pname.strip() == ""'),
 # T3 presence
 ("T3 default required", '    "producer_presence": "optional",', '    "producer_presence": "required",'),
 ("T3 checker optional too", 'ctx.members(p, "receipt.parties", {"checker"} if bare_producer else {"checker", "producer"},', 'ctx.members(p, "receipt.parties", set() if bare_producer else {"checker", "producer"},'),
 ("T3 bare producer takes any member", 'ctx.members(p[role], "receipt.parties.producer", (), {"key_id", "name"})', 'pass'),
 ("T3 bare producer needs a name", 'ctx.members(p[role], "receipt.parties.producer", (), {"key_id", "name"})', 'ctx.members(p[role], "receipt.parties.producer", {"name"}, {"key_id"})'),
 ("T3 checker bare too", '        if role == "producer" and bare_producer:', '        if bare_producer:'),
 ("T3 parties refuses a producer", '{"producer"} if bare_producer else ())', '())'),
 ("T3 absent role read", '        if role not in p:\n            continue\n', ''),
 ("T3 used ids crash on no producer", 'r["parties"].get("producer", {}).get("key_id")', 'r["parties"]["producer"].get("key_id")'),
 ("T3 derivation crashes on no producer", 'producer = parties.get("producer", {})', 'producer = parties["producer"]'),
 # T4 non-string names
 ("T4 default refuse", '    "name_type": "step8",', '    "name_type": "refuse",'),
 ("T4 no note", 'elif name is not None and not isinstance(name, str):', 'elif False:'),
 ("T4 note for null too", 'elif name is not None and not isinstance(name, str):', 'elif not isinstance(name, str):'),
 ("T4 note check reads non-strings", 'not same_name and isinstance(cn, str) and isinstance(pn, str) and', 'not same_name and cn is not None and pn is not None and'),
 ("T4 note not an extension code", '"X_NAME_NOT_STRING: receipt', '"name not a string: receipt'),
 ("T4 refuse lets non-strings through", '        if ctx.opts["name_type"] == "refuse":', '        if False:'),
 # T5 claim
 ("T5 default always", '    "key_claim": "claim",', '    "key_claim": "always",'),
 ("T5 claim ignored", 'by_claim = opts["key_claim"] == "always" or r["independence"] == "independent"', 'by_claim = True'),
 ("T5 never by claim", 'by_claim = opts["key_claim"] == "always" or r["independence"] == "independent"', 'by_claim = False'),
 ("T5 switch ignored", 'by_claim = opts["key_claim"] == "always" or r["independence"] == "independent"', 'by_claim = r["independence"] == "independent"'),
 ("T5 repeated counted only under the claim", 'if role in unresolved and kid in keytable]', 'if role in unresolved and kid in keytable and keytable[kid].get("noncanonical")]'),
 ("T5 unreadable empty", 'if role in unresolved and kid in keytable]', 'if False]'),
 # T7 comparison of values that are not strings
 ("T7 non-strings never equal", 'return _norm_name(v, mode) if v is None or isinstance(v, str) else jcs(v)', 'return _norm_name(v, mode) if v is None or isinstance(v, str) else id(v)'),
 ("T7 value equals its text", 'return _norm_name(v, mode) if v is None or isinstance(v, str) else jcs(v)', 'return _norm_name(v, mode) if v is None or isinstance(v, str) else jcs(v).decode()'),
 # profiles and CLI
 ("P profile 1.4.3 without name_compare", 'PROFILE_1_4_3 = {"name_compare": "exact", "undeclared"', 'PROFILE_1_4_3 = {"undeclared"'),
 ("P profile 1.4.3 without key_claim", '"name_type": "refuse", "key_claim": "always"}', '"name_type": "refuse"}'),
 ("P profile 1.4.2 without 1.4.3", 'PROFILE_1_4_2 = dict(PROFILE_1_4_3, **{', 'PROFILE_1_4_2 = dict({}, **{'),
 ("P CLI --profile 1.4.3 unknown", 'PROFILES = {"1.4.3": PROFILE_1_4_3, "1.4.2"', 'PROFILES = {"1.4.2"'),
 ("P CLI --undeclared unknown", '"--undeclared": "undeclared",', ''),
 ("P CLI --key-claim unknown", ', "--key-claim": "key_claim"', ''),
 ("P CLI --name-type unknown", '"--name-type": "name_type", ', ''),
 ("P CLI --producer-presence unknown", '"--producer-presence": "producer_presence", ', ''),
]
TESTS = ["tests/test_profile144.py", "tests/test_vectors.py", "tests/test_cli.py"]


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
