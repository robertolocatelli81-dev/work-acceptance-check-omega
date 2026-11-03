"""Targeted mutants of the 0.7.0 changes (profile 1.4.3 at 6bb7d0b, README "Profile 1.4.3 rules" S1-S8): each one must
make at least one test fail. The unmutated copy is run first through the same driver (control): it must pass.
usage: python3 -B tools/mutate143.py PYTHON   (an interpreter with cryptography >= 40)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
M = [
 # S1 key scope (91)
 ("S1 default all-entries", '    "key_scope": "used",', '    "key_scope": "all-entries",'),
 ("S1 producer not a used entry", 'used_ids = {k for k in (used_kid, ck0, pk0) if k is not None}', 'used_ids = {k for k in (used_kid, ck0) if k is not None}'),
 ("S1 checker not a used entry", 'used_ids = {k for k in (used_kid, ck0, pk0) if k is not None}', 'used_ids = {k for k in (used_kid, pk0) if k is not None}'),
 ("S1 signer not a used entry", 'used_ids = {k for k in (used_kid, ck0, pk0) if k is not None}', 'used_ids = {k for k in (ck0, pk0) if k is not None}'),
 ("S1 unread entry silent", '    if unread_noncanon and opts["key_scope"] == "used":', '    if False:'),
 ("S1 unread entry KEY_REJECTED again", 'v.get("noncanonical") and (opts["key_scope"] == "all-entries" or k in used_ids)', 'v.get("noncanonical")'),
 # S2 empty key ids (104, 106)
 ("S2 default refuse", '    "empty_key_id": "signature-invalid",', '    "empty_key_id": "refuse",'),
 ("S2 signed key_id refused", 'nonempty=ctx.opts["empty_key_id"] == "refuse")', 'nonempty=True)'),
 ("S2 envelope key_id refused", 'nonempty=opts["empty_key_id"] == "refuse")      # README S2', 'nonempty=True)      # README S2'),
 ("S2 empty identifiers collide", '(a != "" or opts["empty_key_id"] == "refuse")', 'True'),
 ("S2 empty identifiers never compared", 'same_id = (lambda a, b: a == b and (a != "" or opts["empty_key_id"] == "refuse"))', 'same_id = (lambda a, b: a == b and a != "")'),
 ("S2 no note", '        if kv == "":', '        if False:'),
 # S3 malformed digests (94)
 ("S3 default refuse", '    "digest_form": "mismatch",', '    "digest_form": "refuse",'),
 ("S3 always refused", '        if ctx.opts["digest_form"] == "refuse":\n            raise', '        if True:\n            raise'),
 ("S3 note not an extension code", '"X_DIGEST_MALFORMED: %s', '"digest malformed: %s'),
 # S4 stated fraction (95, 96)
 ("S4 default three", '    "stated_fraction": "1-3",', '    "stated_fraction": "three",'),
 ("S4 one to nine digits", '(?:\\.([0-9]{1,3}))?Z\\Z")}', '(?:\\.([0-9]{1,9}))?Z\\Z")}'),
 ("S4 empty fraction readable", '(?:\\.([0-9]{1,3}))?Z\\Z")}', '(?:\\.([0-9]{0,3}))?Z\\Z")}'),
 ("S4 non-ASCII digits", '(?:\\.([0-9]{1,3}))?Z\\Z")}', '(?:\\.(\\d{1,3}))?Z\\Z")}'),
 ("S4 parser ignores the switch", '    m = _STATED[fraction].match(v)', '    m = _STATED["1-3"].match(v)'),
 # S5 CRITERIA_TIME_MISMATCH to the second (99)
 ("S5 default truncate", '    "time_agreement": "second",', '    "time_agreement": "truncate",'),
 ("S5 fraction in committed_at allowed", '        return claim["digits"] == 0 and claim["instant"] == gen["instant"] // 1', '        return claim["instant"] == gen["instant"] // 1'),
 ("S5 genTime fraction kept", '        return claim["digits"] == 0 and claim["instant"] == gen["instant"] // 1', '        return claim["digits"] == 0 and claim["instant"] == gen["instant"]'),
 # S7 authority check without usable genTime (105, 107)
 ("S7 no early genTime check", '    if gen_unusable:\n        bad("failed", "genTime is not a usable time (profile 1.4.3)', '    if False:\n        bad("failed", "genTime is not a usable time (profile 1.4.3)'),
 ("S7 classed no_signer", 'bad("failed", "genTime is not a usable time (profile 1.4.3)', 'bad("no_signer", "genTime is not a usable time (profile 1.4.3)'),
 ("S7 later check continues", '    if gen_unusable:                             # already failed above', '    if False:                             # already failed above'),
 # profiles and CLI
 ("P --profile 1.4.2 without time agreement", '"stated_fraction": "three", "time_agreement": "truncate"}', '"stated_fraction": "three"}'),
 ("P --profile 1.2.1 without the 1.4.2 readings", 'PROFILE_1_2_1 = dict(PROFILE_1_4_2, **{', 'PROFILE_1_2_1 = dict({}, **{'),
 ("P CLI --profile 1.4.2 refused", 'if profile is not None or args[0] not in PROFILES:', 'if profile is not None or args[0] != "1.2.1":'),
 ("P CLI --key-scope unknown", '               "--key-scope": "key_scope", ', '               '),
 ("P CLI profile not applied", '    if profile is not None:\n        opts = dict(PROFILES[profile], **opts)', '    if profile == "1.2.1":\n        opts = dict(PROFILES[profile], **opts)'),
 ("P CLI profile overrides a switch", '        opts = dict(PROFILES[profile], **opts)', '        opts = dict(opts, **PROFILES[profile])'),
]
TESTS = ["tests/test_profile143.py", "tests/test_profile142.py", "tests/test_vectors.py", "tests/test_readings_20261024.py",
         "tests/test_cli.py"]


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
