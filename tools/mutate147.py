"""Targeted mutants of the 0.10.0 changes (profile 1.4.7 at 6f7a075, README "Profile 1.4.7 rules" V1-V5, Q31 and the command
line): each one must make at least one test fail. The unmutated copy is run first through the same driver (control): it must
pass. usage: python3 -B tools/mutate147.py PYTHON [I/N]   (an interpreter with cryptography >= 40; I/N runs every Nth mutant
from the Ith, counted from 0, so that N processes share the list: the totals are then the sum of their lines)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
NOTE_IF = 'if repeated and opts["rp_repeated"] == "bytes":'
DEFECT = 'elif repeated and opts["rp_repeated"] == "no-key":'
COND = 'if pk_pub is not None and opts["independence_rule"] == "derived" and (opts["rp_point"] == "always" or (\n            opts["rp_point"] == "step12" and rp is not None and r["independence"] == "independent")):'
CLS = 'cls = ed_point_class(pk_pub)\n        if cls != "prime-order":\n            ctx.notes.append("X_RP_PRODUCER_KEY_POINT_RULE'
CLS_ = 'cls = ed_point_class(pk_pub)\n        if %s:\n            ctx.notes.append("X_RP_PRODUCER_KEY_POINT_RULE'
M = [
 # V1 a repeated key_id
 ("V1 no note", 'ctx.notes.append("X_RP_KEY_ID_REPEATED:', 'str("X_RP_KEY_ID_REPEATED:'),
 ("V1 note under no-key too", NOTE_IF, 'if repeated:'),
 ("V1 note on every entry", NOTE_IF, 'if opts["rp_repeated"] == "bytes":'),
 ("V1 repeated stays a defect", DEFECT, 'elif repeated:'),
 ("V1 no-key is no defect", DEFECT, 'elif False:'),
 ("V1 a repeated entry skips the class", 'reading Q26)" % (k["key_id"],)\n        else:\n', 'reading Q26)" % (k["key_id"],)\n        elif not repeated:\n'),
 ("V1 one value of the switch", '"rp_repeated": ("bytes", "no-key")', '"rp_repeated": ("bytes",)'),
 ("V1 usage default", '(default bytes)', '(default no-key)'),
 # V3 the point rule
 ("V3 default off", '    "rp_point": "step12",\n', '    "rp_point": "off",\n'),
 ("V3 default always", '    "rp_point": "step12",\n', '    "rp_point": "always",\n'),
 ("V3 small order only", CLS, CLS_ % 'cls == "small-order"'),
 ("V3 mixed order passes", CLS, CLS_ % 'cls not in ("prime-order", "mixed-order")'),
 ("V3 what does not decode passes", CLS, CLS_ % 'cls in ("small-order", "mixed-order")'),
 ("V3 the neutral point only", CLS, CLS_ % 'pk_pub == bytes([1] + [0] * 31)'),
 ("V3 only a key the list holds", CLS, CLS_ % 'cls != "prime-order" and (rp is None or pk_pub in rp["held"])'),
 ("V3 never fails", CLS, 'cls = "prime-order"\n        if cls != "prime-order":\n            ctx.notes.append("X_RP_PRODUCER_KEY_POINT_RULE'),
 ("V3 reads the signer's key", 'cls = ed_point_class(pk_pub)\n        if cls != "prime-order":\n            ctx.notes', 'cls = ed_point_class(signer_pub or pk_pub)\n        if cls != "prime-order":\n            ctx.notes'),
 ("V3 no effect", '"vectors 114, 115)" % (pk, cls))\n            by_key = by_key or ["producer"]', '"vectors 114, 115)" % (pk, cls))\n            pass'),
 ("V3 no note", 'ctx.notes.append("X_RP_PRODUCER_KEY_POINT_RULE:', 'str("X_RP_PRODUCER_KEY_POINT_RULE:'),
 ("V3 note without the class", '"vectors 114, 115)" % (pk, cls))', '"vectors 114, 115)" % (pk, "refused"))'),
 ("V3 note without the key_id", '"vectors 114, 115)" % (pk, cls))', '"vectors 114, 115)" % ("the producer", cls))'),
 ("V3 raises KEY_REJECTED", '"vectors 114, 115)" % (pk, cls))\n            by_key', '"vectors 114, 115)" % (pk, cls))\n            problems.add("KEY_REJECTED")\n            by_key'),
 ("V3 adds a warning", '"vectors 114, 115)" % (pk, cls))\n            by_key', '"vectors 114, 115)" % (pk, cls))\n            warnings.add("SELF_CHECKED")\n            by_key'),
 # V4 where it applies
 ("V4 no list too", 'opts["rp_point"] == "step12" and rp is not None and r["independence"] == "independent")):', 'opts["rp_point"] == "step12" and r["independence"] == "independent")):'),
 ("V4 either claim", 'opts["rp_point"] == "step12" and rp is not None and r["independence"] == "independent")):', 'opts["rp_point"] == "step12" and rp is not None)):'),
 ("V4 under the 1.2.1 reading too", 'if pk_pub is not None and opts["independence_rule"] == "derived" and (', 'if pk_pub is not None and ('),
 ("V4 step12 never", 'opts["rp_point"] == "step12" and rp is not None and', 'False and rp is not None and'),
 ("V4 no key to read", 'if pk_pub is not None and opts["independence_rule"] == "derived" and (', 'if opts["independence_rule"] == "derived" and ('),
 # Q31
 ("Q31 always does nothing", '(opts["rp_point"] == "always" or (', '(False or ('),
 ("Q31 always needs a list", '(opts["rp_point"] == "always" or (', '(opts["rp_point"] == "always" and rp is not None or ('),
 ("Q31 no value always", '"rp_point": ("step12", "off", "always")', '"rp_point": ("step12", "off")'),
 ("Q31 no value off", '"rp_point": ("step12", "off", "always")', '"rp_point": ("step12", "always")'),
 # V5 the older readings, the command line
 ("V5 profile 1.4.5 keeps the new repeated", 'PROFILE_1_4_5 = dict(PROFILE_1_4_7, **{"rp_repeated": "no-key", "rp_point": "off"})', 'PROFILE_1_4_5 = dict(PROFILE_1_4_7, **{"rp_point": "off"})'),
 ("V5 profile 1.4.5 keeps the point rule", 'PROFILE_1_4_5 = dict(PROFILE_1_4_7, **{"rp_repeated": "no-key", "rp_point": "off"})', 'PROFILE_1_4_5 = dict(PROFILE_1_4_7, **{"rp_repeated": "no-key"})'),
 ("V5 profile 1.4.4 does not inherit", 'PROFILE_1_4_4 = dict(PROFILE_1_4_5, **{"rp_input": "unknown"})', 'PROFILE_1_4_4 = {"rp_input": "unknown"}'),
 ("V5 CLI --profile 1.4.5 unknown", '"1.4.5": PROFILE_1_4_5, ', ''),
 ("V5 CLI --rp-point unknown", '"--rp-point": "rp_point", "--sig-r"', '"--sig-r"'),
 ("V5 usage error names the profile", '--profile takes 1.4.7, 1.4.5, 1.4.4,', '--profile takes 1.4.7, 1.4.4,'),
 ("V5 usage line of the switch", '  --rp-point step12|off|always        (default step12)\n', ''),
 ("V5 usage line of the profile", '  --profile 1.4.5              the readings 0.9.0 gave', '  --profile 1.4.4              the readings 0.9.0 gave'),
]
TESTS = ["tests/test_profile147.py", "tests/test_profile145.py", "tests/test_cli.py"]


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
