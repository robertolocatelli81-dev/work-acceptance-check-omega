"""Targeted mutants of the 0.12.0 changes (profile 1.4.11 at 8ce7f42, README "Profile 1.4.11 rules" X4, X7, reading Q36 and the command
line): each one must make at least one test fail. The unmutated copy is run first through the same driver (control): it must pass.
usage: python3 -B tools/mutate1411.py PYTHON [I/N]   (an interpreter with cryptography >= 40; I/N runs every Nth mutant from the Ith,
counted from 0, so that N processes share the list: the totals are then the sum of their lines)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
GATE = 'if opts["criteria_noncharacters"] == "unreadable":                        # X4, Q36'
TEST = 'if 0xFDD0 <= c <= 0xFDEF or c & 0xFFFE == 0xFFFE:'
WALK = ("            stack.extend(v)\n            stack.extend(v.values())\n        elif isinstance(v, list):\n            stack.extend(v)\n"
        "    return None")
NAMES_VALUES = "            stack.extend(v)\n            stack.extend(v.values())"
P147 = 'PROFILE_1_4_7 = dict(PROFILE_1_4_8, **{"sig_r": "not-small", "criteria_unreadable": "mismatch"})'
NOTE_GATE = 'if opts["criteria_noncharacters"] == "report":                         # X4, Q36'
REASON = '"JSON string with the noncharacter U+%04X (RFC 7493 2.1)" % c'
M = [
 # X4 the rule
 ("X4 default readable", '    "criteria_noncharacters": "report",\n', '    "criteria_noncharacters": "readable",\n'),
 ("X4 default unreadable", '    "criteria_noncharacters": "report",\n', '    "criteria_noncharacters": "unreadable",\n'),
 ("Q36 no note", NOTE_GATE, 'if False:'),
 ("Q36 note under every value", NOTE_GATE, 'if True:'),
 ("Q36 note the wrong way", NOTE_GATE, 'if opts["criteria_noncharacters"] != "report":'),
 ("Q36 note without the hit", "                if nc is not None:\n                    ctx.notes", "                if True:\n                    ctx.notes"),
 ("Q36 note helper finds nothing", "        return _noncharacter(strict_json_loads(", "        return None and _noncharacter(strict_json_loads("),
 ("Q36 note helper ignores the limits switch", 'return _noncharacter(strict_json_loads(crit_bytes, opts["criteria_limits"] == "unreadable"))', 'return _noncharacter(strict_json_loads(crit_bytes, True))'),
 ("Q36 note helper raises on a refusal", "    except Refusal:\n        return None\n\n\ndef _criteria_unreadable", "    except ZeroDivisionError:\n        return None\n\n\ndef _criteria_unreadable"),
 ("Q36 the note names another point", '"refuses it)" % nc)', '"refuses it)" % (nc + 1))'),
 ("RFC 7493 2.1 root string reached", "    stack = [obj] if isinstance(obj, (dict, list)) else []", "    stack = [obj]"),
 ("X4 no check", GATE, 'if False:'),
 ("X4 the switch does nothing", GATE, 'if True:'),
 ("X4 the switch the wrong way", GATE, 'if opts["criteria_noncharacters"] != "unreadable":'),
 ("X4 range starts at FDD1", TEST, 'if 0xFDD1 <= c <= 0xFDEF or c & 0xFFFE == 0xFFFE:'),
 ("X4 range ends at FDEE", TEST, 'if 0xFDD0 <= c <= 0xFDEE or c & 0xFFFE == 0xFFFE:'),
 ("X4 range ends at FDF0", TEST, 'if 0xFDD0 <= c <= 0xFDF0 or c & 0xFFFE == 0xFFFE:'),
 ("X4 range starts at FDCF", TEST, 'if 0xFDCF <= c <= 0xFDEF or c & 0xFFFE == 0xFFFE:'),
 ("X4 only xFFFF", TEST, 'if 0xFDD0 <= c <= 0xFDEF or c & 0xFFFF == 0xFFFF:'),
 ("X4 only the BMP pair", TEST, 'if 0xFDD0 <= c <= 0xFDEF or c in (0xFFFE, 0xFFFF):'),
 ("X4 no range", TEST, 'if c & 0xFFFE == 0xFFFE:'),
 ("X4 no pairs", TEST, 'if 0xFDD0 <= c <= 0xFDEF:'),
 ("X4 and for or", TEST, 'if 0xFDD0 <= c <= 0xFDEF and c & 0xFFFE == 0xFFFE:'),
 ("X4 mask FFFC", TEST, 'if 0xFDD0 <= c <= 0xFDEF or c & 0xFFFC == 0xFFFC:'),
 ("X4 the walk skips names", WALK, WALK.replace(NAMES_VALUES, "            stack.extend(v.values())")),
 ("X4 the walk skips values", WALK, WALK.replace(NAMES_VALUES, "            stack.extend(v)")),
 ("X4 the walk skips arrays", WALK, WALK.replace("        elif isinstance(v, list):\n            stack.extend(v)\n", "")),
 ("X4 the first character only", "            for ch in v:\n                c = ord(ch)", "            for ch in v[:1]:\n                c = ord(ch)"),
 ("X4 a hit is not returned", "                    return c\n", "                    break\n"),
 ("X4 the reason", REASON, '"JSON string with a character U+%04X" % c'),
 ("X4 not a reason", "            return " + REASON + "\n", "            return None\n"),
 # X7 the older reading, the command line
 ("X7 profile 1.4.8 empty", 'PROFILE_1_4_8 = {"criteria_noncharacters": "readable"}', 'PROFILE_1_4_8 = {}'),
 ("X7 profile 1.4.8 the other value", 'PROFILE_1_4_8 = {"criteria_noncharacters": "readable"}', 'PROFILE_1_4_8 = {"criteria_noncharacters": "unreadable"}'),
 ("X7 profile 1.4.7 does not inherit", P147, 'PROFILE_1_4_7 = dict(**{"sig_r": "not-small", "criteria_unreadable": "mismatch"})'),
 ("X7 no --profile 1.4.8", 'PROFILES = {"1.4.8": PROFILE_1_4_8, ', 'PROFILES = {'),
 ("X7 one value only", '"criteria_noncharacters": ("report", "unreadable", "readable"),', '"criteria_noncharacters": ("report", "unreadable"),'),
 ("X7 values without report", '"criteria_noncharacters": ("report", "unreadable", "readable"),', '"criteria_noncharacters": ("unreadable", "readable"),'),
 ("X7 no flag", '               "--criteria-noncharacters": "criteria_noncharacters"}', '               "--criteria-noncharacter": "criteria_noncharacters"}'),
 ("X7 usage line of the switch", "  --criteria-noncharacters report|unreadable|readable   (default report)\n", ""),
 ("X7 usage line of the profile", "  --profile 1.4.8              the reading 0.11.0 gave to 1.4.8", "  --profile 1.4.8              the reading 0.10.0 gave to 1.4.8"),
 ("X7 usage error names the profile", "--profile takes 1.4.8, 1.4.7,", "--profile takes 1.4.7,"),
 ("X7 usage line of the defaults", "defaults follow profile 1.4.11 (", "defaults follow profile 1.4.8 ("),
 ("the version", 'VERSION = "war_verify 0.12.0"', 'VERSION = "war_verify 0.11.0"'),
 ("the docstring", "draft profile 1.4.11 (schema identifier 1.2).", "draft profile 1.4.8 (schema identifier 1.2)."),
]
TESTS = ["tests/test_profile1411.py", "tests/test_profile148.py", "tests/test_cli.py"]

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
