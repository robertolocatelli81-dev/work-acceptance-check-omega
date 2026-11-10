"""Targeted mutants of the 0.11.0 changes (profile 1.4.8 at 3e53aac, README "Profile 1.4.8 rules" W1-W8, Q32-Q35 and the command
line): each one must make at least one test fail. The unmutated copy is run first through the same driver (control): it must
pass. usage: python3 -B tools/mutate148.py PYTHON [I/N]   (an interpreter with cryptography >= 40, Python 3.11 or newer for the
mutant of `parse_int`; I/N runs every Nth mutant from the Ith, counted from 0, so that N processes share the list: the totals
are then the sum of their lines)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
MIXED = 'if sig_r == "prime-order" and not _pequal(_pmul(_L, R), _IDENT):'
READ = 'crit_hash == "match" or opts["criteria_read"] == "always"):'
DOCOBJ = 'return "the document is not an object" if absent else None'
NOCRIT = 'return "the document has no member `criteria`" if absent else None'
ITEM = 'if m in c and not isinstance(c[m], t):'
ABSENT = 'if absent and m not in c and (m, t, name) in CRITERIA_READ_TYPES:'
LIMITS = 'opts["criteria_unreadable"] == "mismatch" or opts["criteria_limits"] == "unreadable")'
M = [
 # W1, W2 the R of a signature
 ("W1 default not-small", '    "sig_r": "prime-order",\n', '    "sig_r": "not-small",\n'),
 ("W1 no check of mixed order", MIXED, 'if False:'),
 ("W1 the switch does nothing", MIXED, 'if not _pequal(_pmul(_L, R), _IDENT):'),
 ("W1 the argument's default", 'def ed25519_verify(pub, msg, sig, mode, sig_r="prime-order"):', 'def ed25519_verify(pub, msg, sig, mode, sig_r="not-small"):'),
 ("W1 the record does not pass the switch", 'opts["ed25519"], opts["sig_r"])', 'opts["ed25519"])'),
 ("W1 the order of the wrong point", 'not _pequal(_pmul(_L, R), _IDENT):      # 1.4.8', 'not _pequal(_pmul(_L, _BASE), _IDENT):      # 1.4.8'),
 ("W1 the reason", '"R has mixed order (profile 1.4.8 step 2)"', '"signature does not verify"'),
 ("W1 small order dropped", 'if _pequal(_pmul(8, R), _IDENT):\n            return False, "R has small order', 'if False:\n            return False, "R has small order'),
 ("W2 also under rfc8032", '    if mode == "strict":\n        if _pequal(_pmul(8, R), _IDENT):', '    if sig_r == "prime-order" and not _pequal(_pmul(_L, R), _IDENT):\n        return False, "R"\n    if mode == "strict":\n        if _pequal(_pmul(8, R), _IDENT):'),
 # W3 the code and where it comes from
 ("W3 default mismatch", '    "criteria_unreadable": "step4",\n', '    "criteria_unreadable": "mismatch",\n'),
 ("W3 no code", 'problems.add("CRITERIA_UNREADABLE")', 'problems.add("CRITERIA_RESULTS_MISMATCH")'),
 ("W3 the code out of the list", '"CRITERIA_RESULTS_MISMATCH", "CRITERIA_UNREADABLE",\n', '"CRITERIA_RESULTS_MISMATCH",\n'),
 ("W3 no reason", 'details["criteria_unreadable"] = unreadable', 'pass'),
 ("W3 a refusal reads as readable", '        return "%s: %s" % (e.reason, e.detail) if e.detail else e.reason\n', '        return None\n'),
 ("W3 no limits parameter", 'doc = strict_json_loads(crit_bytes, opts["criteria_limits"] == "unreadable")', 'doc = strict_json_loads(crit_bytes)'),
 ("W3 limits the wrong way", 'doc = strict_json_loads(crit_bytes, opts["criteria_limits"] == "unreadable")', 'doc = strict_json_loads(crit_bytes, opts["criteria_limits"] != "unreadable")'),
 ("W3 the file None reaches the reader", 'if opts["criteria_unreadable"] == "step4" and crit_file is not None and (', 'if opts["criteria_unreadable"] == "step4" and ('),
 # W6 types
 ("W6 no array", 'if not isinstance(doc["criteria"], list):\n        return "member', 'if False:\n        return "member'),
 ("W6 no object", 'if not isinstance(c, dict):\n            return "criteria[%d] is not an object" % i', 'if not isinstance(c, dict):\n            continue'),
 ("W6 no member typed", ITEM, 'if False:'),
 ("W6 null counts as absent", ITEM, 'if c.get(m) is not None and not isinstance(c[m], t):'),
 ("W6 id of any type", '("id", str, "a string")', '("id", object, "a string")'),
 ("W6 required an integer", '("required", bool, "a boolean")', '("required", int, "a boolean")'),
 ("W6 required of any type", '("required", bool, "a boolean")', '("required", object, "a boolean")'),
 ("W6 stops at the first criterion", '                return "criteria[%d] has no member `%s`" % (i, m)\n    return None', '                return "criteria[%d] has no member `%s`" % (i, m)\n        break\n    return None'),
 # W7 precedence, Q32
 ("W7 always read", READ, 'True):'),
 ("W7 Q32 always does nothing", READ, 'crit_hash == "match"):'),
 ("W7 the correspondence runs too", '            details["criteria_unreadable"] = unreadable\n        elif crit_hash == "match":', '            details["criteria_unreadable"] = unreadable\n        if crit_hash == "match":'),
 ("W7 default always", '    "criteria_read": "matched",\n', '    "criteria_read": "always",\n'),
 ("Q32 one value", '"criteria_read": ("matched", "always")', '"criteria_read": ("matched",)'),
 # Q33
 ("Q33 document always unreadable", DOCOBJ, 'return "the document is not an object"'),
 ("Q33 document never", DOCOBJ, 'return None'),
 ("Q33 no criteria always unreadable", NOCRIT, 'return "the document has no member `criteria`"'),
 ("Q33 no criteria never", NOCRIT, 'return None'),
 ("Q33 no member always unreadable", ABSENT, 'if m not in c and (m, t, name) in CRITERIA_READ_TYPES:'),
 ("Q33 no member never", ABSENT, 'if False:'),
 ("Q33 known members must exist too", ABSENT, 'if absent and m not in c:'),
 ("Q33 default absent", '    "criteria_shape": "typed",\n', '    "criteria_shape": "absent",\n'),
 ("Q33 one value", '"criteria_shape": ("typed", "absent")', '"criteria_shape": ("typed",)'),
 # Q34
 ("Q34 default known", '    "criteria_types": "read",\n', '    "criteria_types": "known",\n'),
 ("Q34 known does nothing", 'known = opts["criteria_types"] == "known"', 'known = False'),
 ("Q34 no top members", 'if m in doc and not isinstance(doc[m], t):', 'if False:'),
 ("Q34 no items of the vocabulary", 'not all(isinstance(x, str) for x in doc["result_vocabulary"])', 'False'),
 ("Q34 no members of a criterion", 'CRITERIA_READ_TYPES + (CRITERIA_KNOWN_ITEM if known else ())', 'CRITERIA_READ_TYPES'),
 ("Q34 version any type", '("version", str, "a string")', '("version", object, "a string")'),
 ("Q34 one value", '"criteria_types": ("read", "known")', '"criteria_types": ("read",)'),
 # Q35
 ("Q35 default readable", '    "criteria_limits": "unreadable",\n', '    "criteria_limits": "readable",\n'),
 ("Q35 the mark stays", '        data = data[3:]\n', '        pass\n'),
 ("Q35 the mark refused", '        if limits:\n            raise Refusal("JSON text starts', '        if True:\n            raise Refusal("JSON text starts'),
 ("Q35 Python's limit on digits decides", 'parse_constant=_no_constant, parse_int=lambda _s: 0)', 'parse_constant=_no_constant)'),
 ("Q35 the walk stops at surrogates", '    if limits:\n        _check_values(obj)\n    else:\n        _check_strings(obj)\n', '    if limits:\n        _check_values(obj)\n'),
 ("Q35 the walk has limits", '    if limits:\n        _check_values(obj)\n    else:\n        _check_strings(obj)\n', '    _check_values(obj)\n'),
 ("Q35 the walk skips names", '_check_values(v)\n        elif isinstance(v, dict):\n            stack.extend(v)\n            stack.extend(v.values())', '_check_values(v)\n        elif isinstance(v, dict):\n            stack.extend(v.values())'),
 ("Q35 the walk skips values", '_check_values(v)\n        elif isinstance(v, dict):\n            stack.extend(v)\n            stack.extend(v.values())', '_check_values(v)\n        elif isinstance(v, dict):\n            stack.extend(v)'),
 ("Q35 the walk skips arrays", '        elif isinstance(v, list):\n            stack.extend(v)\n\n\ndef strict_json_loads', '\n\n\ndef strict_json_loads'),
 ("Q35 the correspondence keeps the limits", LIMITS, 'True)'),
 ("Q35 the limits leave 0.10.0", LIMITS, 'opts["criteria_limits"] == "unreadable")'),
 ("Q35 one value", '"criteria_limits": ("unreadable", "readable")', '"criteria_limits": ("unreadable",)'),
 # W8 the older readings, the command line, the note of B5
 ("W8 profile 1.4.7 keeps the new R", 'PROFILE_1_4_7 = dict(PROFILE_1_4_8, **{"sig_r": "not-small", "criteria_unreadable": "mismatch"})', 'PROFILE_1_4_7 = dict(PROFILE_1_4_8, **{"criteria_unreadable": "mismatch"})'),
 ("W8 profile 1.4.7 keeps the code", 'PROFILE_1_4_7 = dict(PROFILE_1_4_8, **{"sig_r": "not-small", "criteria_unreadable": "mismatch"})', 'PROFILE_1_4_7 = dict(PROFILE_1_4_8, **{"sig_r": "not-small"})'),
 ("W8 profile 1.4.5 does not inherit", 'PROFILE_1_4_5 = dict(PROFILE_1_4_7, **{"rp_repeated": "no-key", "rp_point": "off"})', 'PROFILE_1_4_5 = {"rp_repeated": "no-key", "rp_point": "off"}'),
 ("W8 CLI --profile 1.4.7 unknown", '"1.4.7": PROFILE_1_4_7, ', ''),
 ("W8 one value of --sig-r", '"sig_r": ("prime-order", "not-small")', '"sig_r": ("prime-order",)'),
 ("W8 one value of --criteria-unreadable", '"criteria_unreadable": ("step4", "mismatch")', '"criteria_unreadable": ("step4",)'),
 ("W8 usage error names the profile", '--profile takes 1.4.8, 1.4.7, 1.4.5,', '--profile takes 1.4.8, 1.4.5,'),
 ("W8 usage line of the profile", '  --profile 1.4.7              the readings 0.10.0 gave', '  --profile 1.4.5              the readings 0.10.0 gave'),
 ("W8 usage line of the defaults", 'defaults follow profile 1.4.11', 'defaults follow profile 1.4.8'),
 ("CLI --sig-r unknown", '"--sig-r": "sig_r", ', ''),
 ("CLI --criteria-unreadable unknown", '"--criteria-unreadable": "criteria_unreadable",', ''),
 ("CLI --criteria-read unknown", '"--criteria-read": "criteria_read", ', ''),
 ("CLI --criteria-shape unknown", '"--criteria-shape": "criteria_shape",', ''),
 ("CLI --criteria-types unknown", '"--criteria-types": "criteria_types", ', ''),
 ("CLI --criteria-limits unknown", ', "--criteria-limits": "criteria_limits"', ''),
 ("usage line of --sig-r", '  --sig-r prime-order|not-small       (default prime-order)\n', ''),
 ("usage line of --criteria-unreadable", '  --criteria-unreadable step4|mismatch   (default step4)\n', ''),
 ("usage line of --criteria-read", '  --criteria-read matched|always      (default matched)\n', ''),
 ("usage line of --criteria-shape", '  --criteria-shape typed|absent       (default typed)\n', ''),
 ("usage line of --criteria-types", '  --criteria-types read|known         (default read)\n', ''),
 ("usage line of --criteria-limits", '  --criteria-limits unreadable|readable   (default unreadable)\n', ''),
 ("the version", 'VERSION = "war_verify 0.12.0"', 'VERSION = "war_verify 0.11.0"'),
 ("B5 the note says derived again", '"rule of step 2 and establishes no producer (profile 1.4.7 step 12, "', '"rule of step 2 and establishes no producer: derived self-checked (profile 1.4.7 step 12, "'),
]
TESTS = ["tests/test_profile148.py", "tests/test_profile145.py", "tests/test_cli.py"]


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
