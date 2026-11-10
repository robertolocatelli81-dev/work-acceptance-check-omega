"""Differential: war-verify 0.11.0 (7d9f528) against 0.12.0 with --profile 1.4.8 (README, "Results, profile 1.4.11"), on the fuzz
cases (tools/fuzz.py), every vector file under fonti/ and vectors/, the generated cases of tests/test_profile144.py,
tests/test_profile145.py, tests/test_profile147.py and tests/test_profile148.py (as tools/differential_0100.py), and those of
tests/test_profile1411.py (each of the 66 noncharacters escaped in a value and as bytes in a name, their neighbours, and 300 generated
strings), under the option sets below: every older profile and each switch that keeps its meaning. Compares the whole report except
its member `options`, which names the new switch.
Usage: python3 -B tools/differential_0110.py . DIR0110 [control]   (DIR0110: an archive of 7d9f528).
`control`: the positive control, 0.12.0 with its defaults instead of --profile 1.4.8, so the bench must report differences."""
import sys, os, json, glob, copy, importlib.util, itertools, random
repo, d0110 = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(repo, "tools")); sys.path.insert(0, os.path.join(repo, "tests")); sys.path.insert(0, repo)
import war_verify as w12, fuzz
import test_profile144 as t
import test_profile145 as u
import test_profile147 as v
import test_profile148 as x
import test_profile1411 as y
spec = importlib.util.spec_from_file_location("w11", os.path.join(d0110, "war_verify.py"))
w11 = importlib.util.module_from_spec(spec); spec.loader.exec_module(w11)
assert w11.VERSION.endswith("0.11.0") and w12.VERSION.endswith("0.12.0")


def out(mod, doc, opts):
    try:
        if isinstance(doc, (bytes, str)):
            raw = doc.encode("utf-8", "surrogatepass") if isinstance(doc, str) else doc
            rep = mod.run_vector_bytes(raw, opts)[0]
        else:
            rep = mod.run_vector(copy.deepcopy(doc), opts)[0]
    except Exception as e:
        return {"exception": type(e).__name__}
    rep.pop("options", None)
    return rep


cases = []
base = fuzz.build.base()
for fname, fam in fuzz.FAMILIES:
    for name, case, exp in fam(base):
        cases.append(("fuzz:" + name, case if isinstance(case, str) else json.loads(json.dumps(case))))
for f in sorted(glob.glob(os.path.join(repo, "fonti/**/*.json"), recursive=True)) + sorted(glob.glob(os.path.join(repo, "vectors/*.json"))):
    with open(f, "rb") as fh:
        cases.append((os.path.relpath(f, repo), fh.read()))
n_gen = 0
for stated, (pn, _), (pk, _k) in itertools.product(("independent", "self-checked"), t.NAMES, t.KEYS):
    cases.append(("gen:%s|%r|%r" % (stated, pn if pn is not t.MISSING else "MISSING", pk if pk is not t.MISSING else "MISSING"),
                  {"inputs": json.loads(json.dumps(t.doc(stated, "Example Checker", pn, t.SIGNER, pk)))})); n_gen += 1
for stated, pn, pl, pk, kind, label, entries, holds in u.table():
    cases.append(("gen-rp:%s|%r|%r|%s" % (stated, pn if pn is not t.MISSING else "MISSING", pk if pk is not t.MISSING else "MISSING", label),
                  {"inputs": json.loads(json.dumps(u.doc(stated, pn, pk, u.rpdoc(entries), full=True)))})); n_gen += 1
for label, pub, one_key, fails, stated, pname, kind, lname, entries, supplied, held in v.PointRule().table():
    cases.append(("gen-point:%s|%s|%s|%s" % (label, stated, kind, lname),
                  {"inputs": json.loads(json.dumps(v.record(stated, pname, pub, entries)))})); n_gen += 1
for label, data, want, fam in x.table():
    for matches in (True, False):
        cases.append(("gen-criteria:%s|%s" % (label, matches), {"inputs": x.record(data, matches)})); n_gen += 1
for k, data in enumerate(x.generated(148, 300)):
    cases.append(("gen-doc:%d" % k, {"inputs": x.record(data)})); n_gen += 1
s = x.SignatureR()
x.SignatureR.setUpClass()
for label, rb, r, cls, why in s.classes():
    cases.append(("gen-r:%s" % label, {"inputs": s.signed(s.forged(rb, r))})); n_gen += 1
for c in y.NONCHARACTERS:
    cases.append(("gen-nc-value:%04X" % c, {"inputs": y.record(y.extra(b'"x":"a' + y.escaped(c) + b'"'))})); n_gen += 1
    cases.append(("gen-nc-name:%04X" % c, {"inputs": y.record(y.extra(b'"' + chr(c).encode("utf-8") + b'":1', "item"))})); n_gen += 1
for c in sorted({c + d for c in y.NONCHARACTERS for d in (-1, 1)} - set(y.NONCHARACTERS)):
    if c <= 0x10FFFF:
        cases.append(("gen-near:%04X" % c, {"inputs": y.record(y.extra(b'"x":"' + y.escaped(c) + b'"'))})); n_gen += 1
rng = random.Random(14110)
pool = sorted({c + d for c in y.NONCHARACTERS for d in range(-2, 3)} | set(range(0x61, 0x7B)))
pool = [c for c in pool if c <= 0x10FFFF]
for k in range(300):
    cps = [rng.choice(pool) for _ in range(rng.randrange(1, 4))]
    body = b"".join(y.escaped(c) if rng.random() < 0.5 else chr(c).encode("utf-8") for c in cps)
    cases.append(("gen-str:%d" % k, {"inputs": y.record(y.extra(b'"x":"' + body + b'"'))})); n_gen += 1
diffs, n = [], 0
mode = sys.argv[3:]
P = dict(w12.PROFILE_1_4_8)
SETS = [({}, P, "defaults vs --profile 1.4.8"),
        (dict(w11.PROFILE_1_4_7), dict(w12.PROFILE_1_4_7), "--profile 1.4.7 vs --profile 1.4.7"),
        (dict(w11.PROFILE_1_4_5), dict(w12.PROFILE_1_4_5), "--profile 1.4.5 vs --profile 1.4.5"),
        (dict(w11.PROFILE_1_4_4), dict(w12.PROFILE_1_4_4), "--profile 1.4.4 vs --profile 1.4.4"),
        (dict(w11.PROFILE_1_4_3), dict(w12.PROFILE_1_4_3), "--profile 1.4.3 vs --profile 1.4.3"),
        (dict(w11.PROFILE_1_4_2), dict(w12.PROFILE_1_4_2), "--profile 1.4.2 vs --profile 1.4.2"),
        (dict(w11.PROFILE_1_2_1), dict(w12.PROFILE_1_2_1), "--profile 1.2.1 vs --profile 1.2.1"),
        ({"unknown_fields": "report"}, dict(P, unknown_fields="report"), "--unknown-fields report"),
        ({"criteria_limits": "readable"}, dict(P, criteria_limits="readable"), "--criteria-limits readable"),
        ({"criteria_read": "always"}, dict(P, criteria_read="always"), "--criteria-read always"),
        ({"rp_point": "always"}, dict(P, rp_point="always"), "--rp-point always")]
if mode == ["control"]:
    SETS = [({}, {}, "control: defaults vs defaults")]
for opts11, opts12, label in SETS:
    for name, c in cases:
        n += 1
        a, b = out(w11, c, opts11), out(w12, c, opts12)
        if a != b:
            diffs.append((label, name, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}))
print("cases", len(cases), "of which generated", n_gen)
print("compared", n, "runs;", len(diffs), "differ")
by = {}
for d in diffs:
    by[d[1].split(":")[0]] = by.get(d[1].split(":")[0], 0) + 1
print("differing runs by kind of case:", json.dumps(by, sort_keys=True))
for d in diffs[:(8 if mode == ["control"] else 60)]:
    print(d[0], "|", d[1], "|", json.dumps(d[2], default=str)[:300])
