"""Differential: war-verify 0.10.0 (70d2df7) against 0.11.0 with --profile 1.4.7 (README, "Results, profile 1.4.8"), on the fuzz
cases (tools/fuzz.py), every vector file under fonti/ and vectors/, the generated cases of tests/test_profile144.py,
tests/test_profile145.py and tests/test_profile147.py, and those of tests/test_profile148.py (the criteria documents of its table
with the hash matching and not matching, 300 generated documents, the signatures of its table of R), under the option sets
below: every older profile and each switch that keeps its meaning. Compares the whole report except its member `options`, which
names the new switches. One wording changed on purpose: the note X_RP_PRODUCER_KEY_POINT_RULE of 0.10.0 said "derived self-checked"
also where the report says `undeclared`; the words are removed from the 0.10.0 note before comparing, and the runs where that
happened are counted and printed.
Usage: python3 -B tools/differential_0100.py . DIR0100 [control]   (DIR0100: an archive of 70d2df7).
`control`: the positive control, 0.11.0 with its defaults instead of --profile 1.4.7, so the bench must report differences."""
import sys, os, json, glob, copy, importlib.util, itertools
repo, d0100 = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(repo, "tools")); sys.path.insert(0, os.path.join(repo, "tests")); sys.path.insert(0, repo)
import war_verify as w11, fuzz
import test_profile144 as t
import test_profile145 as u
import test_profile147 as v
import test_profile148 as x
spec = importlib.util.spec_from_file_location("w10", os.path.join(d0100, "war_verify.py"))
w10 = importlib.util.module_from_spec(spec); spec.loader.exec_module(w10)
assert w10.VERSION.endswith("0.10.0") and w11.VERSION.endswith("0.11.0")


OLD_NOTE = "establishes no producer: derived self-checked (profile 1.4.7"
NEW_NOTE = "establishes no producer (profile 1.4.7"
reworded = [0]


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
    if mod is w10 and any(OLD_NOTE in n for n in rep.get("notes", ())):
        rep["notes"] = [n.replace(OLD_NOTE, NEW_NOTE) for n in rep["notes"]]
        reworded[0] += 1
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
diffs, n = [], 0
mode = sys.argv[3:]
P = dict(w11.PROFILE_1_4_7)
SETS = [({}, P, "defaults vs --profile 1.4.7"),
        (dict(w10.PROFILE_1_4_5), dict(w11.PROFILE_1_4_5), "--profile 1.4.5 vs --profile 1.4.5"),
        (dict(w10.PROFILE_1_4_4), dict(w11.PROFILE_1_4_4), "--profile 1.4.4 vs --profile 1.4.4"),
        (dict(w10.PROFILE_1_4_3), dict(w11.PROFILE_1_4_3), "--profile 1.4.3 vs --profile 1.4.3"),
        (dict(w10.PROFILE_1_4_2), dict(w11.PROFILE_1_4_2), "--profile 1.4.2 vs --profile 1.4.2"),
        (dict(w10.PROFILE_1_2_1), dict(w11.PROFILE_1_2_1), "--profile 1.2.1 vs --profile 1.2.1"),
        ({"unknown_fields": "report"}, dict(P, unknown_fields="report"), "--unknown-fields report"),
        ({"ed25519": "rfc8032"}, dict(P, ed25519="rfc8032"), "--ed25519 rfc8032"),
        ({"correspondence": "strict"}, dict(P, correspondence="strict"), "--correspondence strict"),
        ({"rp_point": "always"}, dict(P, rp_point="always"), "--rp-point always")]
if mode == ["control"]:
    SETS = [({}, {}, "control: defaults vs defaults")]
for opts10, opts11, label in SETS:
    for name, c in cases:
        n += 1
        a, b = out(w10, c, opts10), out(w11, c, opts11)
        if a != b:
            diffs.append((label, name, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}))
print("cases", len(cases), "of which generated", n_gen)
print("compared", n, "runs;", len(diffs), "differ;", reworded[0], "runs with the note reworded in the 0.10.0 report")
for d in diffs[:(0 if mode == ["control"] else 60)]:
    print(d[0], "|", d[1], "|", json.dumps(d[2], default=str)[:300])
