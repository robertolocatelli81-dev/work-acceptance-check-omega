"""Differential: war-verify 0.9.0 (20837ca) against 0.10.0 with --profile 1.4.5 (README, "Results, profile 1.4.7"), on the
fuzz cases (tools/fuzz.py), every vector file under fonti/ and vectors/, the generated cases of the 1.4.4 space
(tests/test_profile144.py), of the relying-party space (tests/test_profile145.py) and of the point rule and repeated
identifiers (tests/test_profile147.py), under ten option sets: every older profile and each switch of 1.4.5 that keeps its
meaning. Compares the whole report except its member `options`, which names the new switch.
Usage: python3 -B tools/differential_090.py . DIR090 [control|repeated]   (DIR090: an archive of 20837ca).
`control`: the positive control, 0.10.0 with its defaults instead of --profile 1.4.5, so the bench must report differences.
`repeated`: `--rp-repeated bytes` in both; the value keeps its name but not its block (README V1), so differences are
expected, and each one must be the block and the notes only."""
import sys, os, json, glob, copy, importlib.util, itertools
repo, d090 = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(repo, "tools")); sys.path.insert(0, os.path.join(repo, "tests")); sys.path.insert(0, repo)
import war_verify as w10, fuzz
import test_profile144 as t
import test_profile145 as u
import test_profile147 as v
spec = importlib.util.spec_from_file_location("w9", os.path.join(d090, "war_verify.py"))
w9 = importlib.util.module_from_spec(spec); spec.loader.exec_module(w9)
assert w9.VERSION.endswith("0.9.0") and w10.VERSION.endswith(("0.10.0", "0.11.0"))


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
for kid, size in itertools.product(("a", v.PRODUCER), (2, 3)):
    for pubs in itertools.product((v.K2, v.K3, v.K1), repeat=size):
        cases.append(("gen-repeated:%s|%d|%s" % (kid, size, ",".join(p[:6] for p in pubs)),
                      {"inputs": json.loads(json.dumps(v.record("independent", "Example Vendor", v.K2, [v.entry(kid, p) for p in pubs])))})); n_gen += 1
diffs, n = [], 0
mode = sys.argv[3:]
P = dict(w10.PROFILE_1_4_5)
SETS = [({}, P, "defaults vs --profile 1.4.5"),
        (dict(w9.PROFILE_1_4_4), dict(w10.PROFILE_1_4_4), "--profile 1.4.4 vs --profile 1.4.4"),
        (dict(w9.PROFILE_1_4_3), dict(w10.PROFILE_1_4_3), "--profile 1.4.3 vs --profile 1.4.3"),
        (dict(w9.PROFILE_1_4_2), dict(w10.PROFILE_1_4_2), "--profile 1.4.2 vs --profile 1.4.2"),
        (dict(w9.PROFILE_1_2_1), dict(w10.PROFILE_1_2_1), "--profile 1.2.1 vs --profile 1.2.1"),
        ({"unknown_fields": "report"}, dict(P, unknown_fields="report"), "--unknown-fields report"),
        ({"rp_form": "bare-list"}, dict(P, rp_form="bare-list"), "--rp-form bare-list"),
        ({"rp_empty": "absent"}, dict(P, rp_empty="absent"), "--rp-empty absent"),
        ({"rp_entry_defect": "key-rejected"}, dict(P, rp_entry_defect="key-rejected"), "--rp-entry-defect key-rejected"),
        ({"rp_lookup": "both"}, dict(P, rp_lookup="both"), "--rp-lookup both")]
if mode == ["control"]:
    SETS = [({}, {}, "control: defaults vs defaults")]
elif mode == ["repeated"]:
    SETS = [({"rp_repeated": "bytes"}, dict(P, rp_repeated="bytes"), "--rp-repeated bytes")]
for opts9, opts10, label in SETS:
    for name, c in cases:
        n += 1
        a, b = out(w9, c, opts9), out(w10, c, opts10)
        if a != b:
            diffs.append((label, name, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}))
print("cases", len(cases), "of which generated", n_gen)
print("compared", n, "runs;", len(diffs), "differ")
if mode == ["repeated"]:
    members = sorted({k for d in diffs for k in d[2]})
    print("members that differ:", members)
for d in diffs[:(0 if mode == ["control"] else 60)]:
    print(d[0], "|", d[1], "|", json.dumps(d[2], default=str)[:300])
