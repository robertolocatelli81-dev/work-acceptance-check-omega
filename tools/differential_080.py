"""Differential: war-verify 0.8.0 (ce8de8c) against 0.9.0 with --profile 1.4.4 (README, "Results, profile 1.4.5"), on the
fuzz cases (tools/fuzz.py), every vector file under fonti/ and vectors/, the generated cases of the 1.4.4 space
(tests/test_profile144.py) and of the relying-party space (tests/test_profile145.py), under five option sets. Compares
the whole report except its member `options`, which names the new switches.
Usage: python3 -B tools/differential_080.py . DIR080 [control]   (DIR080: an archive of ce8de8c). With `control`, the
positive control: 0.9.0 with its defaults instead of --profile 1.4.4, so the bench must report differences."""
import sys, os, json, glob, copy, importlib.util, itertools
repo, d080 = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(repo, "tools")); sys.path.insert(0, os.path.join(repo, "tests")); sys.path.insert(0, repo)
import war_verify as w9, fuzz
import test_profile144 as t
import test_profile145 as u
spec = importlib.util.spec_from_file_location("w8", os.path.join(d080, "war_verify.py"))
w8 = importlib.util.module_from_spec(spec); spec.loader.exec_module(w8)
assert w8.VERSION.endswith("0.8.0") and w9.VERSION.endswith(("0.9.0", "0.10.0", "0.11.0"))


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
diffs, n = [], 0
control = sys.argv[3:] == ["control"]
for opts8, opts9, label in ((({}, {}, "control: defaults vs defaults"),) if control else ()) or (
                            ({}, dict(w9.PROFILE_1_4_4), "defaults vs --profile 1.4.4"),
                            (dict(w8.PROFILE_1_4_3), dict(w9.PROFILE_1_4_3), "--profile 1.4.3 vs --profile 1.4.3"),
                            (dict(w8.PROFILE_1_4_2), dict(w9.PROFILE_1_4_2), "--profile 1.4.2 vs --profile 1.4.2"),
                            (dict(w8.PROFILE_1_2_1), dict(w9.PROFILE_1_2_1), "--profile 1.2.1 vs --profile 1.2.1"),
                            ({"unknown_fields": "report"}, dict(w9.PROFILE_1_4_4, unknown_fields="report"), "--unknown-fields report")):
    for name, c in cases:
        n += 1
        a, b = out(w8, c, opts8), out(w9, c, opts9)
        if a != b:
            diffs.append((label, name, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}))
print("cases", len(cases), "of which generated", n_gen)
print("compared", n, "runs;", len(diffs), "differ")
for d in diffs[:60]:
    print(d[0], "|", d[1], "|", json.dumps(d[2], default=str)[:300])
