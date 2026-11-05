"""Differential: war-verify 0.7.0 (349a041) against 0.8.0 with --profile 1.4.3 (README, "Results, profile 1.4.4"), on the
fuzz cases (tools/fuzz.py), every vector file under fonti/ and vectors/, and the generated cases of the 1.4.4 name and
presence space (tests/test_profile144.py, NAMES and KEYS), under four option sets. Compares the profile fields, refusal
and reason, tsa_signature, files and the extension codes, all of them: X_NAME_NOT_STRING cannot arise under --profile
1.4.3, where such a name is refused.
Usage: python3 -B tools/differential_070.py . DIR070 [control]   (DIR070: a checkout of 349a041). With `control`, the
positive control: 0.8.0 with its defaults instead of --profile 1.4.3, so the bench must report differences."""
import sys, os, json, glob, copy, importlib.util, itertools
repo, d070 = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(repo, "tools")); sys.path.insert(0, os.path.join(repo, "tests")); sys.path.insert(0, repo)
import war_verify as w8, fuzz, build
import test_profile144 as t
spec = importlib.util.spec_from_file_location("w7", os.path.join(d070, "war_verify.py"))
w7 = importlib.util.module_from_spec(spec); spec.loader.exec_module(w7)
assert w7.VERSION.endswith("0.7.0") and w8.VERSION.endswith("0.8.0")
KEYS = ("refused", "reason", "problem_codes", "warning_codes", "signature_valid", "criteria_committed_before_check",
        "criteria_hash", "independence", "receipt_timestamp", "verdict_recomputed", "tsa_signature", "files",
        "extension_codes")
def out(mod, doc, opts):
    try:
        if isinstance(doc, (bytes, str)):
            raw = doc.encode("utf-8", "surrogatepass") if isinstance(doc, str) else doc
            rep = mod.run_vector_bytes(raw, opts)[0]
        else:
            rep = mod.run_vector(copy.deepcopy(doc), opts)[0]
    except Exception as e:
        return {"exception": type(e).__name__}
    o = {k: rep.get(k) for k in KEYS}
    o["derived"] = rep.get("details", {}).get("independence_derived")
    return o
cases = []
base = build.base()
for fname, fam in fuzz.FAMILIES:
    for name, case, exp in fam(base):
        cases.append(("fuzz:" + name, case if isinstance(case, str) else json.loads(json.dumps(case))))
for f in sorted(glob.glob(os.path.join(repo, "fonti/**/*.json"), recursive=True)) + sorted(glob.glob(os.path.join(repo, "vectors/*.json"))):
    cases.append((os.path.relpath(f, repo), open(f, "rb").read()))
n_gen = 0
for stated, (pn, _), (pk, _k) in itertools.product(("independent", "self-checked"), t.NAMES, t.KEYS):
    cases.append(("gen:%s|%r|%r" % (stated, pn if pn is not t.MISSING else "MISSING", pk if pk is not t.MISSING else "MISSING"),
                  {"inputs": json.loads(json.dumps(t.doc(stated, "Example Checker", pn, t.SIGNER, pk)))})); n_gen += 1
for stated, (cn, _) in itertools.product(("independent", "self-checked"), t.NAMES):
    if cn is not t.MISSING:
        cases.append(("gen-checker:%s|%r" % (stated, cn), {"inputs": json.loads(json.dumps(t.doc(stated, cn, "Example Vendor")))})); n_gen += 1
diffs, n = [], 0
control = sys.argv[3:] == ["control"]
for opts7, opts8, label in ((({}, {}, "control: defaults vs defaults"),) if control else ()) or (
                            ({}, dict(w8.PROFILE_1_4_3), "defaults vs --profile 1.4.3"),
                            (dict(w7.PROFILE_1_4_2), dict(w8.PROFILE_1_4_2), "--profile 1.4.2 vs --profile 1.4.2"),
                            (dict(w7.PROFILE_1_2_1), dict(w8.PROFILE_1_2_1), "--profile 1.2.1 vs --profile 1.2.1"),
                            ({"key_rule": "all-keys"}, dict(w8.PROFILE_1_4_3, key_rule="all-keys"), "all-keys")):
    for name, c in cases:
        n += 1
        a, b = out(w7, c, opts7), out(w8, c, opts8)
        if a != b:
            diffs.append((label, name, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}))
print("cases", len(cases), "of which generated", n_gen)
print("compared", n, "runs;", len(diffs), "differ")
for d in diffs[:60]:
    print(d[0], "|", d[1], "|", json.dumps(d[2], default=str)[:300])
