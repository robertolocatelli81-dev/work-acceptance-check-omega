"""Differential: war-verify 0.6.0 (c51ff40) against 0.7.0 with --profile 1.4.2 (README, "Results, profile 1.4.3"),
on the fuzz cases (tools/fuzz.py), every vector file under fonti/ and vectors/, under three option sets. Compares the
profile fields, refusal and reason, tsa_signature, files and the extension codes (the two codes new in 0.7.0,
X_KEY_ID_EMPTY and X_DIGEST_MALFORMED, left out; under --profile 1.4.2 neither can arise: both inputs are refused).
Usage: python3 -B tools/differential_060.py . DIR060   (DIR060: a checkout of c51ff40)"""
import sys, os, json, glob, copy, importlib.util
repo, d060 = sys.argv[1], sys.argv[2]
sys.path.insert(0, os.path.join(repo, "tools")); sys.path.insert(0, repo)
import war_verify as w7, fuzz, build
spec = importlib.util.spec_from_file_location("w6", os.path.join(d060, "war_verify.py"))
w6 = importlib.util.module_from_spec(spec); spec.loader.exec_module(w6)
assert w6.VERSION.endswith("0.6.0") and w7.VERSION.endswith(("0.7.0", "0.8.0", "0.9.0", "0.10.0", "0.11.0"))
KEYS = ("refused", "reason", "problem_codes", "warning_codes", "signature_valid", "criteria_committed_before_check",
        "criteria_hash", "independence", "receipt_timestamp", "verdict_recomputed", "tsa_signature", "files")
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
    o["ext"] = sorted(x for x in rep.get("extension_codes", []) if x not in ("X_KEY_ID_EMPTY", "X_DIGEST_MALFORMED"))
    return o
cases = []
base = build.base()
for fname, fam in fuzz.FAMILIES:
    for name, case, exp in fam(base):
        cases.append(("fuzz:" + name, case if isinstance(case, str) else json.loads(json.dumps(case))))
for f in sorted(glob.glob(os.path.join(repo, "fonti/**/*.json"), recursive=True)) + sorted(glob.glob(os.path.join(repo, "vectors/*.json"))):
    cases.append((os.path.relpath(f, repo), open(f, "rb").read()))
diffs, n = [], 0
for opts6, opts7, label in (({}, dict(w7.PROFILE_1_4_2), "defaults vs --profile 1.4.2"),
                            (dict(w6.PROFILE_1_2_1), dict(w7.PROFILE_1_2_1), "--profile 1.2.1 vs --profile 1.2.1"),
                            ({"tokens": "structural", "key_rule": "all-keys"}, dict(w7.PROFILE_1_4_2, key_rule="all-keys"), "all-keys")):
    for name, c in cases:
        n += 1
        a, b = out(w6, c, opts6), out(w7, c, opts7)
        if a != b:
            diffs.append((label, name, {k: (a.get(k), b.get(k)) for k in set(a) | set(b) if a.get(k) != b.get(k)}))
print("compared", n, "runs;", len(diffs), "differ")
for d in diffs:
    print(d[0], "|", d[1], "|", json.dumps(d[2], default=str)[:300])
