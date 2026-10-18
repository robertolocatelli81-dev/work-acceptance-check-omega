#!/usr/bin/env python3
"""Score war_verify on the 23 vectors + the live issuer record, field by field (code lists as sets).
usage: python3 -B tools/score.py [--json OUT] [war_verify options as key=value ...]"""
import glob, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import war_verify as wv

def vector_files():
    f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_f7d8984/vectors/*.json")))
    f += sorted(glob.glob(os.path.join(ROOT, "fonti/tetsurohhori_4f6cf49/[0-9]*.json")))
    f += sorted(glob.glob(os.path.join(ROOT, "fonti/babyblueviper1_431525f/*.json")))
    f += sorted(glob.glob(os.path.join(ROOT, "fonti/tetsurohhori_8ff69f4/*.json")))     # posted 2026-10-18 ~07:10Z
    f += [os.path.join(ROOT, "fonti/issuer_274159c/selftest-pass.json")]
    return f

def score(options=None, files=None, verify_fn=None):
    rows = []
    for f in files or vector_files():
        with open(f, "rb") as fh:
            raw = fh.read()
        if verify_fn is None:
            rep, cmp_ = wv.run_vector_bytes(raw, options)
        else:
            rep, cmp_ = verify_fn(json.loads(raw.decode("utf-8", "surrogatepass")))
        rows.append({"file": os.path.relpath(f, ROOT), "agree": cmp_["agree"],
                     "disagreements": [r for r in cmp_["fields"] if not r["agree"]],
                     "fields": len(cmp_["fields"]), "fields_agree": sum(r["agree"] for r in cmp_["fields"])})
    return rows

if __name__ == "__main__":
    args = sys.argv[1:]
    out = None
    if args[:1] == ["--json"]:
        out = args[1]; args = args[2:]
    opts = dict(a.split("=", 1) for a in args)
    rows = score(opts)
    for r in rows:
        print("%-75s %s %d/%d" % (r["file"], "AGREE   " if r["agree"] else "DISAGREE", r["fields_agree"], r["fields"]))
        for d in r["disagreements"]:
            print("      %s: expected %s, ours %s" % (d["field"], json.dumps(d["expected"]), json.dumps(d["ours"])))
    n = len(rows); a = sum(r["agree"] for r in rows)
    fa = sum(r["fields_agree"] for r in rows); ft = sum(r["fields"] for r in rows)
    print("TOTAL documents %d/%d agree; fields %d/%d; options %s" % (a, n, fa, ft, opts or "defaults"))
    if out:
        with open(out, "w") as fh:
            json.dump({"options": opts, "rows": rows, "agree": a, "total": n, "fields_agree": fa, "fields": ft}, fh, indent=1, sort_keys=True, default=str)
