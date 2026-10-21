#!/usr/bin/env python3
"""Score war_verify field by field (code lists as sets) on a published vector set + the live issuer record.
  --set 1.4.1  (default) the 47 vectors of profile 1.4.1 (maximusrufus/work-acceptance-record@06d3b94; 01-46 are the
               files of 4daf721, 47 adds the optional receipt.payment) + live record
  --set 1.4    the 36 vectors of profile 1.4 (maximusrufus/work-acceptance-record@eb0f30b) + live record
  --set 1.3    the 27 vectors of profile 1.3 (maximusrufus/work-acceptance-record@42b4ed0) + live record
  --set 1.2.1  the 23 vectors + 12b + 22-sha1 of the 1.2.1 round + live record (26 documents)
Vector 20 (1.3, 1.4 and 1.4.1, byte-identical) states a contributor's differing expectation in its `difference` member; it is also scored
against that expectation (CONTRIBUTOR_EXPECTATIONS), reported separately, never folded into the total.
usage: python3 -B tools/score.py [--json OUT] [--set 1.4.1|1.4|1.3|1.2.1] [--profile 1.2.1] [war_verify options as key=value ...]"""
import glob, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import war_verify as wv

LIVE = "fonti/issuer_274159c/selftest-pass.json"
# 42b4ed0 vector 20, member `difference`: "Contributor's expectation: problem_codes [] (warning only)."
CONTRIBUTOR_EXPECTATIONS = {"fonti/upstream_42b4ed0/vectors/20-producer-undeclared.json": {"problem_codes": []},
                            "fonti/upstream_eb0f30b/vectors/20-producer-undeclared.json": {"problem_codes": []},
                            "fonti/upstream_4daf721/vectors/20-producer-undeclared.json": {"problem_codes": []},
                            "fonti/upstream_06d3b94/vectors/20-producer-undeclared.json": {"problem_codes": []}}


def vector_files(which="1.4.1"):
    if which == "1.4.1":
        f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_06d3b94/vectors/*.json")))
    elif which == "1.4":
        f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_eb0f30b/vectors/*.json")))
    elif which == "1.3":
        f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_42b4ed0/vectors/*.json")))
    elif which == "1.2.1":
        f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_f7d8984/vectors/*.json")))
        f += sorted(glob.glob(os.path.join(ROOT, "fonti/tetsurohhori_4f6cf49/[0-9]*.json")))
        f += sorted(glob.glob(os.path.join(ROOT, "fonti/babyblueviper1_431525f/*.json")))
        f += sorted(glob.glob(os.path.join(ROOT, "fonti/tetsurohhori_8ff69f4/*.json")))  # posted 2026-10-18 ~07:10Z
    else:
        raise ValueError("unknown vector set %r" % which)
    return f + [os.path.join(ROOT, LIVE)]


def score(options=None, files=None, verify_fn=None, which="1.4.1"):
    rows = []
    for f in files or vector_files(which):
        with open(f, "rb") as fh:
            raw = fh.read()
        if verify_fn is None:
            rep, cmp_ = wv.run_vector_bytes(raw, options)
        else:
            rep, cmp_ = verify_fn(json.loads(raw.decode("utf-8", "surrogatepass")))
        rel = os.path.relpath(f, ROOT)
        row = {"file": rel, "agree": cmp_["agree"],
               "disagreements": [r for r in cmp_["fields"] if not r["agree"]],
               "fields": len(cmp_["fields"]), "fields_agree": sum(r["agree"] for r in cmp_["fields"])}
        if rel in CONTRIBUTOR_EXPECTATIONS and not rep.get("refused"):
            exp = dict(json.loads(raw.decode("utf-8"))["expected"])
            exp.update(CONTRIBUTOR_EXPECTATIONS[rel])
            alt = wv.compare(rep, exp)
            row["contributor_expectation"] = {"agree": alt["agree"],
                                              "disagreements": [r for r in alt["fields"] if not r["agree"]]}
        rows.append(row)
    return rows


if __name__ == "__main__":
    args = sys.argv[1:]
    out, which, opts = None, "1.4.1", {}
    while args and args[0] in ("--json", "--set", "--profile"):
        flag, val = args[0], args[1]
        args = args[2:]
        if flag == "--json":
            out = val
        elif flag == "--set":
            which = val
        elif val == "1.2.1":
            opts.update(wv.PROFILE_1_2_1)
        else:
            raise SystemExit("--profile takes 1.2.1")
    opts.update(dict(a.split("=", 1) for a in args))
    rows = score(opts, which=which)
    for r in rows:
        print("%-75s %s %d/%d" % (r["file"], "AGREE   " if r["agree"] else "DISAGREE", r["fields_agree"], r["fields"]))
        for d in r["disagreements"]:
            print("      %s: expected %s, ours %s" % (d["field"], json.dumps(d["expected"]), json.dumps(d["ours"])))
        if "contributor_expectation" in r:
            c = r["contributor_expectation"]
            print("      contributor's expectation (`difference`): %s%s" % ("AGREE" if c["agree"] else "DISAGREE", "".join(
                "; %s: expected %s, ours %s" % (d["field"], json.dumps(d["expected"]), json.dumps(d["ours"]))
                for d in c["disagreements"])))
    n = len(rows); a = sum(r["agree"] for r in rows)
    fa = sum(r["fields_agree"] for r in rows); ft = sum(r["fields"] for r in rows)
    print("TOTAL set %s: documents %d/%d agree; fields %d/%d; options %s" % (which, a, n, fa, ft, opts or "defaults"))
    if out:
        with open(out, "w") as fh:
            json.dump({"set": which, "options": opts, "rows": rows, "agree": a, "total": n, "fields_agree": fa,
                       "fields": ft}, fh, indent=1, sort_keys=True, default=str)
