#!/usr/bin/env python3
"""Score war_verify field by field (code lists as sets) on a published vector set + the live issuer record.
  --set 8ce7f42 (default) the 126 vectors of profile 1.4.11 at maximusrufus/work-acceptance-record@8ce7f42 + live
               record: the files of --set 3e53aac and 119-126 of 8ce7f42 (01-118 unchanged at 8ce7f42: no file of vectors/
               changed or removed in 3e53aac..8ce7f42, compared on 2026-11-10)
  --set 3e53aac the 118 vectors of profile 1.4.8 at maximusrufus/work-acceptance-record@3e53aac + live
               record: the files of --set 6f7a075 and 116-118 of 3e53aac (01-115 byte-identical at 3e53aac, compared
               blob by blob on 2026-11-07)
  --set 6f7a075 the 115 vectors of profile 1.4.7 at maximusrufus/work-acceptance-record@6f7a075 + live
               record: the files of --set c4b4bd4 and 112-115 of 6f7a075 (01-111 byte-identical at 6f7a075, compared
               blob by blob on 2026-11-06)
  --set c4b4bd4 the 111 vectors of profile 1.4.5 at maximusrufus/work-acceptance-record@c4b4bd4 + live
               record: the files of --set 1b81ec9 and 110-111 of c4b4bd4 (01-109 byte-identical at c4b4bd4, compared
               blob by blob on 2026-11-06)
  --set 1b81ec9 the 109 vectors of profile 1.4.4 at maximusrufus/work-acceptance-record@1b81ec9 + live
               record: the files of --set 6bb7d0b and 108-109 of 1b81ec9 (01-107 byte-identical at 1b81ec9, compared
               file by file on 2026-11-05)
  --set 6bb7d0b the 107 vectors of profile 1.4.3 at maximusrufus/work-acceptance-record@6bb7d0b + live
               record: 01-87 are the files of 85a310d, 88-90 those of cb7e8f1 and 91-107 those of 6bb7d0b (01-90
               byte-identical at 6bb7d0b, compared blob by blob on 2026-11-02)
  --set 85a310d the 87 vectors of profile 1.4.2 at maximusrufus/work-acceptance-record@85a310d + live record
  --set bc5a138 the 57 vectors of profile 1.4.1 at maximusrufus/work-acceptance-record@bc5a138 + live record
  --set 48ab8c9 the 59 vectors of PR #1 of that repository (head 48ab8c9: 58-59 added; merged on 2026-10-27) + live record
  --set 1.4.1  the 47 vectors of profile 1.4.1 (maximusrufus/work-acceptance-record@06d3b94; 01-46 are the
               files of 4daf721, 47 adds the optional receipt.payment) + live record
  --set 1.4    the 36 vectors of profile 1.4 (maximusrufus/work-acceptance-record@eb0f30b) + live record
  --set 1.3    the 27 vectors of profile 1.3 (maximusrufus/work-acceptance-record@42b4ed0) + live record
  --set 1.2.1  the 23 vectors + 12b + 22-sha1 of the 1.2.1 round + live record (26 documents)
Vector 20 (1.3, 1.4 and 1.4.1, byte-identical) states a contributor's differing expectation in its `difference` member; it is also scored
against that expectation (CONTRIBUTOR_EXPECTATIONS), reported separately, never folded into the total.
usage: python3 -B tools/score.py [--json OUT] [--set 8ce7f42|3e53aac|6f7a075|c4b4bd4|1b81ec9|6bb7d0b|85a310d|bc5a138|48ab8c9|1.4.1|1.4|1.3|1.2.1] [--profile 1.4.8|1.4.7|1.4.5|1.4.4|1.4.3|1.4.2|1.2.1] [war_verify options as key=value ...]"""
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
                            "fonti/upstream_06d3b94/vectors/20-producer-undeclared.json": {"problem_codes": []},
                            "fonti/upstream_bc5a138/vectors/20-producer-undeclared.json": {"problem_codes": []},
                            "fonti/upstream_48ab8c9/vectors/20-producer-undeclared.json": {"problem_codes": []},
                            "fonti/upstream_85a310d/vectors/20-producer-undeclared.json": {"problem_codes": []}}


def vector_files(which="8ce7f42"):
    if which in ("8ce7f42", "3e53aac", "6f7a075", "c4b4bd4", "1b81ec9", "6bb7d0b"):
        f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_85a310d/vectors/*.json")))
        f += sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_cb7e8f1/vectors/*.json")))
        f += sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_6bb7d0b/vectors/*.json")),
                    key=lambda p: int(os.path.basename(p).split("-")[0]))
        if which in ("8ce7f42", "3e53aac", "6f7a075", "c4b4bd4", "1b81ec9"):
            f += sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_1b81ec9/vectors/*.json")))
        if which in ("8ce7f42", "3e53aac", "6f7a075", "c4b4bd4"):
            f += sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_c4b4bd4/vectors/*.json")))
        if which in ("8ce7f42", "3e53aac", "6f7a075"):
            f += sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_6f7a075/vectors/*.json")))
        if which in ("8ce7f42", "3e53aac"):
            f += sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_3e53aac/vectors/*.json")))
        if which == "8ce7f42":
            f += sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_8ce7f42/vectors/*.json")))
    elif which in ("85a310d", "bc5a138", "48ab8c9"):
        f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_%s/vectors/*.json" % which)))
    elif which == "1.4.1":
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


def score(options=None, files=None, verify_fn=None, which="8ce7f42"):
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
    out, which, opts = None, "8ce7f42", {}
    while args and args[0] in ("--json", "--set", "--profile"):
        flag, val = args[0], args[1]
        args = args[2:]
        if flag == "--json":
            out = val
        elif flag == "--set":
            which = val
        elif val in wv.PROFILES:
            opts.update(wv.PROFILES[val])
        else:
            raise SystemExit("--profile takes 1.4.8, 1.4.7, 1.4.5, 1.4.4, 1.4.3, 1.4.2 or 1.2.1")
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
