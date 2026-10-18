#!/usr/bin/env python3
"""Summarise the mutation battery by stage and map each new vector to the stage-1 survivors it kills.
usage: python3 -B tools/mutation_report.py STAGE_A_DIR STAGE_B_DIR STAGE_C_DIR OUT.json"""
import ast
import glob
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import mutate  # noqa: E402


def first_suite(killed_by):
    return killed_by[0] if killed_by else None


def main(a_dir, b_dir, c_dir, out):
    A = json.load(open(os.path.join(a_dir, "SUMMARY.json")))
    B = json.load(open(os.path.join(b_dir, "SUMMARY.json"))) if b_dir and os.path.exists(os.path.join(b_dir, "SUMMARY.json")) else {"rows": []}
    base = json.load(open(os.path.join(a_dir, "baseline.json")))
    src = open(mutate.SRC_PATH).read()
    assert hashlib.sha256(src.encode()).hexdigest() == base["source_sha256"], "war_verify.py changed since the battery"
    rows = {r["k"]: r for r in A["rows"]}
    brow = {r["k"]: r for r in B["rows"]}
    C = json.load(open(os.path.join(c_dir, "SUMMARY.json")))
    crow = {r["k"]: r for r in C["rows"]}
    total = len(rows)
    order = ["vectors23", "newvectors", "fuzz"]

    def killed_upto(r, n):
        kb = r["killed_by"]
        if not kb:
            return False
        f = kb[0]
        if f.startswith("exception") or f == "timeout":
            return True      # raised or hung: killed at the first suite that ran
        return any(s in kb for s in order[:n])

    s1 = [k for k, r in rows.items() if not killed_upto(r, 1)]
    s2 = [k for k in s1 if not killed_upto(rows[k], 2)]
    s3 = [k for k in s2 if not killed_upto(rows[k], 3)]
    s4b = [k for k in s3 if not (k in brow and brow[k]["killed_by"])]
    s4 = [k for k in s4b if not (k in crow and crow[k]["killed_by"])]
    # which new vector kills which stage-1 survivor (the survivor = an old, lax mutant that passes the 23 vectors)
    docs = sorted(glob.glob(os.path.join(ROOT, "vectors", "*.json")))
    raw = [open(d, "rb").read() for d in docs]
    import war_verify as wv
    good = [wv.run_vector_bytes(x)[1]["agree"] for x in raw]
    kills = {os.path.basename(d): [] for d in docs}
    for k in s1:
        if k in s2:
            continue
        try:
            mod = mutate.load_module(mutate.mutant_source(src, k))
        except BaseException:
            continue
        for d, x, g in zip(docs, raw, good):
            try:
                ok = mod.run_vector_bytes(x)[1]["agree"]
            except BaseException:
                ok = False
            if g and not ok:
                kills[os.path.basename(d)].append(rows[k]["id"])
    sites = mutate.sites(ast.parse(src))
    surv = [{"id": rows[k]["id"], "line": sites[k][1], "function": sites[k][2], "mutation": sites[k][3]} for k in s4]
    res = {"source_sha256": base["source_sha256"], "mutants": total,
           "survivors_after": {"vectors23": len(s1), "+newvectors": len(s2), "+fuzz": len(s3), "+unittests+options+nemesis": len(s4b),
                               "+local_blocks tests": len(s4)},
           "killed_by_timeout": sum(1 for r in rows.values() if r["killed_by"] == ["timeout"]),
           "killed_by_exception_first": sum(1 for r in rows.values() if r["killed_by"] and r["killed_by"][0].startswith("exception")),
           "new_vector_kills_stage1_survivors": kills, "final_survivors": surv,
           "our_verifier_agrees_on_new_vectors": sum(good), "new_vectors": len(good)}
    with open(out, "w") as fh:
        json.dump(res, fh, indent=1, sort_keys=True)
    print(json.dumps(res["survivors_after"]), "of", total, "| timeouts", res["killed_by_timeout"],
          "| exceptions", res["killed_by_exception_first"])
    print("new vectors killing >= 1 stage-1 survivor: %d/%d" % (sum(1 for v in kills.values() if v), len(kills)))
    by = {}
    for s in surv:
        by[s["function"]] = by.get(s["function"], 0) + 1
    for f, n in sorted(by.items(), key=lambda x: -x[1]):
        print("  final survivors in %-24s %d" % (f, n))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
