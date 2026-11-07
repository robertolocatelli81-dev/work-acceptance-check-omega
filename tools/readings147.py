#!/usr/bin/env python3
"""How much each reading open or closed by profile 1.4.7 changes (README, Q24-Q28, Q31), under the 0.10.0 defaults: on the 2,240
records of tests/test_profile145.py (a key list of two clean entries; Q24 as a bare list) and, for the point rule, on the
records of tests/test_profile147.py. An outcome is the members of `OUTCOME`, refused or not, and the reason. The counts follow
from the table chosen: they say that a switch changes outcomes, not how often it would in use.
usage: python3 -B tools/readings147.py"""
import copy, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "tools")); sys.path.insert(0, os.path.join(ROOT, "tests"))
import score
import test_profile145 as u
import test_profile147 as v


def outcome(i, opts):
    rep = v.run(i, opts)
    return {k: rep.get(k) for k in u.OUTCOME}


records, bare = [], []
for stated, pn, pl, pk, kind, label, entries, holds in u.table():
    records.append(u.doc(stated, pn, pk, u.rpdoc(entries)))
    bare.append(u.doc(stated, pn, pk, copy.deepcopy(entries)))
point = [v.record(stated, pname, pub, entries) for _l, pub, _o, _f, stated, pname, _k, _n, entries, _s, _h in v.PointRule().table()]
print("tables: %d records as an object, %d as a bare list, %d with the keys of the point rule" % (len(records), len(bare), len(point)))
default = [outcome(i, None) for i in records]
default_bare = [outcome(i, None) for i in bare]
default_point = [outcome(i, None) for i in point]
print("defaults: %d of %d refused as an object, %d of %d as a bare list" % (
    sum(bool(o["refused"]) for o in default), len(default), sum(bool(o["refused"]) for o in default_bare), len(bare)))
for key, value, table, base in (("rp_form", "bare-list", bare, default_bare), ("rp_empty", "absent", records, default),
                                ("rp_empty", "refuse", records, default), ("rp_repeated", "no-key", records, default),
                                ("rp_entry_defect", "key-rejected", records, default), ("rp_lookup", "both", records, default),
                                ("rp_point", "off", point, default_point), ("rp_point", "always", point, default_point)):
    other = [outcome(i, {key: value}) for i in table]
    rows = score.score({key: value}, which="6f7a075")
    bad = [os.path.basename(r["file"]).split("-")[0] for r in rows if not r["agree"]]
    print("--%s %s: %d of %d records differ; 6f7a075 set %d/%d %s" % (
        key.replace("_", "-"), value, sum(a != b for a, b in zip(base, other)), len(table), sum(r["agree"] for r in rows),
        len(rows), bad))
split = {}
for i, a, (_l, _p, _o, _f, stated, _n, _k, _ln, _e, supplied, _h) in zip(point, default_point, v.PointRule().table()):
    b = outcome(i, {"rp_point": "always"})
    if a != b:
        key = ("a list" if supplied else "no list", stated, "adds" if "INDEPENDENCE_INCONSISTENT" in b["problem_codes"] else "removes")
        split[key] = split.get(key, 0) + 1
for key in sorted(split):
    print("--rp-point always, %s, claim %s: %s INDEPENDENCE_INCONSISTENT on %d records" % (key + (split[key],)))
n = same = 0
for i in records + point:
    rep = v.run(i)
    if rep["details"]["independence_derived"] == "undeclared" and {"X_RP_PRODUCER_KEY_NOT_HELD", "X_RP_PRODUCER_KEY_POINT_RULE"} & set(rep["extension_codes"]):
        n += 1
        same += "INDEPENDENCE_INCONSISTENT" in rep["problem_codes"] and "PRODUCER_UNDECLARED" in rep["warning_codes"]
print("Q29: %d records with an undeclared producer and a key not held or failing the point rule; %d have INDEPENDENCE_INCONSISTENT and PRODUCER_UNDECLARED" % (n, same))
