#!/usr/bin/env python3
"""How much each reading of profile 1.4.5 changed under 0.9.0 (from 0.10.0: --profile 1.4.5 and --set c4b4bd4; README, Q24-Q29; tools/readings147.py counts the defaults), on the records of tests/test_profile145.py: LISTS as
an object, and as a bare list for Q24, with a key list of two clean entries: the longer one of the test table is KEY_REJECTED
already (79), which would hide Q27. An outcome is the members of `COMPARED`, refused or not, and the reason. The
counts follow from the table chosen: they say that a switch changes outcomes, not how often it would in use.
usage: python3 -B tools/readings145.py"""
import copy, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "tools")); sys.path.insert(0, os.path.join(ROOT, "tests"))
import score
import test_profile145 as u
import war_verify as wv


def outcome(i, opts):
    rep = u.run(i, opts)
    return {k: rep.get(k) for k in u.OUTCOME}, rep


records, bare = [], []
for stated, pn, pl, pk, kind, label, entries, holds in u.table():
    records.append(u.doc(stated, pn, pk, u.rpdoc(entries)))
    bare.append(u.doc(stated, pn, pk, copy.deepcopy(entries)))
print("table: %d records as an object, %d as a bare list" % (len(records), len(bare)))
default = [outcome(i, None)[0] for i in records]
default_bare = [outcome(i, None)[0] for i in bare]
print("defaults: %d of %d refused as an object, %d of %d as a bare list" % (
    sum(bool(o["refused"]) for o in default), len(default), sum(bool(o["refused"]) for o in default_bare), len(bare)))
for key, value, table, base in (("rp_form", "bare-list", bare, default_bare), ("rp_empty", "absent", records, default),
                                ("rp_empty", "refuse", records, default), ("rp_repeated", "bytes", records, default),
                                ("rp_entry_defect", "key-rejected", records, default), ("rp_lookup", "both", records, default)):
    other = [outcome(i, {key: value})[0] for i in table]
    rows = score.score(dict(wv.PROFILE_1_4_5, **{key: value}), which="c4b4bd4")
    print("--%s %s: %d of %d records differ; c4b4bd4 set %d/%d" % (
        key.replace("_", "-"), value, sum(a != b for a, b in zip(base, other)), len(table), sum(r["agree"] for r in rows), len(rows)))
# Q29: an undeclared producer whose key the list does not hold, under the claim
n = same = 0
for i in records:
    rep = outcome(i, None)[1]
    if rep["details"]["independence_derived"] == "undeclared" and "X_RP_PRODUCER_KEY_NOT_HELD" in rep["extension_codes"]:
        n += 1
        same += "INDEPENDENCE_INCONSISTENT" in rep["problem_codes"] and "PRODUCER_UNDECLARED" in rep["warning_codes"]
print("Q29: %d records with an undeclared producer and a key not held; %d have INDEPENDENCE_INCONSISTENT and PRODUCER_UNDECLARED" % (n, same))
