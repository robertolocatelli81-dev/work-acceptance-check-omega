#!/usr/bin/env python3
"""How much each reading of profile 1.4.11 changes (README, X1, X4, X5, Q36), under the 0.12.0 defaults: on the criteria documents of
tests/test_profile1411.py (each noncharacter escaped in a value and as bytes in a name, their neighbours, the generative grids of numbers
and depth) and of tests/test_profile148.py, and on the 120 records of the product of step 12 in tests/test_profile1411.py. An outcome is the
members of `OUTCOME` of tests/test_profile145.py. The counts follow from the tables chosen: they say that a switch changes outcomes, not
how often it would in use.
usage: python3 -B tools/readings1411.py"""
import itertools, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "tools")); sys.path.insert(0, os.path.join(ROOT, "tests"))
import score
import test_profile145 as u
import test_profile147 as v
import test_profile148 as w
import test_profile1411 as y


def outcome(i, opts):
    rep = v.run(i, opts)
    return {k: rep.get(k) for k in u.OUTCOME}


docs = [y.extra(b'"x":"a' + y.escaped(c) + b'"') for c in y.NONCHARACTERS]
docs += [y.extra(b'"' + chr(c).encode("utf-8") + b'":1', "item") for c in y.NONCHARACTERS]
docs += [y.extra(b'"x":"' + y.escaped(c) + b'"') for c in sorted({c + d for c in y.NONCHARACTERS for d in (-2, -1, 1, 2)} - set(y.NONCHARACTERS))
         if c <= 0x10FFFF]
for value in y.INT_VALUES:
    for _f, txt, _i in y.number_forms(value):
        docs += [put(txt.encode()) for _p, put in y.PLACES]
for txt in (b"1e309", b"-1e309", b"1E400", b"1e+400", b"1e-400", b"4.9e-324", b"2.4e-324"):
    docs += [put(txt) for _p, put in y.PLACES]
g = y.GenerativeDepth()
docs += [g.depth_doc(level, val, wrap, where) for level in (63, 64, 65, 200) for _l, val in y.VALUES for wrap in ("arrays", "members")
         for where in ("root", "criterion")]
docs += [data for _l, data, _w, _f in w.table()]
recs = [y.record(d) for d in docs]
print("tables: %d criteria documents (%d of tests/test_profile1411.py, %d of tests/test_profile148.py); %d records of step 12" % (
    len(recs), len(recs) - len(w.table()), len(w.table()), 120))
base = [outcome(i, None) for i in recs]
print("defaults: %d of %d documents CRITERIA_UNREADABLE" % (sum(w.UNREADABLE in o["problem_codes"] for o in base), len(recs)))
for key, value in (("criteria_noncharacters", "unreadable"), ("criteria_noncharacters", "readable"), ("criteria_limits", "readable")):
    got = [outcome(i, {key: value}) for i in recs]
    res = score.score({key: value}, which="8ce7f42")
    print("--%s %s: %d of %d documents differ; 8ce7f42 set %d/%d %s" % (key.replace("_", "-"), value, sum(a != b for a, b in zip(base, got)),
                                                                     len(recs), sum(r["agree"] for r in res), len(res), v.nums(res)))
q = [y.q31_record(rp, claim, pname, key, kid) for (_rl, rp), claim, (pname, _p), key, kid in
     itertools.product(y.RP_LISTS, y.CLAIMS, y.PRODUCERS, y.PRODUCER_KEYS, y.KEY_IDS)]
qb = [outcome(i, None) for i in q]
for value in ("always", "off"):
    got = [outcome(i, {"rp_point": value}) for i in q]
    res = score.score({"rp_point": value}, which="8ce7f42")
    print("--rp-point %s: %d of %d records differ; 8ce7f42 set %d/%d %s" % (value, sum(a != b for a, b in zip(qb, got)), len(q),
                                                                        sum(r["agree"] for r in res), len(res), v.nums(res)))
