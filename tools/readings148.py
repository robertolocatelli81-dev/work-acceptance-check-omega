#!/usr/bin/env python3
"""How much each reading of profile 1.4.8 changes (README, Q32-Q35, W1), under the 0.11.0 defaults: on the criteria documents of
tests/test_profile148.py, with the hash matching and not matching, and on the signatures of its table of R. An outcome is the
members of `OUTCOME` of tests/test_profile145.py. The counts follow from the tables chosen: they say that a switch changes
outcomes, not how often it would in use.
usage: python3 -B tools/readings148.py"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "tools")); sys.path.insert(0, os.path.join(ROOT, "tests"))
import score
import test_profile145 as u
import test_profile147 as v
import test_profile148 as w


def outcome(i, opts):
    rep = v.run(i, opts)
    return {k: rep.get(k) for k in u.OUTCOME}


rows = w.table()
matched = [w.record(data) for _l, data, _w, _f in rows]
other = [w.record(data, False) for _l, data, _w, _f in rows]
s = w.SignatureR()
w.SignatureR.setUpClass()
sigs = [s.signed(s.forged(rb, r)) for _l, rb, r, _c, _y in s.classes()]
print("tables: %d criteria documents, by family %s; %d signatures" % (len(rows), sorted({f: sum(x[3] == f for x in rows) for f in {x[3] for x in rows}}.items()), len(sigs)))
base_m, base_o, base_s = [outcome(i, None) for i in matched], [outcome(i, None) for i in other], [outcome(i, None) for i in sigs]
print("defaults: %d of %d documents CRITERIA_UNREADABLE, %d CRITERIA_RESULTS_MISMATCH" % (
    sum(w.UNREADABLE in o["problem_codes"] for o in base_m), len(rows), sum(w.RESULTS in o["problem_codes"] for o in base_m)))
for key, value, table, base in (("criteria_unreadable", "mismatch", matched, base_m), ("criteria_read", "always", other, base_o), ("criteria_shape", "absent", matched, base_m),
                                ("criteria_types", "known", matched, base_m), ("criteria_limits", "readable", matched, base_m),
                                ("sig_r", "not-small", sigs, base_s), ("ed25519", "rfc8032", sigs, base_s)):
    got = [outcome(i, {key: value}) for i in table]
    res = score.score({key: value})
    print("--%s %s: %d of %d records differ; 3e53aac set %d/%d %s" % (key.replace("_", "-"), value, sum(a != b for a, b in zip(base, got)), len(table),
                                                                     sum(r["agree"] for r in res), len(res), v.nums(res)))
why = [v.run(i, None)["details"]["signature_reason"] != v.run(i, {"sig_r": "not-small"})["details"]["signature_reason"] for i in sigs]
print("--sig-r not-small: details.signature_reason differs on %d of %d signatures" % (sum(why), len(sigs)))
