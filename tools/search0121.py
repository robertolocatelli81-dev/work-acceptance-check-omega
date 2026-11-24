#!/usr/bin/env python3
"""The search of the entry points of version 0.12.1 (README, "Tests"): crashes and fail-opens.

  verify    every 6th document of the default set and the live record (23): an unknown member added to each object
            and 15 values put in each member of `inputs`, under both values of --unknown-fields (61,200 runs); any
            exception other than a refusal, or an unknown member accepted as stated under the default, is reported
  inputs    the issuer's key file as --keys and as the relying party's list, and whole vector files (every 10th, their
            members outside `inputs` and the first two levels of `inputs`) through run_vector_bytes, changed the same
            way (4,348 runs)
  argv      250 random command lines of war_verify.py (seed 7): only the documented exit codes, no traceback

usage: python3 -B tools/search0121.py verify|inputs|argv      exit 0 when nothing is found, 1 otherwise"""
import collections
import copy
import json
import os
import random
import subprocess
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
import score  # noqa: E402
import war_verify as wv  # noqa: E402

LIVE = os.path.join(ROOT, "fonti", "issuer_274159c")


def paths(o, p=()):
    yield p
    if isinstance(o, dict):
        for k, v in o.items():
            yield from paths(v, p + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from paths(v, p + (i,))


def get(o, p):
    for k in p:
        o = o[k]
    return o


def load(f):
    with open(f, encoding="utf-8") as fh:
        return json.load(fh)


def report(n, found, ex):
    print("runs", n)
    for k, c in found.most_common():
        print(c, k, ex.get(k))
    print("found %d" % sum(found.values()))
    return 1 if found else 0


def search_verify():
    vals = [None, True, False, 0, -1, 1.5, "", "x", "AAAA", [], {}, [1], {"a": 1}, 2 ** 52, "1970-01-01T00:00:00Z"]
    files = score.vector_files()
    files = files[::6] + [files[-1]]
    found, ex, n = collections.Counter(), {}, 0
    for f in files:
        doc = load(f)
        inp = doc.get("inputs", doc)
        for p in list(paths(inp)):
            muts = [("unknown", None)] if isinstance(get(inp, p), dict) else []
            muts += [("val", v) for v in vals] if p else []
            for kind, v in muts:
                d = copy.deepcopy(inp)
                if kind == "unknown":
                    get(d, p)["zz_unknown"] = 1
                else:
                    get(d, p[:-1])[p[-1]] = copy.deepcopy(v)
                for opts in ({}, {"unknown_fields": "report"}):
                    n += 1
                    try:
                        rep = wv.verify(d, opts)
                    except wv.Refusal:
                        continue
                    except Exception as e:  # noqa: BLE001 — the finding
                        k = (type(e).__name__, traceback.extract_tb(e.__traceback__)[-1].lineno)
                        found[k] += 1
                        ex.setdefault(k, (os.path.basename(f), p, kind, opts, str(e)[:120]))
                        continue
                    if kind == "unknown" and not opts and rep.get("accepted_as_stated"):
                        k = ("UNKNOWN_ACCEPTED", os.path.basename(f), p)
                        found[k] += 1
    return report(n, found, ex)


def search_inputs():
    vals = [None, True, 0, -1, 1.5, "", "x", [], {}, [1], {"a": 1}, 2 ** 52]
    found, ex = collections.Counter(), {}
    n = [0]

    def run(fn, tag):
        n[0] += 1
        try:
            fn()
        except wv.Refusal:
            pass
        except ValueError as e:
            if "rp_input" in str(e) or "option" in str(e):      # a usage error of the library call, not of the input
                return
            k = (tag, type(e).__name__, traceback.extract_tb(e.__traceback__)[-1].lineno)
            found[k] += 1
            ex.setdefault(k, str(e)[:150])
        except Exception as e:  # noqa: BLE001 — the finding
            k = (tag, type(e).__name__, traceback.extract_tb(e.__traceback__)[-1].lineno)
            found[k] += 1
            ex.setdefault(k, str(e)[:150])

    def variants(base, p):
        for v in vals + (["UNK"] if isinstance(get(base, p), dict) else []):
            d = copy.deepcopy(base)
            if v == "UNK":
                get(d, p)["zz"] = 1
            elif p:
                get(d, p[:-1])[p[-1]] = copy.deepcopy(v)
            else:
                d = copy.deepcopy(v)
            yield d

    kf = load(os.path.join(LIVE, "checker-keys-20261018.json"))
    rec = load(os.path.join(LIVE, "selftest-pass.json"))
    for p in list(paths(kf)):
        for d in variants(kf, p):
            run(lambda: wv.verify(rec["inputs"], {}, d), "keys_override")
            run(lambda: wv.verify(rec["inputs"], {}, kf, d), "rp_override")
    for f in score.vector_files()[::10]:
        doc = load(f)
        for p in list(paths(doc)):
            if p and p[0] == "inputs" and len(p) > 2:
                continue
            for d in variants(doc, p):
                raw = json.dumps(d).encode()
                run(lambda: wv.run_vector_bytes(raw, {}), "run_vector")
    return report(n[0], found, ex)


def search_argv():
    r, py = ROOT, sys.executable
    vals = ["", "x", "-", "--", "pkix", "structural", "1.4.8", "/nonexistent", r + "/fonti", r + "/roots",
            os.path.join(LIVE, "selftest-pass.json"), os.path.join(LIVE, "checker-keys-20261018.json"), os.devnull,
            r + "/war_verify.py", "\udcff" if os.name != "nt" else "x"]
    flags = ["--vector", "--profile", "--keys", "--relying-party-keys", "--tokens", "--tsa-roots", "--unknown-fields",
             "--bogus", "-h", "--rp-form", "--criteria-limits"]
    random.seed(7)
    found, ex = collections.Counter(), {}
    for _ in range(250):
        argv = [random.choice(flags + vals) for _ in range(random.randint(0, 6))]
        try:
            p = subprocess.run([py, "-B", os.path.join(r, "war_verify.py")] + argv, capture_output=True, timeout=60)
        except Exception as e:  # noqa: BLE001 — the finding (a timeout included)
            found[type(e).__name__] += 1
            ex.setdefault(type(e).__name__, argv)
            continue
        if p.returncode not in (0, 1, 2, 3, 64, 74) or b"Traceback" in p.stderr:
            k = (p.returncode, p.stderr.strip().splitlines()[-1][:120] if p.stderr.strip() else b"")
            found[k] += 1
            ex.setdefault(k, argv)
    return report(250, found, ex)


if __name__ == "__main__":
    modes = {"verify": search_verify, "inputs": search_inputs, "argv": search_argv}
    if len(sys.argv) != 2 or sys.argv[1] not in modes:
        print(__doc__)
        sys.exit(64)
    sys.exit(modes[sys.argv[1]]())
