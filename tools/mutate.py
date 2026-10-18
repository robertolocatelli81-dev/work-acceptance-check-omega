#!/usr/bin/env python3
"""Automatic mutation battery on war_verify.py (part d).

Operators (ast): every comparison operator flipped (< <=, > >=, == !=, in / not in, is / is not); every `and`/`or`
swapped; every `not` removed; every `raise` replaced by `pass` (check removed); every `X.add(...)` statement
replaced by `pass` (code not raised); every `if` test forced to False (branch removed).

A mutant is KILLED by a suite when any (document, compared field) agreement differs from the original's, or when
it raises / times out. usage:
  nice -n 10 python3 -B tools/mutate.py --suite vectors23 [--suite newvectors] [--suite fuzz] --json OUT [-j 2]"""
import ast
import glob
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
SRC_PATH = os.path.join(ROOT, "war_verify.py")

SWAP = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
        ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}


def _func_of(tree):
    owner = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.ClassDef)):
            for n in ast.walk(fn):
                owner.setdefault(id(n), fn.name)
    return owner


def sites(tree):
    owner = _func_of(tree)
    out = []
    for n in ast.walk(tree):
        fn = owner.get(id(n), "<module>")
        if isinstance(n, ast.Compare):
            for i, op in enumerate(n.ops):
                if type(op) in SWAP:
                    out.append(("cmp", n.lineno, fn, "%s -> %s" % (type(op).__name__, SWAP[type(op)].__name__), (n, i)))
        elif isinstance(n, ast.BoolOp):
            out.append(("boolop", n.lineno, fn, type(n.op).__name__ + " swapped", (n, None)))
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            out.append(("not", n.lineno, fn, "not removed", (n, None)))
        elif isinstance(n, ast.Raise):
            out.append(("raise", n.lineno, fn, "raise -> pass", (n, None)))
        elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute) \
                and n.value.func.attr == "add":
            out.append(("add", n.lineno, fn, "%s.add(...) -> pass" % ast.unparse(n.value.func.value), (n, None)))
        elif isinstance(n, ast.If):
            out.append(("if", n.lineno, fn, "if-test -> False", (n, None)))
    return out


class _Mut(ast.NodeTransformer):
    def __init__(self, target, kind, idx):
        self.t, self.kind, self.idx = target, kind, idx

    def visit(self, node):
        if node is self.t:
            k = self.kind
            if k == "cmp":
                node.ops[self.idx] = SWAP[type(node.ops[self.idx])]()
                return node
            if k == "boolop":
                node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
                return node
            if k == "not":
                return node.operand
            if k in ("raise", "add"):
                return ast.copy_location(ast.Pass(), node)
            if k == "if":
                node.test = ast.copy_location(ast.Constant(False), node.test)
                return node
        return self.generic_visit(node)


def mutant_source(src, k):
    tree = ast.parse(src)
    s = sites(tree)[k]
    kind, _, _, _, (node, idx) = s
    tree2 = _Mut(node, kind, idx).visit(tree)
    ast.fix_missing_locations(tree2)
    return ast.unparse(tree2)


def load_module(source, name="war_verify"):
    m = types.ModuleType(name)
    m.__file__ = SRC_PATH
    exec(compile(source, SRC_PATH, "exec"), m.__dict__)
    return m


# ------------------------------------------------------------------------------------------------ suites
def suite_docs(name):
    if name == "vectors23":
        f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_f7d8984/vectors/*.json")))
        f += sorted(glob.glob(os.path.join(ROOT, "fonti/tetsurohhori_4f6cf49/[0-9]*.json")))
        f += sorted(glob.glob(os.path.join(ROOT, "fonti/babyblueviper1_431525f/*.json")))
    elif name == "vectors13":                       # profile 1.3, maximusrufus/work-acceptance-record@42b4ed0
        f = sorted(glob.glob(os.path.join(ROOT, "fonti/upstream_42b4ed0/vectors/*.json")))
    elif name == "selftest":
        f = [os.path.join(ROOT, "fonti/issuer_274159c/selftest-pass.json")]
    elif name == "newvectors":
        f = sorted(glob.glob(os.path.join(ROOT, "vectors/*.json")))
    else:
        raise ValueError(name)
    return [open(x, "rb").read() for x in f]


OPTION_SETS = [{"reference_time": "earlier"}, {"key_id_source": "receipt"}, {"time_agreement": "exact"},
               {"accuracy": "interval"}, {"name_compare": "normalized"}, {"correspondence": "strict"},
               {"ed25519": "rfc8032"}, {"unknown_fields": "report"}, {"key_id_agreement": "ignore"},
               {"key_rule": "all-keys"}, {"key_id_agreement": "require", "key_id_source": "envelope",
               "reference_time": "covering-token", "accuracy": "ignore", "key_rule": "refuse",
               "independence_rule": "stated-independent"}]


def outcome_options(mod):
    docs = suite_docs("vectors23") + suite_docs("selftest") + suite_docs("newvectors")
    return [outcome_vectors(mod, docs, o) for o in OPTION_SETS]


def outcome_nemesis(mod):
    """NEMESIS round-1 script, in process with the mutant as war_verify (its CLI checks run the file on disk)."""
    import contextlib
    import io
    import runpy
    sys.modules["war_verify"] = mod
    buf = io.StringIO()
    saved = sys.argv
    sys.argv = ["nemesis_r1_check.py", ROOT, os.path.join(ROOT, "fonti")]
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    try:
        with contextlib.redirect_stdout(buf):
            try:
                runpy.run_path(os.path.join(ROOT, "tests", "nemesis_r1_check.py"), run_name="__main__")
            except SystemExit:
                pass
    finally:
        sys.argv = saved
    return sorted(l for l in buf.getvalue().splitlines() if l.startswith("FAIL "))


def outcome_vectors(mod, docs, options=None):
    sig = []
    for raw in docs:
        try:
            rep, cmp_ = mod.run_vector_bytes(raw, options)
            sig.append(tuple((r["field"], r["agree"]) for r in cmp_["fields"]))
        except Exception as e:
            sig.append(("EXC", type(e).__name__))
    return sig


def outcome_fuzz(mod):
    import fuzz
    saved = fuzz.wv
    fuzz.wv = mod
    try:
        import build
        bsaved = build.wv
        build.wv = mod
        try:
            rows = fuzz.run()
        finally:
            build.wv = bsaved
    finally:
        fuzz.wv = saved
    return [r["ours_ok"] for r in rows]


def outcome_unittests(mod, names=("test_jcs_json", "test_der_times", "test_ed25519", "test_tsa_pkix")):
    """In a fresh worker process: the mutant replaces war_verify for every test module (CLI tests excluded: they
    run the file on disk)."""
    import io
    import unittest
    sys.modules["war_verify"] = mod
    for m in ("build", "testpki", "fuzz", "ed25519_edges", "score"):
        sys.modules.pop(m, None)
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    names = list(names)
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    res = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    return sorted(str(t[0]) for t in res.failures + res.errors)


def evaluate(k, suites, baseline):
    src = open(SRC_PATH).read()
    res = {"k": k, "killed_by": [], "error": None}
    try:
        mod = load_module(mutant_source(src, k))
        for s in suites:
            if s == "fuzz":
                got = outcome_fuzz(mod)
            elif s == "unittests":
                got = outcome_unittests(mod)
            elif s == "options":
                got = outcome_options(mod)
            elif s == "localblocks":
                got = outcome_unittests(mod, ("test_local_blocks",))
            elif s == "profile13":
                got = outcome_unittests(mod, ("test_profile13",))
            elif s == "nemesis":
                got = outcome_nemesis(mod)
            else:
                got = outcome_vectors(mod, suite_docs(s))
            if json.loads(json.dumps(got)) != baseline[s]:
                res["killed_by"].append(s)
    except BaseException as e:        # SystemExit included: a mutant may call main() on import
        res["killed_by"].append("exception:%s" % type(e).__name__)
        res["error"] = str(e)[:200]
    return res


def baseline(suites):
    src = open(SRC_PATH).read()
    mod = load_module(ast.unparse(ast.parse(src)))   # the unparsed original must behave like the original
    out = {}
    for s in suites:
        if s == "fuzz":
            out[s] = outcome_fuzz(mod)
        elif s == "unittests":
            out[s] = outcome_unittests(mod)
        elif s == "options":
            out[s] = outcome_options(mod)
        elif s == "localblocks":
            out[s] = outcome_unittests(mod, ("test_local_blocks",))
        elif s == "profile13":
            out[s] = outcome_unittests(mod, ("test_profile13",))
        elif s == "nemesis":
            out[s] = outcome_nemesis(mod)
        else:
            out[s] = outcome_vectors(mod, suite_docs(s))
    return json.loads(json.dumps(out))


def main(argv):
    """--outdir DIR --suite S [--suite S2] [-j N] [--timeout SEC]   (driver)
       --one K --outdir DIR                                           (worker, one mutant, one result file)"""
    import concurrent.futures
    import subprocess
    suites, outdir, jobs, one, timeout, only = [], None, 2, None, 300, None
    a = argv[1:]
    while a:
        x = a.pop(0)
        if x == "--suite":
            suites.append(a.pop(0))
        elif x == "--outdir":
            outdir = a.pop(0)
        elif x == "-j":
            jobs = int(a.pop(0))
        elif x == "--one":
            one = int(a.pop(0))
        elif x == "--timeout":
            timeout = int(a.pop(0))
        elif x == "--only":
            with open(a.pop(0)) as fh:
                only = set(json.load(fh))
    os.makedirs(outdir, exist_ok=True)
    bpath = os.path.join(outdir, "baseline.json")
    if one is not None:
        with open(bpath) as fh:
            b = json.load(fh)
        r = evaluate(one, b["suites"], b["outcomes"])
        with open(os.path.join(outdir, "m%04d.json" % one), "w") as fh:
            json.dump(r, fh)
        return 0
    src = open(SRC_PATH).read()
    allsites = sites(ast.parse(src))
    if not os.path.exists(bpath):
        with open(bpath, "w") as fh:
            json.dump({"suites": suites, "outcomes": baseline(suites),
                       "source_sha256": __import__("hashlib").sha256(src.encode()).hexdigest()}, fh)
    todo = [k for k, s in enumerate(allsites) if s[2] != "<module>" and (only is None or k in only)
            and not os.path.exists(os.path.join(outdir, "m%04d.json" % k))]
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)

    def go(k):
        try:
            subprocess.run(["nice", "-n", "10", sys.executable, "-B", os.path.abspath(__file__), "--one", str(k),
                            "--outdir", outdir], env=env, timeout=timeout, capture_output=True)
        except subprocess.TimeoutExpired:
            with open(os.path.join(outdir, "m%04d.json" % k), "w") as fh:
                json.dump({"k": k, "killed_by": ["timeout"], "error": "timeout %ds" % timeout}, fh)
        return k

    with concurrent.futures.ThreadPoolExecutor(jobs) as ex:
        list(ex.map(go, todo))
    rows, missing = [], []
    for k, (kind, line, fn, desc, _) in enumerate(allsites):
        if fn == "<module>" or (only is not None and k not in only):
            continue
        p = os.path.join(outdir, "m%04d.json" % k)
        if not os.path.exists(p):
            missing.append(k)            # a worker died without writing: counted, never silently dropped
            continue
        with open(p) as fh:
            r = json.load(fh)
        rows.append({"id": "m%04d" % k, "k": k, "kind": kind, "line": line, "function": fn, "mutation": desc,
                     "killed_by": r["killed_by"], "error": r["error"]})
    surv = [r for r in rows if not r["killed_by"]]
    print("mutants %d (module-level guard excluded), results %d, missing %d, killed %d, survivors %d, suites %s"
          % (len(rows) + len(missing), len(rows), len(missing), len(rows) - len(surv), len(surv), suites))
    byfn = {}
    for r in surv:
        byfn[r["function"]] = byfn.get(r["function"], 0) + 1
    for fn, n in sorted(byfn.items(), key=lambda x: -x[1]):
        print("  survivors in %-24s %d" % (fn, n))
    with open(os.path.join(outdir, "SUMMARY.json"), "w") as fh:
        json.dump({"suites": suites, "rows": rows, "missing": missing, "survivors": [r["id"] for r in surv]}, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
