"""The operators of tools/mutate.py (comparison flipped, and/or swapped, not removed, raise and .add() removed, if forced to False)
on every site of the lines of war_verify.py that differ from 0.10.0, run against the tests that cover those lines, not against the
vector suites of tools/mutate.py, which hold no case of 1.4.8. The unmutated source, through the same unparser, is run first
(control): it must pass. A mutant that lives prints ALIVE, and the exit is 1, unless its id is in EQUIVALENT, each entry with the
reason read in the code (README, "Tests"). usage: python3 -B tools/mutate148_sites.py PYTHON WAR_VERIFY_0_10_0 [I/N]"""
import ast, os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tools"))
import mutate
PY, OLD = sys.argv[1], sys.argv[2]
src = open(os.path.join(REPO, "war_verify.py")).read()
EQUIVALENT = {}
TESTS = ["tests/test_profile148.py", "tests/test_cli.py"]


def run(text):
    d = tempfile.mkdtemp()
    try:
        for x in ("tests", "tools", "vectors"):
            shutil.copytree(os.path.join(REPO, x), os.path.join(d, x))
        for x in ("fonti", "roots"):
            os.symlink(os.path.join(REPO, x), os.path.join(d, x))
        open(os.path.join(d, "war_verify.py"), "w").write(text)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        for t in TESTS:                                 # stops at the first test file that fails
            if subprocess.run([PY, "-B", t, "-f"], cwd=d, env=env, capture_output=True).returncode != 0:
                return [t]
        return []
    finally:
        shutil.rmtree(d)


diff = subprocess.run(["diff", "--unchanged-line-format=", "--old-line-format=", "--new-line-format=%dn\n", OLD, os.path.join(REPO, "war_verify.py")],
                      capture_output=True, text=True).stdout
lines = {int(x) for x in diff.split()}
sites = [(k, s) for k, s in enumerate(mutate.sites(ast.parse(src))) if s[1] in lines and s[2] != "<module>"]
print("%d new lines, %d sites" % (len(lines), len(sites)), flush=True)
if len(sys.argv) > 3:
    part, parts = map(int, sys.argv[3].split("/"))
    sites = sites[part::parts]
ctl = run(ast.unparse(ast.parse(src)))
print("CONTROL (unmutated copy, unparsed)", "FAILS %s" % ctl if ctl else "passes", flush=True)
if ctl:
    sys.exit(1)
killed = equivalent = alive = 0
for k, s in sites:
    label = "m%04d line %d %s: %s" % (k, s[1], s[2], s[3])
    dead = run(mutate.mutant_source(src, k))
    if dead:
        killed += 1
        print("KILLED ", label, [os.path.basename(t) for t in dead], flush=True)
    elif k in EQUIVALENT:
        equivalent += 1
        print("EQUIV  ", label, "|", EQUIVALENT[k], flush=True)
    else:
        alive += 1
        print("ALIVE  ", label, "|", open(os.path.join(REPO, "war_verify.py")).read().split("\n")[s[1] - 1].strip()[:90], flush=True)
print("sites %d: killed %d, equivalent %d, alive %d" % (len(sites), killed, equivalent, alive))
sys.exit(1 if alive else 0)
