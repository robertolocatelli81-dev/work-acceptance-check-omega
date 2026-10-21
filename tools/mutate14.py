"""Targeted mutants of the 0.3.0 changes (profile 1.4 `tsa_signature`): each one must make at least one test fail.
usage: python3 -B tools/mutate14.py PYTHON   (an interpreter with cryptography >= 40)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
M = [
 ("precedence order", '"failed-first": ("failed", "no_signer", "unsupported", "untrusted")', '"failed-first": ("unsupported", "failed", "no_signer", "untrusted")'),
 ("CA invalid -> failed", 'bad("failed" if cur is signer else "untrusted",', 'bad("failed",'),
 ("signer invalid -> untrusted", 'bad("failed" if cur is signer else "untrusted",', 'bad("untrusted",'),
 ("no path -> failed", 'bad("untrusted", "no path from', 'bad("failed", "no path from'),
 ("not CA -> failed", 'bad("untrusted", "issuer %s is not a CA"', 'bad("failed", "issuer %s is not a CA"'),
 ("signer not found -> failed", 'bad("no_signer", "signer certificate not found', 'bad("failed", "signer certificate not found'),
 ("no SignerInfo -> failed", 'bad("no_signer", "no SignerInfo")', 'bad("failed", "no SignerInfo")'),
 ("unsupported -> failed", 'bad("unsupported" if why.endswith(UNSUPPORTED_SUFFIX) else "failed", why)', 'bad("failed", why)'),
 ("empty anchors are anchors", 'anchors = load_roots_b64(inputs["tsa_roots_base64"]) or None', 'anchors = load_roots_b64(inputs["tsa_roots_base64"])'),
 ("token root is an anchor", '    pool = certs + [r for r in roots]\n', '    pool = certs + [r for r in roots]\n    root_ders |= {c.public_bytes(Encoding.DER) for c in certs if c.subject == c.issuer}\n'),
 ("absent not read as not_evaluated", 'all(mine.get(t, "not_evaluated") == theirs[t] for t in theirs)', 'all(mine.get(t) == theirs[t] for t in theirs)'),
 ("extra key ignored", 'and all(mine[t] == "not_evaluated" for t in set(mine) - set(theirs))', ''),
 ("bad anchor skipped", 'raise Refusal("inputs.tsa_roots_base64[%d] is not a DER X.509 certificate" % i)', 'continue'),
 ("never evaluated", 'tsa_sig[key] = tsa_outcome(v, opts["tsa_precedence"])', 'tsa_sig[key] = "not_evaluated"'),
 ("inputs anchors win over CLI", '    if opts["tsa_roots"]:\n        anchors = roots', '    if opts["tsa_roots"] and "tsa_roots_base64" not in inputs:\n        anchors = roots'),
 ("unknown value accepted", 'and all(theirs[t] in TSA_VALUES for t in theirs)', ''),
 ("tsa changes other members", '        tsa_sig[key] = tsa_outcome(v, opts["tsa_precedence"])\n', '        tsa_sig[key] = tsa_outcome(v, opts["tsa_precedence"])\n        if tsa_sig[key] != "verified":\n            warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")\n'),
 ("key labels swapped", '(("criteria", "criteria_token", crit_parsed), ("receipt", "record_token", rec_parsed))', '(("receipt", "criteria_token", crit_parsed), ("criteria", "record_token", rec_parsed))'),
 ("ESS not checked", 'res["reasons"].append(msg)\n        res["classes"].append(cls)', 'res["reasons"].append(msg)\n        res["classes"].append(cls)\n        if "ESSCertID" in msg:\n            res["reasons"].pop(); res["classes"].pop()'),
 ("EKU not checked", 'if ekus != [OID_KP_TIMESTAMPING]:', 'if False:'),
 ("chain API guard removed", 'if not hasattr(x509.Certificate, "verify_directly_issued_by"):', 'if False:'),
]
TESTS = ["tests/test_tsa_signature14.py", "tests/test_nemesis_14.py", "tests/test_vectors.py", "tests/test_cli.py",
         "tests/test_tsa_pkix.py"]
killed = 0
not_applicable = 0
for name, o, n in M:
    if src.count(o) != 1:
        print("NOT APPLICABLE", name, src.count(o)); not_applicable += 1; continue
    d = tempfile.mkdtemp()
    try:
        for x in ("tests", "tools", "vectors"):
            shutil.copytree(os.path.join(REPO, x), os.path.join(d, x))
        for x in ("fonti", "roots"):
            os.symlink(os.path.join(REPO, x), os.path.join(d, x))
        open(os.path.join(d, "war_verify.py"), "w").write(src.replace(o, n))
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        dead = [t for t in TESTS if subprocess.run([PY, "-B", t], cwd=d, env=env, capture_output=True).returncode != 0]
        print("KILLED " if dead else "ALIVE  ", name, [os.path.basename(t) for t in dead])
        killed += bool(dead)
    finally:
        shutil.rmtree(d)
print("killed %d/%d" % (killed, len(M)))
sys.exit(0 if killed == len(M) and not not_applicable else 1)   # a mutant not applied is a bench defect, not a kill
