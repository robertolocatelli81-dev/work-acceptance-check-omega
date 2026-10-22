"""Targeted mutants of the 0.3.0, 0.4.0 and 0.4.1 changes (profile 1.4 / 1.4.1 `tsa_signature`; PKIStatusInfo grammar): each one must make at
least one test fail.
usage: python3 -B tools/mutate14.py PYTHON   (an interpreter with cryptography >= 40)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
M = [
 ("precedence order", '"failed-first": ("failed", "no_signer", "unsupported", "untrusted")', '"failed-first": ("unsupported", "failed", "no_signer", "untrusted")'),
 ("issuer defect always failed", 'bad("failed" if anchored else "untrusted", msg)', 'bad("failed", msg)'),
 ("issuer defect always untrusted", 'bad("failed" if anchored else "untrusted", msg)', 'bad("untrusted", msg)'),
 ("signer validity not checked", '    if not _cert_time_ok(signer, gen):', '    if False:'),
 ("anchor validity checked", '    for _ in range(8):\n        if cur.public_bytes(Encoding.DER) in root_ders:', '    for _ in range(8):\n        if not _cert_time_ok(cur, gen) and cur is not signer:\n            issuer_defects.append("anchor")\n        if cur.public_bytes(Encoding.DER) in root_ders:'),
 ("P-521 accepted", 'pub.curve.name not in ("secp256r1", "secp384r1")', 'pub.curve.name not in ("secp256r1", "secp384r1", "secp521r1")'),
 ("P-384 refused", 'pub.curve.name not in ("secp256r1", "secp384r1")', 'pub.curve.name not in ("secp256r1",)'),
 ("accepted values ignored", ' or mine.get(t, "not_evaluated") in accepted.get(t, ())', ''),
 ("accepted values of the other token", 'in accepted.get(t, ())', 'in sum(accepted.values(), [])'),
 ("accepted grammar open on values", '\n                or any(not isinstance(x, str) or x not in TSA_VALUES for x in vals):', ':'),
 ("accepted member unknown", '"expected_1_2_1", "tsa_signature_accepted"}', '"expected_1_2_1"}'),
 ("unknown key algorithm reaches the engine", 'if kalg is not None and kalg not in KEY_ALGORITHMS:', 'if False:'),
 ("key that does not parse -> unsupported", 'bad("failed", "TSA key does not parse: %s" % e)', 'bad("unsupported", "TSA key does not parse: %s" % e)'),
 ("expired signer classed as issuer defect", '        bad("failed", "certificate %s not valid at genTime" % signer.subject.rfc4514_string())\n    for _ in range(8):', '        issuer_defects.append("certificate %s not valid at genTime" % signer.subject.rfc4514_string())\n    for _ in range(8):'),
 ("no path -> failed", 'bad("untrusted", "no path from', 'bad("failed", "no path from'),
 ("not CA not checked", 'if not bc.ca:', 'if False:'),
 ("signer not found -> failed", 'bad("no_signer", "signer certificate not found', 'bad("failed", "signer certificate not found'),
 ("no SignerInfo -> failed", 'bad("no_signer", "no SignerInfo")', 'bad("failed", "no SignerInfo")'),
 ("unsupported -> failed", 'bad("unsupported" if why.endswith(UNSUPPORTED_SUFFIX) else "failed", why)', 'bad("failed", why)'),
 ("empty anchors are anchors", 'anchors = load_roots_b64(inputs["tsa_roots_base64"]) or None', 'anchors = load_roots_b64(inputs["tsa_roots_base64"])'),
 ("token root is an anchor", '    pool = certs + [r for r in roots]\n', '    pool = certs + [r for r in roots]\n    root_ders |= {c.public_bytes(Encoding.DER) for c in certs if c.subject == c.issuer}\n'),
 ("absent not read as not_evaluated", 'all(mine.get(t, "not_evaluated") == theirs[t] or', 'all(mine.get(t) == theirs[t] or'),
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
 ("payment not allowed", 'RECEIPT_OPTIONAL = {"payment"}', 'RECEIPT_OPTIONAL = set()'),
 ("payment values untyped", '            _str(pm[m], "receipt.payment." + m, nonempty=True)', '            pass'),
 ("payment protocol/scheme open", 'if pm["protocol"] != "x402" or pm["scheme"] != "exact":', 'if False:'),
 ("payment network open", 'if not _EIP155.match(pm["network"]):', 'if not pm["network"].startswith("eip155:"):'),
 ("payment chain id longer than CAIP-2 allows", r'_EIP155 = re.compile(r"\Aeip155:[1-9][0-9]{0,31}\Z")', r'_EIP155 = re.compile(r"\Aeip155:[1-9][0-9]*\Z")'),
 ("anchors not among the issuer candidates (bytes-only match)", '    pool = certs + [r for r in roots]', '    pool = certs'),
 ("empty PKIFreeText accepted", "        if not texts:\n            raise Refusal(\"PKIStatusInfo.statusString is an empty PKIFreeText\")", "        if False:\n            raise Refusal(\"PKIStatusInfo.statusString is an empty PKIFreeText\")"),
 ("PKIFreeText member tag not checked", '            _expect(t, 0x0C, "PKIFreeText UTF8String")', '            pass'),
 ("PKIFreeText UTF-8 not checked", '                t.content.decode("utf-8")', '                pass'),
 ("failInfo unused-bit count 8 accepted", "c[0] > 7", "c[0] > 8"),
 ("failInfo one octet with unused bits accepted", "(len(c) == 1 and c[0])", "False"),
 ("failInfo nonzero unused bits accepted", "(len(c) > 1 and c[-1] & ((1 << c[0]) - 1))", "False"),
 ("failInfo empty accepted", "if not c or c[0] > 7", "if c and c[0] > 7"),
 ("failInfo trailing zero bits accepted (named bit list)", "if len(c) > 1 and not (c[-1] >> c[0]) & 1:", "if False:"),
]
TESTS = ["tests/test_payment141.py", "tests/test_tsa_signature14.py", "tests/test_nemesis_14.py", "tests/test_nemesis_141b.py",
         "tests/test_vectors.py", "tests/test_cli.py",
         "tests/test_tsa_pkix.py", "tests/test_status_info.py"]
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
