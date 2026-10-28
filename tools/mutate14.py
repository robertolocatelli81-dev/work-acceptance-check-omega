"""Targeted mutants of the 0.3.0, 0.4.0, 0.4.1 and 0.5.0 changes (profile 1.4 / 1.4.1 `tsa_signature`; PKIStatusInfo;
bc5a138: a statusString UTF8String that is not UTF-8, issuer defects failed, receipt.tools.numbers_for_canonicalization,
payment form, unsigned envelope timestamp.digest_sha256):
each one must make at least one test fail.
usage: python3 -B tools/mutate14.py PYTHON   (an interpreter with cryptography >= 40)"""
import os, shutil, subprocess, sys, tempfile
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.argv[1]
src = open(os.path.join(REPO, "war_verify.py")).read()
M = [
 ("precedence order", '"failed-first": ("failed", "no_signer", "unsupported", "untrusted")', '"failed-first": ("unsupported", "failed", "no_signer", "untrusted")'),
 ("issuer defect untrusted without the anchor (0.4.1)", 'bad("failed", msg)       # or not', 'bad("failed" if anchored else "untrusted", msg)       # or not'),
 ("issuer defect always untrusted", 'bad("failed", msg)       # or not', 'bad("untrusted", msg)       # or not'),
 ("signer validity not checked", '    if not _cert_time_ok(signer, gen):', '    if False:'),
 ("anchor validity checked", '    for _ in range(8):\n        if cur.public_bytes(Encoding.DER) in root_ders:', '    for _ in range(8):\n        if not _cert_time_ok(cur, gen) and cur is not signer:\n            issuer_defects.append("anchor")\n        if cur.public_bytes(Encoding.DER) in root_ders:'),
 ("P-521 accepted", 'pub.curve.name not in ("secp256r1", "secp384r1")', 'pub.curve.name not in ("secp256r1", "secp384r1", "secp521r1")'),
 ("P-384 refused", 'pub.curve.name not in ("secp256r1", "secp384r1")', 'pub.curve.name not in ("secp256r1",)'),
 ("accepted values ignored", ' or mine.get(t, "not_evaluated") in accepted.get(t, ())', ''),
 ("accepted values of the other token", 'in accepted.get(t, ())', 'in sum(accepted.values(), [])'),
 ("accepted grammar open on values", '\n                or any(not isinstance(x, str) or x not in TSA_VALUES for x in vals):', ':'),
 ("accepted member unknown", '"expected_1_2_1", "tsa_signature_accepted",', '"expected_1_2_1",'),
 ("unknown key algorithm reaches the engine", 'if kalg is not None and kalg not in KEY_ALGORITHMS:', 'if False:'),
 ("key that does not parse -> unsupported", 'bad("failed", "TSA key does not parse: %s" % e)', 'bad("unsupported", "TSA key does not parse: %s" % e)'),
 # removed in 0.5.0, "expired signer classed as issuer defect": equivalent since issuer defects are `failed` too
 # (bc5a138 step 9). Same call bad("failed", same message), no bad() in between; differential 2026-10-24: 113 vector
 # documents and 11 test-PKI tokens with expired signers, full tsa_signature details identical; control (signer validity
 # removed) differs on 6 of the 11. The signer rule stays covered by "signer validity not checked".
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
 ("payment values untyped", '        _str(pm[m], "receipt.payment." + m, nonempty=True)', '        pass'),
 ("payment outside the form refused again", '            check_payment_form(r["payment"])', '            check_payment_form(r["payment"])\n            raise Refusal("x")'),
 ("payment form refusal escapes", '        except Refusal as e:\n            ctx.notes.append("receipt.payment outside', '        except KeyError as e:\n            ctx.notes.append("receipt.payment outside'),
 ("payment members not checked", '    if missing or unknown:\n        raise Refusal("receipt.payment members"', '    if False:\n        raise Refusal("receipt.payment members"'),
 ("payment amount open", '    if not _DEC.match(pm["amount"]):', '    if False:'),
 ("payment amount leading zeros", r'_DEC = re.compile(r"\A(0|[1-9][0-9]*)\Z")', r'_DEC = re.compile(r"\A[0-9]+\Z")'),
 ("payment hex open", '        if m in pm and not re.match(', '        if False and not re.match('),
 ("payment hex one size", '("nonce", 32), ("settlement_tx", 32)):', '("nonce", 20), ("settlement_tx", 32)):'),
 ("payment note loses the detail", '% (e.reason, ": %s" % (e.detail,) if e.detail not in ("", None) else ""))\n\n\ndef check_payment_form', '% (e.reason, ""))\n\n\ndef check_payment_form'),
 ("tools member of 52/57 refused again", 'TOOLS_OPTIONAL = {"numbers_for_canonicalization",', 'TOOLS_OPTIONAL = {'),
 ("tools open to other members (0.5.0 as first committed)", 'ctx.members(t, "receipt.tools", {"profile", "validator"}, TOOLS_OPTIONAL)', 'ctx.members(t, "receipt.tools", {"profile", "validator"}, set(t) if isinstance(t, dict) else TOOLS_OPTIONAL)'),
 ("tools numbers type open", 'if not isinstance(nums, list) or any(isinstance(x, bool) or not isinstance(x, (int, float)) for x in nums):', 'if not isinstance(nums, list):'),
 ("tools numbers accept booleans", 'any(isinstance(x, bool) or not isinstance(x, (int, float)) for x in nums)', 'any(not isinstance(x, (int, float)) for x in nums)'),
 ("tools member not noted", '            ctx.notes.append("receipt.tools.%s not interpreted (profile %s', '            str("receipt.tools.%s not interpreted (profile %s'),
 ("unknown members reported by default", '    "unknown_fields": "refuse",', '    "unknown_fields": "report",'),
 ("digest outside the form refused again", '        except Refusal as e:\n            digest_ok = False', '        except KeyError as e:\n            digest_ok = False'),
 ("digest malformed code missing", 'ctx.notes.append("X_TIMESTAMP_METADATA_MALFORMED: %s', 'ctx.notes.append("x_timestamp_metadata_malformed: %s'),
 ("malformed digest still compared (token)", '(ts_digest_ok and ts["digest_sha256"] != rec_parsed', '(ts["digest_sha256"] != rec_parsed'),
 ("malformed digest still compared (receipt)", 'if ts_declared and ts_digest_ok and ts["digest_sha256"] != receipt_digest.hex():', 'if ts_declared and ts["digest_sha256"] != receipt_digest.hex():'),
 ("envelope other members open (0.5.0 as first committed)", '        ts_declared, meta_gen, ts_digest_ok = check_envelope_timestamp(ctx, ts)', '        try:\n            ts_declared, meta_gen, ts_digest_ok = check_envelope_timestamp(ctx, ts)\n        except Refusal:\n            pass'),
 ("envelope none form not checked", '        ctx.members(ts, "envelope.timestamp", TS_NONE)', '        pass'),
 ("envelope tsa type unchecked", '        _str(ts["tsa"], "envelope.timestamp.tsa")', '        pass'),
 ("envelope granted form not checked", '        ctx.members(ts, "envelope.timestamp", TS_GRANTED)', '        pass'),
 ("payment protocol/scheme open", 'if pm["protocol"] != "x402" or pm["scheme"] != "exact":', 'if False:'),
 ("payment network open", 'if not _EIP155.match(pm["network"]):', 'if not pm["network"].startswith("eip155:"):'),
 ("payment chain id longer than CAIP-2 allows", r'_EIP155 = re.compile(r"\Aeip155:[1-9][0-9]{0,31}\Z")', r'_EIP155 = re.compile(r"\Aeip155:[1-9][0-9]*\Z")'),
 ("anchors not among the issuer candidates (bytes-only match)", '    pool = certs + [r for r in roots]', '    pool = certs'),
 ("empty PKIFreeText accepted", "        if not texts:\n            raise Refusal(\"PKIStatusInfo.statusString is an empty PKIFreeText\")", "        if False:\n            raise Refusal(\"PKIStatusInfo.statusString is an empty PKIFreeText\")"),
 ("PKIFreeText member tag not checked", '            _expect(t, 0x0C, "PKIFreeText UTF8String")', '            pass'),
 ("PKIFreeText UTF-8 not checked", '                t.content.decode("utf-8")', '                pass'),
 ("statusString outside the grammar refused again", '        rest = rest[1:]\n        notes.append("PKIStatusInfo.statusString present (not read)"', '        if bad_utf8:\n            raise Refusal("statusString")\n        rest = rest[1:]\n        notes.append("PKIStatusInfo.statusString present (not read)"'),
 ("failInfo unused-bit count 8 accepted", "c[0] > 7", "c[0] > 8"),
 ("failInfo one octet with unused bits accepted", "(len(c) == 1 and c[0])", "False"),
 ("failInfo nonzero unused bits accepted", "(len(c) > 1 and c[-1] & ((1 << c[0]) - 1))", "False"),
 ("failInfo empty accepted", "if not c or c[0] > 7", "if c and c[0] > 7"),
 ("failInfo trailing zero bits accepted (named bit list)", "if len(c) > 1 and not (c[-1] >> c[0]) & 1:", "if False:"),
]
TESTS = ["tests/test_payment141.py", "tests/test_tsa_signature14.py", "tests/test_nemesis_14.py", "tests/test_nemesis_141b.py",
         "tests/test_vectors.py", "tests/test_cli.py",
         "tests/test_tsa_pkix.py", "tests/test_status_info.py", "tests/test_readings_20261024.py", "tests/test_fuzz.py"]
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
