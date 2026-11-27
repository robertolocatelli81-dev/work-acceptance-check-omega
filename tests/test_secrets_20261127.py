"""0.12.2 (2026-11-27): a secret given to war-verify does not come out of it.

war-verify reads public material only (a signed record, public Ed25519 keys, TSA certificates), so a secret enters only
by mistake: a private key, a seed or a password put in a key file, a relying party's list, a document or a TSA root
file. A canary goes into each of those inputs (--keys, --relying-party-keys, inputs.keys, inputs.relying_party_keys,
--tsa-roots, inputs.tsa_roots_base64, the record file itself, the environment) and is searched in everything that comes
out: standard output and error (refusal reasons and details, notes, tracebacks) and every file left in the folder. It is
searched raw and in hex, HEX, decimal, base64 and base64url (at each of the three offsets, so inside a longer text too).
The command line starts no process and opens no connection (an audit hook counts it), and reads no environment variable.

Positive control: the search finds each form, a producer that repeats a name finds the canary, and the audit hook
sees a process and a connection; on 0.12.1 (dee0989)
the tests of the new behaviour fail (CHANGELOG, "0.12.2")."""
import base64
import contextlib
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import _paths  # noqa: F401
import war_verify as wv
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

ROOT = _paths.ROOT
SCRIPT = os.path.join(ROOT, "war_verify.py")
DOC = os.path.join(ROOT, "vectors", "omega-01-required-downgraded-in-results.json")
SEED = hashlib.sha256(b"war-verify test_secrets canary seed").digest()      # a test key, not anyone's
PRIV = Ed25519PrivateKey.from_private_bytes(SEED)
PUB = PRIV.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
KEYNAME = base64.urlsafe_b64encode(SEED).decode().rstrip("=")               # 43 characters: a key where a name goes
PASSWORD = "Pw-" + KEYNAME                                                  # a token where a value goes
ENVTOKEN = "tok-" + hashlib.sha256(b"war-verify env canary").hexdigest()    # in the environment of every run
CANARIES = (SEED, SEED.hex().encode(), KEYNAME.encode(), PASSWORD.encode(), ENVTOKEN.encode())
B64 = base64.b64encode


def forms(secret):
    out = {"raw": secret, "hex": secret.hex().encode(), "HEX": secret.hex().upper().encode(),
           "decimal": str(int.from_bytes(secret, "big")).encode()}
    for k in range(3):          # base64 of the secret inside a longer text: what depends on the secret alone, at each offset
        whole = base64.b64encode(b"\0" * k + secret + b"\0" * ((3 - (k + len(secret)) % 3) % 3))
        part = whole[(k * 8 + 5) // 6:(k + len(secret)) * 8 // 6]
        out["base64+%d" % k], out["base64url+%d" % k] = part, part.replace(b"+", b"-").replace(b"/", b"_")
    return out


def found(secret, *outputs):
    blob = b"\n".join(o if isinstance(o, bytes) else str(o).encode("utf-8", "surrogatepass") for o in outputs)
    blob += b"\n" + blob.replace(b"\\/", b"/")      # JSON may escape the slash of base64
    return sorted(n for n, f in forms(secret).items() if f in blob)


def doc():
    with open(DOC, encoding="utf-8") as f:
        return json.load(f)


GOOD = doc()["inputs"]["keys"]
JWK = {"kty": "OKP", "crv": "Ed25519", "d": base64.urlsafe_b64encode(SEED).decode().rstrip("="),
       "x": base64.urlsafe_b64encode(PUB).decode().rstrip("=")}
PEM = PRIV.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
DER = PRIV.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())


def entry(**kw):
    e = dict(GOOD["keys"][0])
    e.update(kw)
    return e


def with_keys(*extra, **top):
    kf = dict(GOOD, keys=list(GOOD["keys"]) + list(extra))
    kf.update(top)
    return kf


SMALL = B64(b"\x01" + b"\0" * 31).decode()          # the identity point: small order
# Key-file shapes, each holding a canary (name, value, options). A str value is the raw text of the file.
KEYFILES = [
    ("private member at the top", with_keys(private_key=SEED.hex()), []),
    ("JWK d in an entry", dict(GOOD, keys=[entry(d=JWK["d"])] + GOOD["keys"][1:]), []),
    ("key as a member name, top", with_keys(**{KEYNAME: 1}), []),
    ("key as a member name, entry", dict(GOOD, keys=[dict(entry(), **{KEYNAME: 1})]), []),
    ("key as a member name, reported", with_keys(**{KEYNAME: 1}), ["--unknown-fields", "report"]),
    ("key as a member name, entry, reported", dict(GOOD, keys=[dict(entry(), **{KEYNAME: 1})] + GOOD["keys"][1:]),
     ["--unknown-fields", "report"]),
    ("key as a repeated member name", '{"issuer": "x", "%s": 1, "%s": 2, "keys": []}' % (KEYNAME, KEYNAME), []),
    ("password as a status", dict(GOOD, keys=[entry(status=PASSWORD)]), []),
    ("seed and key as the public key", with_keys(entry(key_id="extra", public_key_base64=B64(SEED + PUB).decode())), []),
    ("seed as the public key", with_keys(entry(key_id="extra", public_key_base64=B64(SEED).decode())), []),
    ("key as a key id, non-canonical key", with_keys(entry(key_id=KEYNAME, public_key_base64="AA=")), []),
    ("key as a repeated key id", with_keys(entry(key_id=KEYNAME), entry(key_id=KEYNAME)), []),
    ("key as a repeated key id, 1.2.1", with_keys(entry(key_id=KEYNAME), entry(key_id=KEYNAME)), ["--profile", "1.2.1"]),
    ("key as a repeated key id, no-key", with_keys(entry(key_id=KEYNAME), entry(key_id=KEYNAME)),
     ["--rp-repeated", "no-key"]),
    ("key as a key id, small-order key", with_keys(entry(key_id=KEYNAME, public_key_base64=SMALL)), []),
    ("key as a key id, small-order key, 1.2.1", with_keys(entry(key_id=KEYNAME, public_key_base64=SMALL)),
     ["--profile", "1.2.1"]),
    ("key as a key id, small-order key, rfc8032", with_keys(entry(key_id=KEYNAME, public_key_base64=SMALL)),
     ["--profile", "1.2.1", "--ed25519", "rfc8032"]),
    ("password in issuer, version, purpose, since, also_published",
     with_keys(issuer=PASSWORD, version=PASSWORD, purpose=PASSWORD, also_published=[PASSWORD]), []),
    ("password as since", dict(GOOD, keys=[entry(since=PASSWORD)] + GOOD["keys"][1:]), []),
    ("password as alg", dict(GOOD, keys=[entry(alg=PASSWORD)]), []),
    ("a private JWK as the file", JWK, []),
    ("a JWK set with a private key", {"keys": [JWK]}, []),
    ("a list holding a private JWK", [JWK], ["--rp-form", "bare-list"]),
]
RAW_FILES = [("a PEM private key as the file", PEM), ("a raw seed as the file", SEED),
             ("a DER private key as the file", DER), ("the seed in hex as the file", SEED.hex().encode())]


def self_signed():
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "war test root")])
    t = datetime.datetime(2026, 1, 1)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
         .not_valid_before(t).not_valid_after(t + datetime.timedelta(days=3650)).sign(k, hashes.SHA256()))
    return c.public_bytes(ser.Encoding.PEM)


AUDIT = r"""
import sys
seen = []
def hook(ev, args):
    if ev.split(".")[0] in ("subprocess", "socket", "urllib") or ev in ("os.system", "os.exec", "os.posix_spawn",
            "os.spawn", "os.startfile", "os.fork", "os.forkpty", "os.putenv", "os.unsetenv", "ctypes.dlopen"):
        seen.append(ev)
sys.addaudithook(hook)
sys.path.insert(0, sys.argv[1])
import war_verify
rc = war_verify.main(["war_verify.py"] + sys.argv[2:])
sys.stderr.write("\nAUDIT %r\n" % sorted(set(seen)))
sys.exit(rc)
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="warsec-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.written = set()            # the inputs: they hold the canary by construction

    def file(self, name, data):
        p = os.path.join(self.d, name)
        self.written.add(p)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def json_file(self, name, value):
        return self.file(name, value if isinstance(value, str) else json.dumps(value))

    def left(self):
        out = []
        for base, _, files in os.walk(self.d):
            for n in files:
                p = os.path.join(base, n)
                if p in self.written:
                    continue
                with open(p, "rb") as f:
                    out.append(f.read())
        return out

    def run_cli(self, argv):
        """The command line in a child with an audit hook: stdout, stderr, exit; no process, no connection."""
        aud = os.path.join(self.d, "audit_hook.py")
        if not os.path.exists(aud):
            self.file("audit_hook.py", AUDIT)
        env = dict(os.environ, WAR_TEST_TOKEN=ENVTOKEN, GITHUB_TOKEN=ENVTOKEN, TSA_PASSWORD=ENVTOKEN)
        r = subprocess.run([sys.executable, "-B", aud, ROOT] + list(argv), capture_output=True, timeout=120,
                           cwd=self.d, env=env)
        audit = re.findall(rb"AUDIT (\[[^\]\r\n]*\])", r.stderr)     # Windows writes \r\n
        self.assertEqual(audit[-1:], [b"[]"], (argv, r.stderr[-2000:]))
        self.assertNotIn(b"Traceback", r.stderr, (argv, r.stderr[-2000:]))
        self.assertIn(r.returncode, (0, 1, 2, 3, 74), (argv, r.stderr[-2000:]))
        json.loads(r.stdout.decode("utf-8"))            # every exit writes one JSON report
        files = self.left()
        for c in CANARIES:
            self.assertEqual(found(c, r.stdout, r.stderr, *files), [], (argv, c[:8], r.stdout[-3000:]))
        return r


class TheSearchFinds(Base):
    """Positive control of the search, and of a producer that leaks."""

    def test_every_form(self):
        s = SEED
        for name, text in (("raw", b"x" + s + b"y"), ("hex", b'"' + s.hex().encode()), ("HEX", s.hex().upper().encode()),
                           ("decimal", str(int.from_bytes(s, "big")).encode()), ("base64+0", base64.b64encode(s)),
                           ("base64+1", base64.b64encode(b"{" + s + b"}")), ("base64+2", base64.b64encode(b'{"' + s)),
                           ("base64url+0", base64.urlsafe_b64encode(s)), ("base64url+1", base64.urlsafe_b64encode(b"a" + s)),
                           ("base64url+2", base64.urlsafe_b64encode(b"ab" + s + b"c"))):
            self.assertIn(name, found(s, text), name)
        self.assertEqual(found(s, b"nothing", hashlib.sha256(s).hexdigest()), [])

    def test_a_producer_that_repeats_names_is_found(self):
        kf = self.json_file("k.json", with_keys(**{KEYNAME: 1}))
        out = io.StringIO()
        with mock.patch.object(wv, "_named", lambda s, r=False: repr(s) if r else s), contextlib.redirect_stdout(out):
            wv.main(["war_verify.py", "--unknown-fields", "report", "--keys", kf, DOC])
        self.assertIn("raw", found(KEYNAME.encode(), out.getvalue()))
        with self.assertRaises(AssertionError):     # and the check of run_cli fails on such an output
            for c in CANARIES:
                self.assertEqual(found(c, out.getvalue()), [])

    def test_the_cli_check_fails_on_a_file_left_with_the_canary(self):
        self.run_cli([DOC])
        with open(os.path.join(self.d, "leak.txt"), "wb") as f:      # not an input: as if the verifier had written it
            f.write(base64.b64encode(b"ab" + SEED))
        with self.assertRaises(AssertionError):
            self.run_cli([DOC])
        # and the audit hook sees a process and a connection: a stand-in war_verify that makes both
        fake = os.path.join(self.d, "fake")
        os.makedirs(fake)
        self.file(os.path.join("fake", "war_verify.py"), "import socket, subprocess, sys\n"
                  "def main(argv):\n"
                  "    subprocess.run([sys.executable, '-c', 'pass'])\n"
                  "    try:\n        socket.create_connection(('127.0.0.1', 9), timeout=1)\n"
                  "    except OSError:\n        pass\n"
                  "    print('{}')\n    return 0\n")
        r = subprocess.run([sys.executable, "-B", os.path.join(self.d, "audit_hook.py"), fake], capture_output=True,
                           timeout=120, cwd=self.d)
        seen = re.findall(rb"AUDIT (\[[^\]\r\n]*\])", r.stderr)[-1]
        self.assertIn(b"subprocess.Popen", seen, r.stderr[-500:])
        self.assertIn(b"socket.connect", seen, r.stderr[-500:])


class KeyFiles(Base):
    def test_key_files_by_every_channel(self):
        """--keys, --relying-party-keys, inputs.keys, inputs.relying_party_keys: one run for each shape."""
        for name, kf, opts in KEYFILES:
            text = kf if isinstance(kf, str) else json.dumps(kf)
            with self.subTest(shape=name, channel="--keys"):
                p = self.file("keys.json", text)
                self.run_cli(opts + ["--keys", p, DOC])
            with self.subTest(shape=name, channel="--relying-party-keys"):
                p = self.file("rp.json", text)
                rp = ["--rp-input", "step12"] if "--profile" in opts else []     # 1.2.1 reads no such list
                self.run_cli(opts + rp + ["--relying-party-keys", p, DOC])
            for member in ("keys", "relying_party_keys"):
                with self.subTest(shape=name, channel="inputs." + member):
                    d = doc()
                    d["inputs"][member] = "@@HERE@@"
                    p = self.file("doc.json", json.dumps(d).replace('"@@HERE@@"', text))
                    self.run_cli(opts + [p])
                    self.run_cli(opts + ["--vector", p])

    def test_raw_key_files(self):
        for name, data in RAW_FILES:
            for flag in ("--keys", "--relying-party-keys", None):
                with self.subTest(shape=name, channel=flag or "the record"):
                    p = self.file("raw.bin", data)
                    self.run_cli([flag, p, DOC] if flag else [p])

    def test_invalid_utf8_names_its_position_not_its_byte(self):
        p = self.file("raw.bin", SEED)
        r = self.run_cli(["--keys", p, DOC])
        out = json.loads(r.stdout.decode("utf-8"))
        self.assertEqual((r.returncode, out["reason"]), (2, "JSON text is not valid UTF-8"))
        self.assertNotRegex(out["reason_detail"], r"0x[0-9a-fA-F]{2}")
        self.assertRegex(out["reason_detail"], r"\Abyte at position [0-9]+ is not UTF-8\Z")


class Names(unittest.TestCase):
    """A name or identifier taken from an input is repeated up to 32 characters, a longer one by its length only."""

    def refusal(self, text):
        with self.assertRaises(wv.Refusal) as cm:
            wv.strict_json_loads(text.encode())
        return cm.exception

    def test_the_bound(self):
        for n in (1, 32, 33, 43, 300):
            name = "S" * n
            shown = n <= 32
            e = self.refusal('{"%s": 1, "%s": 2}' % (name, name))
            self.assertEqual(name in e.detail, shown, n)
            if not shown:
                self.assertEqual(e.detail, "<a name of %d characters>" % n)
            ctx = wv.Ctx({"unknown_fields": "report"})
            ctx.members({"a": 1, name: 2}, "keys", {"a"})
            self.assertEqual(name in ctx.notes[0], shown, n)
            ctx = wv.Ctx({"unknown_fields": "refuse"})
            with self.assertRaises(wv.Refusal) as cm:
                ctx.members({"a": 1, name: 2}, "keys", {"a"})
            self.assertEqual(name in cm.exception.detail, shown, n)
            ctx = wv.Ctx(dict(wv.DEFAULT_OPTIONS))           # the criteria document: its member names too
            wv._correspondence(ctx, json.dumps({"criteria": [{"id": "c", "required": True, name: 1}], name: 2}).encode(),
                               [], "strict")
            self.assertEqual([name in x for x in ctx.notes], [shown, shown], (n, ctx.notes))

    def test_a_short_name_keeps_its_text(self):
        self.assertEqual(wv._named("omega-test-1"), "omega-test-1")
        self.assertEqual(wv._named("omega-test-1", True), "'omega-test-1'")
        self.assertEqual(wv._named("x" * 33, True), "<a name of 33 characters>")
        ctx = wv.Ctx(dict(wv.DEFAULT_OPTIONS, rp_repeated="bytes"))     # a short key_id reads as in 0.12.1 (vector 113)
        e = entry(key_id="k1")
        wv.check_rp_keys(ctx, {"keys": [e, e]})
        self.assertIn("key_id 'k1' is listed more than once", ctx.notes[0])
        self.assertNotIn("\"'k1'\"", ctx.notes[0])

    def test_rejected_keys_of_the_same_length_stay_apart(self):
        d = doc()
        a, b = "A" * 40, "B" * 40
        d["inputs"]["keys"] = with_keys(entry(key_id=a, public_key_base64=SMALL), entry(key_id=b, public_key_base64=SMALL))
        rep, _ = wv.run_vector(d)
        self.assertEqual(sorted(rep["details"]["rejected_keys"]),
                         ["<a name of 40 characters>", "<a name of 40 characters> #2"])
        # a short key_id spelled like a shown one is not overwritten: three rejected entries stay three
        d["inputs"]["keys"] = with_keys(entry(key_id=a, public_key_base64=SMALL), entry(key_id=b, public_key_base64=SMALL),
                                        entry(key_id="<a name of 40 characters> #3", public_key_base64=SMALL))
        rep, _ = wv.run_vector(d)
        self.assertEqual(len(rep["details"]["rejected_keys"]), 3, rep["details"]["rejected_keys"])


class TsaRoots(Base):
    def test_a_private_key_in_the_roots_is_refused_and_not_repeated(self):
        cert = self_signed()
        for name, data in (("cert then key", cert + PEM), ("key only", PEM),
                           ("encrypted key", PRIV.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                                                ser.BestAvailableEncryption(PASSWORD.encode())))):
            for as_dir in (False, True):
                with self.subTest(shape=name, dir=as_dir):
                    if as_dir:
                        os.makedirs(os.path.join(self.d, "roots"), exist_ok=True)
                        p = self.file(os.path.join("roots", "r.pem"), data)
                        arg = os.path.dirname(p)
                    else:
                        p = arg = self.file("r.pem", data)
                    r = self.run_cli(["--tsa-roots", arg, DOC])
                    cannot = json.loads(r.stdout.decode("utf-8"))["report"]["cannot_run"]
                    self.assertEqual(r.returncode, 74)
                    self.assertTrue(any("holds a private key" in c for c in cannot), cannot)

    def test_a_root_that_is_not_a_regular_file_is_checked_when_read(self):
        """A pipe is read once, after the check of cryptography: the key is refused there (cryptography 40 or newer)."""
        p = self.file("r.pem", self_signed() + PEM)
        with mock.patch.object(wv.os.path, "isfile", lambda _p: False), mock.patch.object(wv.os.path, "isdir",
                                                                                         lambda _p: True), \
                mock.patch.object(wv.os, "listdir", lambda _p: [os.path.basename(p)]):
            with self.assertRaises(wv.CannotRun) as cm:
                wv.load_roots(self.d)
        if hasattr(x509.Certificate, "verify_directly_issued_by"):
            self.assertEqual(str(cm.exception), "TSA root %s holds a private key (PEM): refused" % p)
        else:                   # cryptography 39: the TSA checks cannot run before any root is read
            self.assertIn("lacks Certificate.verify_directly_issued_by", str(cm.exception))

    def test_other_root_shapes_do_not_repeat_the_key(self):
        for name, data in (("raw seed", SEED), ("DER private key", DER), ("hex seed", SEED.hex().encode())):
            with self.subTest(shape=name):
                p = self.file("r.der", data)
                self.run_cli(["--tsa-roots", p, DOC])
        # a DER private key is refused as the PEM one is (exit 74), in every DER form; a DER certificate is still read
        rsa = __import__("cryptography.hazmat.primitives.asymmetric.rsa", fromlist=["rsa"]).generate_private_key(
            65537, 2048)
        eck = ec.generate_private_key(ec.SECP256R1())
        ders = (("PKCS#8", DER), ("PKCS#8 encrypted", PRIV.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8,
                                                                        ser.BestAvailableEncryption(PASSWORD.encode()))),
                ("PKCS#1 RSA", rsa.private_bytes(ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL,
                                                 ser.NoEncryption())),
                ("SEC1 EC", eck.private_bytes(ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption())))
        cert = self_signed()
        cert_der = x509.load_pem_x509_certificate(cert).public_bytes(ser.Encoding.DER)
        for name, data in ders:
            for as_dir in (False, True):
                with self.subTest(shape=name, dir=as_dir):
                    if as_dir:
                        os.makedirs(os.path.join(self.d, "droots"), exist_ok=True)
                        self.file(os.path.join("droots", "a.der"), cert_der)
                        p = self.file(os.path.join("droots", "b.der"), data)
                        arg = os.path.dirname(p)
                    else:
                        p = arg = self.file("k.der", data)
                    r = self.run_cli(["--tsa-roots", arg, DOC])
                    cannot = json.loads(r.stdout.decode("utf-8"))["report"]["cannot_run"]
                    self.assertEqual(r.returncode, 74)
                    self.assertTrue(any("holds a private key (DER)" in c for c in cannot), cannot)
        self.assertFalse(wv._der_private_key(cert_der))
        if hasattr(x509.Certificate, "verify_directly_issued_by"):     # cryptography 40 or newer: TSA checks can run
            self.assertEqual(len(wv.load_roots(self.file("c.der", cert_der))), 1)
        pgp = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + B64(SEED) + b"\n-----END PGP PRIVATE KEY BLOCK-----\n"
        with self.assertRaises(wv.CannotRun) as cm:
            wv.load_roots(self.file("k.asc", cert + pgp))
        self.assertIn("holds a private key (PEM)", str(cm.exception))
        for item in (B64(DER).decode(), B64(SEED).decode(), PASSWORD):
            with self.subTest(inputs_tsa_roots_base64=item[:6]):
                d = doc()
                d["inputs"]["tsa_roots_base64"] = [item]
                p = self.json_file("doc.json", d)
                self.run_cli([p])


class Environment(unittest.TestCase):
    def test_the_verifier_reads_no_environment_variable(self):
        with open(os.path.join(ROOT, "war_verify.py"), encoding="utf-8") as f:
            src = f.read()
        self.assertEqual(re.findall(r"os\.environ|getenv|putenv|\bsubprocess\b|\bsocket\b|urllib|http\.client", src), [])


if __name__ == "__main__":
    unittest.main()
