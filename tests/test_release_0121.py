"""Version 0.12.1: the defects of 0.12.0 found on 2026-11-24, each test failing on 0.12.0 (positive control, README "Tests").
- tools/fetch_sources.py pinned the live key file of api.babyblueviper.com, which changed: a fresh clone stopped at 449/450.
- tools/score.py ignored an unknown option (criteria-noncharacters=report gave 129/129, exit 0).
- war_verify.verify() ignored an unknown option key; compare() raised TypeError on an expected code list holding a list; strict_json_loads left the nesting bound to RecursionError, whose
  depth differs between Python versions; every file was read to its end, whatever its size."""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

import _paths
import fetch_sources
import score
import war_verify as wv

ROOT = _paths.ROOT
LIVE = os.path.join(ROOT, "fonti", "issuer_274159c")


def rows():
    with open(os.path.join(ROOT, "SOURCES.json"), encoding="utf-8") as fh:
        return json.load(fh)


def cli(script, *args):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    p = subprocess.run([sys.executable, "-B", script] + list(args), capture_output=True, text=True, env=env,
                       encoding="utf-8", cwd=ROOT)
    return p.returncode, p.stdout, p.stderr


class Sources(unittest.TestCase):
    def test_no_row_is_fetched_from_a_live_url(self):
        dated = re.compile(r"\Ahttps://(raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/|web\.archive\.org/web/"
                           r"[0-9]{14}id_/)")
        live = [r["path"] for r in rows() if "url" in r and not dated.match(r["url"])]
        self.assertEqual(live, [])

    def test_every_row_is_of_a_closed_form(self):
        self.assertEqual([(r["path"], fetch_sources.row_error(r)) for r in rows() if fetch_sources.row_error(r)], [])
        good = {"path": "fonti/a/b.json", "sha256": "0" * 64,
                "url": "https://raw.githubusercontent.com/o/r/" + "a" * 40 + "/b.json"}
        self.assertIsNone(fetch_sources.row_error(good))
        for bad in (dict(good, extra="x"), dict(good, url="https://example.org/b.json"),
                    dict(good, url="https://raw.githubusercontent.com/o/r/main/b.json"),
                    dict(good, path="fonti/../../x"), dict(good, path="/etc/x"), dict(good, path="tests/x"),
                    dict(good, sha256="A" * 64), dict(good, sha256=1), {"path": good["path"], "sha256": "0" * 64},
                    dict(good, live_url="http://x"), [], None):
            self.assertIsNotNone(fetch_sources.row_error(bad), bad)

    def test_the_key_file_is_rebuilt_from_the_record_at_its_commit(self):
        with open(os.path.join(LIVE, "selftest-pass.json"), "rb") as fh:
            data = fetch_sources.derive_keyfile(fh.read())
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         "2a4eb3cc1cf71402f0331ebd42d652cfde0f50fdb81685689fe1788c7e70d403")
        row = [r for r in rows() if r["path"].endswith("checker-keys-20261018.json")]
        self.assertEqual(len(row), 1)
        self.assertEqual(row[0]["derived_from"], "fonti/issuer_274159c/selftest-pass.json")

    def test_check_mode_passes_offline(self):
        rc, out, _ = cli(os.path.join("tools", "fetch_sources.py"), "--check")
        self.assertEqual(rc, 0, out[-400:])
        self.assertIn("%d/%d sources verified" % (len(rows()), len(rows())), out)

    def test_unknown_mode_is_a_usage_error(self):
        self.assertEqual(cli(os.path.join("tools", "fetch_sources.py"), "--bogus")[0], 64)


class ScoreOptions(unittest.TestCase):
    def test_unknown_option_is_refused_with_exit_2(self):
        rc, out, err = cli(os.path.join("tools", "score.py"), "criteria-noncharacters=report")
        self.assertEqual(rc, 2)
        self.assertIn("criteria-noncharacters=report", err)
        self.assertNotIn("TOTAL", out)

    def test_parse_is_closed(self):
        self.assertEqual(score.parse_args(["criteria_noncharacters=readable"]),
                         (None, "5f7517a", {"criteria_noncharacters": "readable"}))
        self.assertEqual(score.parse_args(["--set", "1.3", "--profile", "1.4.8"])[1:], ("1.3", wv.PROFILE_1_4_8))
        for bad in (["bogus=1"], ["criteria_noncharacters"], ["criteria_noncharacters=nope"],
                    ["sig_r=prime-order", "sig_r=not-small"], ["--set", "zzz"], ["--set"], ["--json"],
                    ["--set", "1.3", "--set", "1.4"], ["--profile", "9"], ["tsa_roots="]):
            with self.assertRaises(ValueError, msg=bad):
                score.parse_args(bad)

    def test_verify_refuses_an_unknown_option_key(self):
        doc = wv.strict_json_loads(wv.read_bounded(os.path.join(LIVE, "selftest-pass.json")))
        with self.assertRaises(ValueError):
            wv.verify(doc["inputs"], {"criteria-noncharacters": "report"})


class Compare(unittest.TestCase):
    def test_an_expected_code_list_holding_a_list_disagrees(self):    # 0.12.0: TypeError, a traceback with --vector
        for codes in ([[1]], [{"a": 1}], ["X", ["Y"]]):
            rows = wv.compare({"problem_codes": []}, {"problem_codes": codes})
            self.assertFalse(rows["agree"], codes)


class Nesting(unittest.TestCase):
    def reason(self, data, limits=True):
        try:
            wv.strict_json_loads(data, limits)
        except wv.Refusal as e:
            return e.reason
        return None

    def test_same_reason_at_every_depth(self):          # RecursionError came at about 1,000 on 3.9-3.12, 100,000 on 3.14
        for n in (66, 1000, 20000, 200000):
            self.assertEqual(self.reason(b"[" * n + b"]" * n), "JSON nesting deeper than 64", n)
            self.assertEqual(self.reason(b'{"a":' * n + b"1" + b"}" * n), "JSON nesting deeper than 64", n)

    def test_bound_unchanged_where_it_parses(self):
        self.assertIsNone(self.reason(b"[" * 65 + b"]" * 65))
        self.assertEqual(self.reason(b"[" * 65 + b"1" + b"]" * 65), "JSON nesting deeper than 64")
        self.assertIsNone(self.reason(b'["' + b"[" * 5000 + b'\\"{"]'))          # brackets in a string do not count

    def test_lifted_limits_have_one_bound_on_every_python(self):
        self.assertIsNone(self.reason(b"[" * 512 + b"]" * 512, False))
        self.assertIsNone(self.reason(b'{"a":' * 512 + b"1" + b"}" * 512, False))
        for n in (513, 2000, 20000, 200000):
            self.assertEqual(self.reason(b"[" * n + b"]" * n, False), "JSON nesting deeper than 512", n)

    def test_count_function(self):
        self.assertFalse(wv.json_too_deep('[["]]]]\\"[[["]]', 2))
        self.assertTrue(wv.json_too_deep('[["]"],[[]]]', 2))
        self.assertTrue(wv.json_too_deep('\\[[]', 1))           # outside a string a backslash escapes nothing
        self.assertFalse(wv.json_too_deep('\\[[]', 2))


class BoundedReads(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.big = os.path.join(self.d.name, "big.json")
        with open(self.big, "wb") as fh:
            fh.truncate(wv.MAX_FILE_BYTES + 1)

    def test_read_bounded(self):
        with self.assertRaises(wv.Refusal) as c:
            wv.read_bounded(self.big)
        self.assertIn("file larger than %d bytes" % wv.MAX_FILE_BYTES, c.exception.reason)
        ok = os.path.join(self.d.name, "ok.json")
        with open(ok, "wb") as fh:
            fh.truncate(wv.MAX_FILE_BYTES)
        self.assertEqual(len(wv.read_bounded(ok)), wv.MAX_FILE_BYTES)

    def test_cli_refuses_a_file_past_the_bound(self):
        rec = os.path.join(LIVE, "selftest-pass.json")
        for args in ([self.big], ["--keys", self.big, rec], ["--relying-party-keys", self.big, rec]):
            rc, out, _ = cli("war_verify.py", *args)
            self.assertEqual(rc, 2, args)
            self.assertIn("file larger than", json.loads(out)["reason"], args)


if __name__ == "__main__":
    unittest.main()
