"""Own DER parser and the two time grammars."""
import unittest

import _paths  # noqa: F401
import testpki as tp
import war_verify as wv

OPTS = dict(wv.DEFAULT_OPTIONS)


class DER(unittest.TestCase):
    def refused(self, raw):
        with self.assertRaises(wv.Refusal):
            wv.parse_tsr(raw, OPTS)

    def test_good_and_variants(self):
        d = b"\x44" * 32
        good = tp.unsigned_tsr(tp.tstinfo(d))
        t = wv.parse_tsr(good, OPTS)["token"]["tst"]
        self.assertEqual(t["hashed"], d)
        self.assertEqual(t["gen"]["text"], "20260301000000Z")
        self.refused(good + b"\x00")
        self.refused(b"\x30\x81" + good[1:])
        self.refused(b"\x30\x80" + good[2:] + b"\x00\x00")
        self.refused(good[:-1])
        self.refused(tp.unsigned_tsr(tp.tstinfo(d, ordering=False)))
        self.refused(tp.unsigned_tsr(tp.tstinfo(d), status=2))

    def test_unsigned_vector_shape_only_in_structural_mode(self):
        raw = tp.unsigned_tsr(tp.tstinfo(b"\x44" * 32))
        p = wv.parse_tsr(raw, OPTS)
        self.assertTrue(any("X_TOKEN_NOT_CMS_CONFORMANT" in n for n in p["notes"]))
        self.refused_pkix = lambda: wv.parse_tsr(raw, dict(OPTS, tokens="pkix"))
        with self.assertRaises(wv.Refusal):
            self.refused_pkix()
        with_si = tp.unsigned_tsr(tp.tstinfo(b"\x44" * 32), with_signerinfos=True)
        self.assertFalse(any("X_TOKEN" in n for n in wv.parse_tsr(with_si, OPTS)["notes"]))

    def test_integers_and_oids(self):
        self.assertEqual(wv.der_int(wv.der_parse_one(b"\x02\x01\x80", "i"), "i"), -128)
        with self.assertRaises(wv.Refusal):
            wv.der_int(wv.der_parse_one(b"\x02\x02\x00\x01", "i"), "i")
        with self.assertRaises(wv.Refusal):
            wv.der_int(wv.der_parse_one(b"\x02\x02\xff\x80", "i"), "i")
        self.assertEqual(wv.der_oid(wv.der_parse_one(tp.oid("2.16.840.1.101.3.4.2.1"), "o"), "o"), "2.16.840.1.101.3.4.2.1")
        with self.assertRaises(wv.Refusal):
            wv.der_oid(wv.der_parse_one(b"\x06\x03\x2a\x80\x01", "o"), "o")

    def test_accuracy(self):
        raw = tp.unsigned_tsr(tp.tstinfo(b"\x44" * 32, accuracy=(1, 500, 7)))
        acc = wv.parse_tsr(raw, OPTS)["token"]["tst"]["accuracy"]
        self.assertEqual(float(acc), 1.500007)


class Times(unittest.TestCase):
    def test_generalized_time(self):
        ok = {"20260301000000Z": 0, "19920722132100.3Z": 1, "20260301000000.000001Z": 6}
        for s, digits in ok.items():
            self.assertEqual(wv.parse_generalized_time(s, "g")["digits"], digits)
        for s in ("20260301000000", "20260301000000.0Z", "20260301000000.Z", "20261231235960Z", "202603010000Z",
                  "20260301000000+0000", "20260301000000z", "20260229000000Z", "20240230000000Z", "2026030100000Z"):
            with self.assertRaises(wv.Refusal, msg=s):
                wv.parse_generalized_time(s, "g")
        self.assertIsNotNone(wv.parse_generalized_time("20240229000000Z", "g"))

    def test_rfc3339(self):
        a = wv.parse_rfc3339z("2026-06-01T12:00:00Z", "t")["instant"]
        b = wv.parse_rfc3339z("2026-06-01T12:00:00.000001Z", "t")["instant"]
        self.assertLess(a, b)
        for s in ("2026-06-01T12:00:00+00:00", "2026-06-01t12:00:00Z", "2026-06-01 12:00:00Z", "2026-06-01T12:00:60Z"):
            with self.assertRaises(wv.Refusal, msg=s):
                wv.parse_rfc3339z(s, "t")
        self.assertEqual(wv.fmt_instant(b), "2026-06-01T12:00:00.000001Z")

    def test_both_grammars_agree_on_instants(self):
        self.assertEqual(wv.parse_rfc3339z("2026-03-01T00:00:00Z", "t")["instant"],
                         wv.parse_generalized_time("20260301000000Z", "g")["instant"])
        import calendar
        self.assertEqual(wv.parse_rfc3339z("2026-03-01T00:00:00Z", "t")["instant"], calendar.timegm((2026, 3, 1, 0, 0, 0)))

    def test_truncate_agreement(self):
        claim = wv.parse_rfc3339z("2026-03-01T00:00:00Z", "t")
        self.assertTrue(wv._times_agree(claim, wv.parse_generalized_time("20260301000000.9Z", "g"), "truncate"))
        self.assertFalse(wv._times_agree(claim, wv.parse_generalized_time("20260301000000.9Z", "g"), "exact"))
        self.assertFalse(wv._times_agree(claim, wv.parse_generalized_time("20260301000001Z", "g"), "truncate"))


if __name__ == "__main__":
    unittest.main()
