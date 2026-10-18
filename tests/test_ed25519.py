"""Ed25519: RFC 8032 7.1 tests 1-3, and the edge cases where the `cryptography` engine alone is too lax."""
import base64
import hashlib
import unittest

import _paths  # noqa: F401
import ed25519_edges
import war_verify as wv

RFC8032 = [  # rfc8032.txt section 7.1, TEST 1, 2, 3
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
]


class Ed(unittest.TestCase):
    def test_rfc8032_vectors_both_modes_and_pure(self):
        for pk, m, s in RFC8032:
            pk, m, s = bytes.fromhex(pk), bytes.fromhex(m), bytes.fromhex(s)
            self.assertTrue(wv.ed_verify_pure(pk, m, s))
            for mode in ("strict", "rfc8032"):
                self.assertTrue(wv.ed25519_verify(pk, m, s, mode)[0])
            bad = s[:10] + bytes([s[10] ^ 1]) + s[11:]           # positive control
            self.assertFalse(wv.ed25519_verify(pk, m, bad, "strict")[0])
            self.assertFalse(wv.ed_verify_pure(pk, m, bad))

    def test_edge_table(self):
        rows, _ = ed25519_edges.run()
        t = {r["case"]: r for r in rows}
        r = t["A = identity, R = identity, S = 0, other msg"]
        self.assertTrue(r["engine"])          # the engine alone accepts a universal forgery ...
        self.assertFalse(r["strict"])         # ... strict mode does not
        r = t["A = identity non-canonical (y=1+p), R = identity, S = 0"]
        self.assertTrue(r["engine"])          # the engine decodes a non-canonical A ...
        self.assertFalse(r["pure_rfc8032"])   # ... RFC 8032 5.1.3 does not
        self.assertFalse(r["rfc8032"])
        self.assertFalse(t["S + L (non-canonical S)"]["engine"])
        k = [c for c in t if c.startswith("A order 2")][0]
        self.assertGreater(t[k]["engine"], 0)
        self.assertEqual(t[k]["strict"], 0)

    def test_same_scalar_signs_for_mixed_order_key(self):
        res, _ = ed25519_edges.same_scalar_mixed_key(64)
        self.assertGreater(res["engine"], 0)
        self.assertEqual(res["strict"], 0)
        self.assertGreater(res["ground"], 0)

    def test_point_classes_and_same_key(self):
        pts, T8 = ed25519_edges.torsion_points()
        self.assertEqual(wv.ed_point_class(pts[0]), "small-order")
        A = bytes.fromhex(RFC8032[0][0])
        self.assertEqual(wv.ed_point_class(A), "prime-order")
        Amix = wv._encode_point(wv._padd(wv.ed_decode(A), T8))
        self.assertEqual(wv.ed_point_class(Amix), "mixed-order")
        self.assertTrue(wv.ed_same_key(A, Amix))
        self.assertFalse(wv.ed_same_key(A, bytes.fromhex(RFC8032[1][0])))
        self.assertEqual(wv.ed_point_class((2 ** 255 - 18).to_bytes(32, "little")), "non-canonical encoding (y >= p)")


if __name__ == "__main__":
    unittest.main()
