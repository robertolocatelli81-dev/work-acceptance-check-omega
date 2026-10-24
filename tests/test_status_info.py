"""PKIStatusInfo grammar (RFC 3161 2.4.2): statusString is PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
(RFC 4210 5.1.1) and failInfo is a BIT STRING. Profile 1.4.1 step 5 (bc5a138): imprint, genTime and accuracy come
from the signed TSTInfo, "never other bytes of the response, such as PKIStatusInfo.statusString". Vectors 50 and 51 fix
one case outside the grammar: a UTF8String whose bytes are not UTF-8. From 0.5.0 that case is listed in notes and not
refused (0.4.1 refused it); anything else outside the grammar is still refused (the profile does not fix it; until
0.4.0 any SEQUENCE was accepted silently). failInfo keeps the DER rules of X.690 (no vector says otherwise).

The end-to-end case is the construction described on x402-foundation/tsc#4 on 2026-10-21 (an imprint pattern in the
unsigned PKIStatusInfo of a genuine token), rebuilt here from vector 31 for both tokens: before the grammar check the
imprint was already read from the signed TSTInfo only (criteria: CRITERIA_TIMESTAMP_MISMATCH; record:
imprint_mismatch); 0.4.1 refused the response; 0.5.0 reads the probe's layout (one UTF8String that is not UTF-8, as in
vectors 50 and 51) and the outcome is again the mismatch, and still refuses the layout with the values as direct
members (not UTF8Strings), which no vector fixes."""
import base64
import json
import os
import unittest

import _paths
import war_verify as wv

V31 = os.path.join(_paths.ROOT, "fonti", "upstream_06d3b94", "vectors", "31-tsa-freetsa-verified.json")


def L(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(t, body):
    return bytes([t]) + L(len(body)) + body


def resp(*status_members):
    """TimeStampResp with PKIStatus rejection (2) and the given extra PKIStatusInfo members, no token."""
    return tlv(0x30, tlv(0x30, tlv(0x02, b"\x02") + b"".join(status_members)))


def utf8(s):
    return tlv(0x0C, s)


class StatusString(unittest.TestCase):
    def ok(self, raw):
        return wv.parse_tsr(raw, None)

    OUTSIDE = ("PKIStatusInfo.statusString holds a UTF8String that is not UTF-8 (RFC 4210 5.1.1): not read, not a reason "
               "to refuse (profile 1.4.1 vectors 50, 51)")

    def test_free_text_accepted_and_noted(self):
        out = self.ok(resp(tlv(0x30, utf8(b"rejected") + utf8("café".encode()))))
        self.assertIn("PKIStatusInfo.statusString present (not read)", out["notes"])
        self.assertNotIn(self.OUTSIDE, out["notes"])

    def test_empty_free_text_refused(self):
        # not fixed by the profile (vectors 50 and 51 hold one UTF8String): closed by construction
        with self.assertRaises(wv.Refusal) as cm:
            self.ok(resp(tlv(0x30, b"")))
        self.assertIn("empty PKIFreeText", cm.exception.args[0])

    def test_member_not_utf8string_refused(self):
        for member in (tlv(0x13, b"text"), tlv(0x04, b"\x00" * 32), tlv(0x30, tlv(0x06, b"\x2a")), tlv(0x2C, utf8(b"a"))):
            with self.assertRaises(wv.Refusal, msg=member.hex()) as cm:
                self.ok(resp(tlv(0x30, utf8(b"ok") + member)))
            self.assertIn("PKIFreeText UTF8String", cm.exception.args[0])

    def test_invalid_utf8_noted_not_refused(self):
        for bad in (b"\xff", b"\xc3", b"\xed\xa0\x80"):
            self.assertIn(self.OUTSIDE, self.ok(resp(tlv(0x30, utf8(bad))))["notes"])

    def test_statusString_outside_DER_still_refused(self):
        # the response itself must still be DER: a statusString whose length runs past the end is a TLV defect
        with self.assertRaises(wv.Refusal):
            wv.parse_tsr(resp(b"\x30\x05" + utf8(b"ab")), None)


class FailInfo(unittest.TestCase):
    def test_valid_bit_strings(self):
        for c in (b"\x07\x80", b"\x00\x01", b"\x02\x04\x04", b"\x00", b"\x01\x01\x02"):
            out = wv.parse_tsr(resp(tlv(0x03, c)), None)
            self.assertIn("PKIStatusInfo.failInfo present", out["notes"])

    def test_malformed_bit_strings_refused(self):
        for c in (b"", b"\x08\x80", b"\x08\x00", b"\x01", b"\x07\x81", b"\x01\x01"):
            with self.assertRaises(wv.Refusal, msg=c.hex()) as cm:
                wv.parse_tsr(resp(tlv(0x03, c)), None)
            self.assertIn("malformed BIT STRING", cm.exception.args[0])

    def test_trailing_zero_bits_refused(self):
        """PKIFailureInfo is a named bit list: DER removes trailing zero bits (X.690 11.2.2), so badAlg alone is
        07 80, never 00 80; the all-zero list is the empty BIT STRING 00."""
        for c in (b"\x00\x80", b"\x00\x12", b"\x01\x02\x04", b"\x00\x00"):
            with self.assertRaises(wv.Refusal, msg=c.hex()) as cm:
                wv.parse_tsr(resp(tlv(0x03, c)), None)
            self.assertIn("trailing zero bits", cm.exception.args[0])

    def test_both_members_in_order(self):
        out = wv.parse_tsr(resp(tlv(0x30, utf8(b"x")), tlv(0x03, b"\x07\x80")), None)
        self.assertEqual(len(out["notes"]), 2)


def _children(body):
    out = []
    while body:
        n = body[1]
        h = 2 if n < 128 else 2 + (n & 0x7F)
        m = n if n < 128 else int.from_bytes(body[2:h], "big")
        out.append(body[:h + m])
        body = body[h + m:]
    return out


def _body(raw):
    n = raw[1]
    return raw[2:] if n < 128 else raw[2 + (n & 0x7F):]


def with_status_string(tsr, imprint, gen, as_probe=False):
    """Copy of a genuine TimeStampResp whose unsigned PKIStatusInfo also holds
    AlgorithmIdentifier(sha-256) || OCTET STRING(imprint) || GeneralizedTime as its statusString. No signed byte
    changes. With as_probe, the three values are the content of one UTF8String inside the statusString SEQUENCE
    and the AlgorithmIdentifier carries NULL parameters: byte for byte the layout of the published probe
    (probe-status-string-imprint.json, SHA-256 66f9aeb761aae596...), whose UTF8String content is not UTF-8; without
    it they are direct members of the SEQUENCE (not UTF8Strings)."""
    kids = _children(_body(tsr))
    status = _children(_body(kids[0]))
    alg = tlv(0x30, tlv(0x06, bytes.fromhex("608648016503040201")) + (tlv(0x05, b"") if as_probe else b""))
    payload = alg + tlv(0x04, imprint) + gen
    extra = tlv(0x30, utf8(payload) if as_probe else payload)
    return tlv(0x30, tlv(0x30, b"".join(status) + extra) + b"".join(kids[1:]))


@unittest.skipUnless(os.path.exists(V31), "fonti/upstream_06d3b94 not present")
class ImprintInUnsignedBytes(unittest.TestCase):
    def setUp(self):
        with open(V31, "rb") as fh:
            self.v = wv.strict_json_loads(fh.read())
        i = self.v["inputs"]
        self.rec = base64.b64decode(i["receipt_tsr_base64"])
        self.cri = base64.b64decode(i["criteria_tsr_base64"])

    def tst(self, raw):
        return wv.parse_tsr(raw, None)["token"]

    def gen(self, raw):
        return [c for c in _children(_body(self.tst(raw)["econtent"])) if c[0] == 0x18][0]

    def test_construction_puts_the_imprint_in_unsigned_bytes_only(self):
        crit_digest = bytes.fromhex(self.v["inputs"]["receipt"]["receipt"]["criteria"]["sha256"])
        probe = with_status_string(self.rec, crit_digest, self.gen(self.cri), as_probe=True)
        self.assertIn(crit_digest, probe)
        self.assertNotEqual(self.tst(self.rec)["tst"]["hashed"], crit_digest)
        self.assertEqual(self.tst(probe)["tst"]["hashed"], self.tst(self.rec)["tst"]["hashed"])   # signed TSTInfo only

    def test_record_token_variant_reads_the_signed_imprint(self):
        rec_digest = self.tst(self.rec)["tst"]["hashed"]
        probe = with_status_string(self.cri, rec_digest, self.gen(self.rec), as_probe=True)
        self.assertIn(rec_digest, probe)
        self.assertEqual(self.tst(probe)["tst"]["hashed"], self.tst(self.cri)["tst"]["hashed"])

    def test_direct_members_layout_refused(self):
        # the values as direct members of the statusString (not UTF8Strings): no vector fixes it, so it is refused
        crit_digest = bytes.fromhex(self.v["inputs"]["receipt"]["receipt"]["criteria"]["sha256"])
        rec_digest = self.tst(self.rec)["tst"]["hashed"]
        for base, digest, gen in ((self.rec, crit_digest, self.gen(self.cri)), (self.cri, rec_digest, self.gen(self.rec))):
            with self.assertRaises(wv.Refusal) as cm:
                wv.parse_tsr(with_status_string(base, digest, gen), None)
            self.assertIn("PKIFreeText UTF8String", cm.exception.args[0])

    def test_probe_layout_noted_and_signed_imprint_read(self):
        """The published probe's layout for both tokens: a PKIFreeText of one UTF8String whose bytes are not UTF-8."""
        crit_digest = bytes.fromhex(self.v["inputs"]["receipt"]["receipt"]["criteria"]["sha256"])
        rec_digest = self.tst(self.rec)["tst"]["hashed"]
        for base, digest, gen in ((self.rec, crit_digest, self.gen(self.cri)), (self.cri, rec_digest, self.gen(self.rec))):
            probe = with_status_string(base, digest, gen, as_probe=True)
            self.assertIn(digest, probe)
            self.assertEqual(wv.der_parse_one(probe, "r").kids()[0].kids()[1].kids()[0].tag, 0x0C)
            out = wv.parse_tsr(probe, None)
            self.assertIn(StatusString.OUTSIDE, out["notes"])
            self.assertEqual(out["token"]["tst"]["hashed"], self.tst(base)["tst"]["hashed"])


if __name__ == "__main__":
    unittest.main()
