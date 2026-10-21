"""Profile 1.4.1 at 06d3b94: the optional receipt member `payment` (x402 exact), outcome-neutral. Oracle: vector 47
and the profile sentence; the grammar is this verifier's closed reading of the member list (values as non-empty
strings, protocol x402, scheme exact, network eip155:<chain id> with the chain id in decimal, no leading zeros, 1-32
digits as CAIP-2 bounds the reference)."""
import os
import unittest

import _paths  # noqa: F401
import war_verify as wv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V47 = os.path.join(ROOT, "fonti/upstream_06d3b94/vectors/47-receipt-payment-x402-exact.json")


def load():
    with open(V47, "rb") as fh:
        return wv.strict_json_loads(fh.read())


class Payment(unittest.TestCase):
    def run_doc(self, doc, options=None):
        return wv.run_vector(doc, options)

    def with_payment(self, pm):
        d = load()
        d["inputs"]["receipt"]["receipt"]["payment"] = pm
        return d

    def test_vector_47_agrees(self):
        rep, cmp_ = self.run_doc(load())
        self.assertTrue(cmp_["agree"], cmp_)
        self.assertIn("receipt.payment present: grammar checked; not checked against a chain (outcome-neutral)",
                      rep["notes"])

    def test_payment_edited_after_signing_is_signature_invalid(self):
        pm = dict(load()["inputs"]["receipt"]["receipt"]["payment"], amount="1001")
        rep, _ = self.run_doc(self.with_payment(pm))
        self.assertFalse(rep.get("refused"), rep)
        self.assertIs(rep["signature_valid"], False)
        self.assertIn("SIGNATURE_INVALID", rep["problem_codes"])

    def test_grammar_is_closed(self):
        base = load()["inputs"]["receipt"]["receipt"]["payment"]
        bad = []
        for m in sorted(base):
            bad.append({k: v for k, v in base.items() if k != m})                       # member missing
            for v in (None, 0, 1000, True, 1.5, [], {}, ["x"], ""):
                bad.append(dict(base, **{m: v}))                                         # wrong type or empty
        bad.append(dict(base, extra="x"))                                                # unknown member
        bad.append(dict(base, settlement_tx=7))
        bad.append(dict(base, settlement_tx=""))
        for p, sc in (("x403", "exact"), ("X402", "exact"), ("x402", "upto"), ("x402", "Exact")):
            bad.append(dict(base, protocol=p, scheme=sc))
        for n in ("eip155:0", "eip155:", "eip155:08453", "base", "eip155:8453\n", "eip155:-1", "solana:1",
                  "eip155:" + "9" * 33,                                              # CAIP-2 reference: 1-32 chars
                  "eip155:\u0668\u0664\u0665\u0663", "eip155:\uff18\uff14\uff15\uff13"):  # digits outside 0-9
            bad.append(dict(base, network=n))
        for x in ([], "x402", 7, None):
            bad.append(x)
        for pm in bad:
            with self.subTest(pm=pm):
                rep, _ = self.run_doc(self.with_payment(pm))
                self.assertTrue(rep.get("refused"), (pm, rep.get("problem_codes")))
        self.assertGreater(len(bad), 80)

    def test_chain_ids_of_1_and_32_digits_pass_the_grammar(self):
        for n in ("eip155:1", "eip155:" + "9" * 32):
            rep, _ = self.run_doc(self.with_payment(dict(load()["inputs"]["receipt"]["receipt"]["payment"], network=n)))
            self.assertFalse(rep.get("refused"), (n, rep))
            self.assertIn("SIGNATURE_INVALID", rep["problem_codes"], n)          # grammar ok; not the signed bytes

    def test_settlement_tx_is_accepted_and_still_signed(self):
        pm = dict(load()["inputs"]["receipt"]["receipt"]["payment"], settlement_tx="0x" + "ab" * 32)
        rep, _ = self.run_doc(self.with_payment(pm))
        self.assertFalse(rep.get("refused"), rep)
        # grammar passes; the bytes are not the signed ones
        self.assertIn("SIGNATURE_INVALID", rep["problem_codes"])

    def test_unknown_member_reported_under_unknown_fields_report(self):
        pm = dict(load()["inputs"]["receipt"]["receipt"]["payment"], extra="x")
        rep, _ = self.run_doc(self.with_payment(pm), {"unknown_fields": "report"})
        self.assertFalse(rep.get("refused"), rep)
        self.assertTrue(any(n.startswith("X_UNKNOWN_MEMBER: receipt.payment.extra") for n in rep["notes"]))

    def test_positive_control_old_grammar_refuses_47(self):
        old = wv.RECEIPT_OPTIONAL
        try:
            wv.RECEIPT_OPTIONAL = set()
            rep, cmp_ = self.run_doc(load())
        finally:
            wv.RECEIPT_OPTIONAL = old
        self.assertTrue(rep.get("refused"))
        self.assertFalse(cmp_["agree"])


if __name__ == "__main__":
    unittest.main()
