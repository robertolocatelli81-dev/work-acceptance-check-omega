"""Profile 1.4.1: the optional receipt member `payment` (x402 exact), outcome-neutral. Oracle: vectors 47 (06d3b94)
and 55 (bc5a138) and the stated form (bc5a138 README and verifier/check_payment.py _in_form: exactly the required members
plus optional settlement_tx, all strings; network eip155: and a decimal chain id without leading zeros; amount a decimal
string; addresses 20 bytes, nonce and settlement_tx 32 bytes, 0x-prefixed hex). "A member outside it changes no
outcome": from 0.5.0 a payment outside the form is listed in notes as unsupported, never refused (0.4.1 refused it)."""
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
        self.assertIn("receipt.payment present: inside the stated form; not checked against a chain "
                      "(outcome-neutral)", rep["notes"])

    def test_payment_edited_after_signing_is_signature_invalid(self):
        pm = dict(load()["inputs"]["receipt"]["receipt"]["payment"], amount="1001")
        rep, _ = self.run_doc(self.with_payment(pm))
        self.assertFalse(rep.get("refused"), rep)
        self.assertIs(rep["signature_valid"], False)
        self.assertIn("SIGNATURE_INVALID", rep["problem_codes"])

    def test_outside_the_form_is_noted_never_refused(self):
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
        for a in ("01", "1.0", "-1", "1e3", " 1", "1\n", "\u0661", "0x10"):                # amount: decimal string
            bad.append(dict(base, amount=a))
        for m, n in (("asset", 20), ("payer", 20), ("pay_to", 20), ("nonce", 32), ("settlement_tx", 32)):
            for v in ("0x" + "a" * (2 * n - 1), "0x" + "a" * (2 * n + 1), "0X" + "a" * (2 * n), "a" * (2 * n + 2),
                      "0x" + "g" * (2 * n), "0x" + "a" * (2 * n) + "\n"):
                bad.append(dict(base, **{m: v}))
        for x in ([], "x402", 7, None):
            bad.append(x)
        for pm in bad:
            with self.subTest(pm=pm):
                rep, _ = self.run_doc(self.with_payment(pm))
                self.assertFalse(rep.get("refused"), (pm, rep.get("reason")))
                self.assertTrue(any(n.startswith("receipt.payment outside the stated form") for n in rep["notes"]),
                                (pm, rep["notes"]))
        self.assertGreater(len(bad), 120)

    def test_inside_the_form_upper_case_hex_and_settlement_tx(self):
        base = load()["inputs"]["receipt"]["receipt"]["payment"]
        for pm in (dict(base, payer="0x" + "A" * 40), dict(base, settlement_tx="0x" + "Ab" * 32), dict(base, amount="0")):
            rep, _ = self.run_doc(self.with_payment(pm))
            self.assertFalse(any(n.startswith("receipt.payment outside") for n in rep["notes"]), pm)

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

    def test_unknown_member_is_outside_the_form_under_both_unknown_fields_modes(self):
        pm = dict(load()["inputs"]["receipt"]["receipt"]["payment"], extra="x")
        for mode in ("refuse", "report"):
            rep, _ = self.run_doc(self.with_payment(pm), {"unknown_fields": mode})
            self.assertFalse(rep.get("refused"), rep)
            self.assertTrue(any(n.startswith("receipt.payment outside the stated form") and "extra" in n
                                for n in rep["notes"]), rep["notes"])

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
