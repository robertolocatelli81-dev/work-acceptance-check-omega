"""RFC 8785 number table (Appendix B), string escaping, UTF-16 member order; strict JSON intake."""
import struct
import unittest

import _paths  # noqa: F401
import war_verify as wv

APPENDIX_B = [  # transcribed from rfc8785.txt Appendix B, Table 1 (NaN/Infinity rows: must be refused)
    ("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"), ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"), ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"), ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"), ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"), ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"), ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


def f(h):
    return struct.unpack(">d", bytes.fromhex(h))[0]


class JCS(unittest.TestCase):
    def test_appendix_b_all_rows(self):
        for h, want in APPENDIX_B:
            self.assertEqual(wv._jcs_number(f(h)), want, h)

    def test_exponent_boundaries(self):
        # ECMAScript Number::toString boundaries not in Appendix B: n = 0 (0.5), n = 21 (1e20), n = 22 (1e21)
        for x, want in ((0.5, "0.5"), (-0.5, "-0.5"), (1e20, "100000000000000000000"), (1e21, "1e+21"),
                        (123.456, "123.456"), (1e-7, "1e-7"), (1.5e-7, "1.5e-7"), (0.1, "0.1")):
            self.assertEqual(wv._jcs_number(x), want, x)

    def test_non_finite_refused(self):
        for h in ("7fffffffffffffff", "7ff0000000000000"):
            with self.assertRaises(ValueError):
                wv._jcs_number(f(h))

    def test_positive_control_naive_repr_fails_the_table(self):
        wrong = [h for h, want in APPENDIX_B if repr(f(h)) != want]
        self.assertEqual(len(wrong), 10)        # measured: 10 of the 24 rows

    def test_member_order_is_utf16(self):
        # RFC 8785 3.2.3 sorting example
        obj = {"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh",
               "1": "One", "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"}
        got = wv.jcs(obj).decode("utf-8")
        order = ["\r", "1", "\u0080", "ö", "€", "\U0001f600", "דּ"]
        pos = [got.index('"%s"' % k if k != "\r" else '"\\r"') for k in order]
        self.assertEqual(pos, sorted(pos))
        naive = sorted(obj)                      # positive control: code-point order differs
        self.assertNotEqual(naive, order)

    def test_string_escapes(self):
        self.assertEqual(wv.jcs("\u0000\b\f\n\r\t\"\\/\u001f\u007f "),
                         '"\\u0000\\b\\f\\n\\r\\t\\"\\\\/\\u001f\u007f "'.encode("utf-8"))

    def test_rfc8785_section_3_2_2_example(self):
        # RFC 8785 3.2.2 (sample input, numbers part)
        self.assertEqual(wv.jcs({"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001]}),
                         b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}')


class StrictJSON(unittest.TestCase):
    def refused(self, b):
        with self.assertRaises(wv.Refusal):
            wv.strict_json_loads(b)

    def test_refusals(self):
        self.refused(b'{"a":1,"a":2}')
        self.refused(b'{"a":{"b":1,"b":1}}')
        self.refused(b'\xef\xbb\xbf{"a":1}')
        self.refused(b'{"a":"\\ud800"}')
        self.refused(b'{"a":NaN}')
        self.refused(b'{"a":Infinity}')
        self.refused(b'{"a":9007199254740993}')
        self.refused(b'{"a":"\xff"}')
        self.refused(b'[' * 100 + b']' * 100)
        self.refused(b'{"a":1} x')

    def test_accepts_and_positive_control(self):
        self.assertEqual(wv.strict_json_loads(b'{"a":-0}'), {"a": 0})
        self.assertEqual(wv.strict_json_loads(b'{"a":9007199254740991}'), {"a": 9007199254740991})
        with self.assertRaises(wv.Refusal):                       # I-JSON: +-(2^53-1)
            wv.strict_json_loads(b'{"a":9007199254740992}')
        import json
        self.assertEqual(json.loads('{"a":1,"a":2}'), {"a": 2})   # the stdlib alone would accept


if __name__ == "__main__":
    unittest.main()
