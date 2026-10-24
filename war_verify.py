#!/usr/bin/env python3
"""war_verify.py - clean-room verifier for work-acceptance records, draft profile 1.4.1 (schema identifier 1.2).

Written from the profile README at maximusrufus/work-acceptance-record@bc5a138 (profile 1.4.1; 06d3b94 and d79a737
before it; 1.4 at eb0f30b, 1.3 at 42b4ed0 and 1.2.1 at f7d8984), the test vectors listed in README.md ("What was
read"), and the RFCs it names. An issue comment quoting parts of the reference verifier was read before 0.4.0, and a
probe description before 0.4.1. For 0.5.0 the payment form was taken from the function _in_form of the reference
verifier/check_payment.py (opened), and the reference verifier/war_verify.py was searched once with grep and run as a
black box (README.md, "What was read"); no other implementation of this profile was opened. The 1.2.1 readings of version 0.1.0 are selectable with
--profile 1.2.1.

Closed by construction: every member of every JSON object is either understood or the input is refused with a
reason, except where profile 1.4.1 (bc5a138) fixes the outcome; each such case is listed in "notes" (README.md,
"Closed by construction"). Where a standard says what to do with something unknown (RFC 5280 4.2: a non-critical extension that is
not recognised MAY be ignored, a critical one MUST be rejected; RFC 3161 2.4.2: unknown PKIStatus values MUST be
an error), that rule is followed and the event is listed in the report's "notes".

Standard library + `cryptography` (Ed25519 arithmetic engine, X.509 certificate parsing and the TSA signature in
--tokens pkix). JSON canonicalisation (RFC 8785) and DER/CMS/TSTInfo parsing are written here.

Exit codes:  0  the record is accepted as stated (signature valid, no problem codes, commitment order decided)
                AND no local block applies (report field "local_blocks"): the key file came from --keys, the
                signing key is not a test key, every time-stamp token whose time was used was authenticated
                (--tokens pkix), supplied files match the record, no key in the key file is rejected, and
                receipt.key_id agrees with signature.key_id (a profile code under 1.3, a local block under
                --key-id-agreement require, not required under --key-id-agreement ignore)
             1  verified, but not accepted as stated (problem codes, invalid signature, order undetermined under
                --accuracy interval) or a local block applies; the profile fields are still the profile's
             2  the input was refused (outside the grammar, unknown schema/canonicalization/suite, ...)
             3  --vector mode: our outcome differs from the vector's "expected" object
            64  usage error
            74  a check could not run (e.g. `cryptography` missing, --tsa-roots unreadable); a report is printed
"""
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import unicodedata
from fractions import Fraction

VERSION = "war_verify 0.5.0"

try:  # the only third-party dependency; its absence is exit 74, never a silent skip
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _CRYPTO_ERROR = None
except Exception as _e:  # pragma: no cover - exercised by tests in a venv without cryptography
    InvalidSignature = UnsupportedAlgorithm = Ed25519PublicKey = None
    _CRYPTO_ERROR = "%s: %s" % (type(_e).__name__, _e)

# ----------------------------------------------------------------------------------------------- profile constants
SCHEMA = "trilatic.acceptance-receipt/1.2"
CANONICALIZATION = "JCS-RFC8785"
SUITE = {"digest": "sha-256", "signature": "Ed25519"}
VOCAB = ("pass", "fail", "not-evaluated", "error")                       # README property 4
PROBLEM_CODES = frozenset((                                               # README step 8, closed list
    "SIGNATURE_INVALID", "KEY_REJECTED", "CHECKER_NOT_SIGNER", "KEY_COLLISION", "INDEPENDENCE_INCONSISTENT", "RESULT_VOCABULARY",
    "VERDICT_MISMATCH", "CRITERIA_HASH_MISMATCH", "CRITERIA_RESULTS_MISMATCH", "CRITERIA_TIMESTAMP_MISMATCH",
    "CRITERIA_TIME_MISMATCH", "CRITERIA_COMMITTED_AFTER_CHECK"))
WARNING_CODES = frozenset(("SELF_CHECKED", "PRODUCER_UNDECLARED", "CRITERIA_COMMITMENT_UNVERIFIED"))
STEP1_REASON = "unknown schema, canonicalization or suite"                # README step 1 wording
COVERS = "sha256 of the canonical receipt object"

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8"
UNSUPPORTED_SUFFIX = "not implemented by this verifier"
HASH_OIDS = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224", OID_SHA256: "sha256",
             "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512",
             "2.16.840.1.101.3.4.2.8": "sha3-256", "2.16.840.1.101.3.4.2.9": "sha3-384",
             "2.16.840.1.101.3.4.2.10": "sha3-512"}

DEFAULT_OPTIONS = {
    # Defaults = profile 1.3 (maximusrufus/work-acceptance-record@42b4ed0). The 1.2.1 readings stay behind switches.
    # Step 2 (1.3) "verify the Ed25519 signature with the key named by the signed `receipt.key_id`".
    # receipt = receipt.key_id (1.3); envelope = signature.key_id (this verifier's 1.2.1 reading).
    "key_id_source": "receipt",
    # Step 5 (1.3) "the **earlier** of `issued_utc` and the genTime of the record's own token when a token covering
    # the record is supplied, else `issued_utc`"; covering-token = the 1.2.1 text.
    "reference_time": "earlier",
    # README step 5 "a criteria.committed_at that disagrees": truncate = equal at committed_at's own precision.
    "time_agreement": "truncate",
    # Step 5 (1.3) "A token's stated `accuracy` widens its time against 'committed before'; a token stating none is
    # taken at its genTime; `ordering` is ignored" = widen. ignore = 1.2.1 (accuracy not used); interval = RFC 3161
    # 2.4.2 ordering rule with 'undetermined' when the order is not provable.
    "accuracy": "widen",
    # structural = imprint and genTime only (profile text); pkix = full RFC 3161/5652/5280 TSA validation.
    "tokens": "structural",
    "tsa_roots": None,
    # INDEPENDENCE_INCONSISTENT name comparison: exact bytes, or NFKC+casefold+whitespace-collapsed.
    "name_compare": "exact",
    # members the profile does not define: refuse (closed) or report (listed in notes, otherwise ignored).
    "unknown_fields": "refuse",
    # strict = canonical A and R, A of prime order, R not of small order, S < L; rfc8032 = RFC 8032 5.1.7 only.
    "ed25519": "strict",
    # CRITERIA_RESULTS_MISMATCH: ids-required = same ids, same `required`; strict = also the same titles.
    "correspondence": "ids-required",
    # Step 2 (1.3) "The envelope's `signature.key_id` must equal it, else `SIGNATURE_INVALID`" = signature-invalid.
    # require = 1.2.1 reading of this verifier (profile fields unchanged, a local block for exit 0); ignore = noted.
    "key_id_agreement": "signature-invalid",
    # Step 2 (1.3) key rule: "the public key must be a canonical encoding (y < p) of a point of prime order; any other
    # key ... is `KEY_REJECTED` and no signature check is run". signer = applied to the key named by receipt.key_id
    # (other bad keys in the file: X_UNUSED_KEY_REJECTED, a local block); all-keys = any bad key in the key file is
    # KEY_REJECTED; refuse = 1.2.1 behaviour of this verifier (the whole input refused, per --ed25519).
    "key_rule": "signer",
    # Step 8 (1.3) "a stated `independence` that differs from the derived one is also `INDEPENDENCE_INCONSISTENT`"
    # = derived; stated-independent = 1.2.1 reading (only a stated `independent` with the same party).
    "independence_rule": "derived",
    # Profile 1.4 step 9 lists the `tsa_signature` values without an order; failed-first = a check that ran and failed
    # decides; evaluability-first = no_signer, then unsupported, before failed.
    "tsa_precedence": "failed-first",
}
OPTION_VALUES = {
    "key_id_source": ("envelope", "receipt"), "reference_time": ("covering-token", "earlier"),
    "time_agreement": ("truncate", "exact"), "accuracy": ("widen", "ignore", "interval"),
    "tokens": ("structural", "pkix"),
    "name_compare": ("exact", "normalized"), "unknown_fields": ("refuse", "report"), "ed25519": ("strict", "rfc8032"),
    "correspondence": ("ids-required", "strict"),
    "key_id_agreement": ("signature-invalid", "require", "ignore"), "key_rule": ("signer", "all-keys", "refuse"),
    "independence_rule": ("derived", "stated-independent"),
    "tsa_precedence": ("failed-first", "evaluability-first"),
}
# The profile 1.2.1 readings of this verifier (version 0.1.0), selectable together with --profile 1.2.1.
PROFILE_1_2_1 = {"key_id_source": "envelope", "reference_time": "covering-token", "accuracy": "ignore",
                 "key_id_agreement": "require", "key_rule": "refuse", "independence_rule": "stated-independent"}


class Refusal(Exception):
    """The input is outside the grammar this verifier implements; nothing is reported as a result."""

    def __init__(self, reason, detail=""):
        Exception.__init__(self, reason)
        self.reason = reason
        self.detail = detail


class CannotRun(Exception):
    """A check that was asked for cannot run in this environment (exit 74)."""


# ======================================================================================== strict JSON (RFC 8259)
class _Dup(Exception):
    pass


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _Dup(k)
        out[k] = v
    return out


def _no_constant(name):
    raise ValueError("non-finite number %s" % name)


MAX_SAFE = 2 ** 53


def _check_values(obj, depth=0):
    if depth > 64:
        raise Refusal("JSON nesting deeper than 64")
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError:
            raise Refusal("JSON string with a lone surrogate (RFC 7493 2.1, RFC 8785 3.2.2.2)")
    elif isinstance(obj, bool) or obj is None:
        pass
    elif isinstance(obj, int):
        if abs(obj) >= MAX_SAFE:
            raise Refusal("integer outside the I-JSON range +-(2^53-1) (RFC 7493 2.2)")
    elif isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise Refusal("non-finite number")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _check_values(k, depth + 1)
            _check_values(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _check_values(v, depth + 1)


def strict_json_loads(data):
    """bytes -> value. Refuses: BOM, invalid UTF-8, duplicate member names, NaN/Infinity, lone surrogates,
    integers outside +-(2^53-1), nesting > 64, trailing garbage."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("bytes expected")
    if data[:3] == b"\xef\xbb\xbf":
        raise Refusal("JSON text starts with a byte order mark (RFC 8259 8.1)")
    try:
        text = bytes(data).decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise Refusal("JSON text is not valid UTF-8", str(e))
    try:
        obj = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constant)
    except _Dup as e:
        raise Refusal("duplicate JSON member name", repr(e.args[0]))
    except RecursionError:
        raise Refusal("JSON nesting too deep")
    except ValueError as e:
        raise Refusal("not JSON", str(e))
    _check_values(obj)
    return obj


# ========================================================================================== JCS (RFC 8785)
def _jcs_number(x):
    if isinstance(x, bool):
        raise ValueError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > MAX_SAFE:
            raise ValueError("integer outside +-2^53")
        x = float(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite number")
    if x == 0:
        return "0"                                   # also -0 (RFC 8785 Appendix B)
    sign = "-" if x < 0 else ""
    r = repr(abs(x))                                 # shortest round-trip digits (same as ECMAScript)
    if "e" in r:
        mant, exp = r.split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) + exp - lead_zeros                   # value = 0.digits * 10^n
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        s = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + es
    return sign + s


def _jcs_string(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif c < 0x20:
            out.append("\\u%04x" % c)
        elif 0xD800 <= c <= 0xDFFF:
            raise ValueError("lone surrogate")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs(v, out):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, str):
        out.append(_jcs_string(v))
    elif isinstance(v, (int, float)):
        out.append(_jcs_number(v))
    elif isinstance(v, list):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _jcs(x, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        for i, k in enumerate(sorted(v, key=lambda s: s.encode("utf-16-be"))):   # RFC 8785 3.2.3
            if i:
                out.append(",")
            out.append(_jcs_string(k))
            out.append(":")
            _jcs(v[k], out)
        out.append("}")
    else:
        raise ValueError("not a JSON value: %r" % type(v))


def jcs(value):
    out = []
    _jcs(value, out)
    return "".join(out).encode("utf-8")


# ============================================================================================ strict base64
_B64 = re.compile(r"\A[A-Za-z0-9+/]*={0,2}\Z")


def b64_strict(s, what):
    """RFC 4648 section 4 with padding, canonical (no non-zero pad bits, no whitespace)."""
    if not isinstance(s, str) or not _B64.match(s) or len(s) % 4:
        raise Refusal("%s is not canonical padded base64" % what)
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise Refusal("%s is not canonical padded base64" % what)
    if base64.b64encode(raw).decode("ascii") != s:
        raise Refusal("%s is non-canonical base64 (non-zero padding bits)" % what)
    return raw


# =========================================================================================== times
def _days_from_civil(y, m, d):
    y -= m <= 2
    era = (y if y >= 0 else y - 399) // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _valid_date(y, mo, d, h, mi, s):
    if not (1 <= mo <= 12 and 0 <= h <= 23 and 0 <= mi <= 59):
        return "out-of-range field"
    if s == 60:
        return "leap second 60 (not accepted: see README, 'Times')"
    if not 0 <= s <= 59:
        return "out-of-range seconds"
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    mdays = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    if not 1 <= d <= mdays:
        return "day out of range"
    return None


def _to_instant(y, mo, d, h, mi, s, frac):
    secs = _days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s
    f = Fraction(int(frac), 10 ** len(frac)) if frac else Fraction(0)
    return Fraction(secs) + f


_RFC3339Z = re.compile(r"\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z\Z")


def parse_rfc3339z(v, what):
    """RFC 3339 date-time restricted to UTC with an upper-case Z (the fields are named *_utc / *_at in UTC)."""
    if not isinstance(v, str):
        raise Refusal("%s is not a string" % what)
    m = _RFC3339Z.match(v)
    if not m:
        raise Refusal("%s is not an RFC 3339 UTC date-time ending in Z" % what, v)
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    bad = _valid_date(y, mo, d, h, mi, s)
    if bad:
        raise Refusal("%s: %s" % (what, bad), v)
    frac = m.group(7) or ""
    return {"instant": _to_instant(y, mo, d, h, mi, s, frac), "digits": len(frac), "text": v}


_GENTIME = re.compile(r"\A([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]*[1-9]))?Z\Z")


def parse_generalized_time(v, what):
    """GeneralizedTime with the RFC 3161 2.4.2 restrictions: seconds present, Z, '.' only with non-zero digits
    and no trailing zeros."""
    if isinstance(v, (bytes, bytearray)):
        try:
            v = bytes(v).decode("ascii")
        except UnicodeDecodeError:
            raise Refusal("%s is not ASCII" % what)
    m = _GENTIME.match(v)
    if not m:
        raise Refusal("%s violates the RFC 3161 2.4.2 GeneralizedTime syntax" % what, v)
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    bad = _valid_date(y, mo, d, h, mi, s)
    if bad:
        raise Refusal("%s: %s" % (what, bad), v)
    frac = m.group(7) or ""
    return {"instant": _to_instant(y, mo, d, h, mi, s, frac), "digits": len(frac), "text": v}


def fmt_instant(x):
    if x is None:
        return None
    whole = x.numerator // x.denominator
    frac = x - whole
    days, rem = divmod(whole, 86400)
    # civil_from_days
    z = days + 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + (3 if mp < 10 else -9)
    y += m <= 2
    s = "%04d-%02d-%02dT%02d:%02d:%02d" % (y, m, d, rem // 3600, rem % 3600 // 60, rem % 60)
    if frac:
        digits = ""
        f = frac
        for _ in range(12):
            f *= 10
            digits += str(f.numerator // f.denominator)
            f -= f.numerator // f.denominator
            if not f:
                break
        s += "." + digits
    return s + "Z"


# ===================================================================================== Ed25519 group checks
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)
_IDENT = (0, 1, 1, 0)


def _padd(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _pmul(s, P):
    Q = _IDENT
    while s > 0:
        if s & 1:
            Q = _padd(Q, P)
        P = _padd(P, P)
        s >>= 1
    return Q


def _pequal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _P == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _P == 0


def _encode_point(P):
    zi = pow(P[2], _P - 2, _P)
    x, y = P[0] * zi % _P, P[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def ed_decode(b):
    """RFC 8032 5.1.3 decoding, with its two canonicity checks. Returns a point or a reason string."""
    if len(b) != 32:
        return "not 32 bytes"
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return "non-canonical encoding (y >= p)"
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return "non-canonical encoding (x = 0 with sign bit 1)"
        return (0, y, 1, 0)
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return "not a curve point"
    if (x & 1) != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


_BASE = ed_decode(int.to_bytes(4 * pow(5, _P - 2, _P) % _P, 32, "little"))


def ed_point_class(b):
    """'prime-order' | 'small-order' | 'mixed-order' | reason string for an undecodable encoding."""
    P = ed_decode(b)
    if isinstance(P, str):
        return P
    if _pequal(_pmul(8, P), _IDENT):
        return "small-order"
    if not _pequal(_pmul(_L, P), _IDENT):
        return "mixed-order"
    return "prime-order"


def ed_same_key(a, b):
    """True if the two encodings are equal or differ only by a small-order (torsion) component, i.e. the same
    private scalar can produce signatures accepted under both (measured in tools/ed25519_edges.py)."""
    if a == b:
        return True
    A, B = ed_decode(a), ed_decode(b)
    if isinstance(A, str) or isinstance(B, str):
        return False
    negB = ((_P - B[0]) % _P, B[1], B[2], (_P - B[3]) % _P)
    return _pequal(_pmul(8, _padd(A, negB)), _IDENT)


def ed_verify_pure(pub, msg, sig):
    """RFC 8032 5.1.7 cofactorless verification in pure Python (differential reference for the tests)."""
    if len(sig) != 64:
        return False
    A = ed_decode(pub)
    R = ed_decode(sig[:32])
    if isinstance(A, str) or isinstance(R, str):
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    return _pequal(_pmul(S, _BASE), _padd(R, _pmul(k, A)))


def ed25519_verify(pub, msg, sig, mode):
    """Returns (valid: bool, reason or None)."""
    if _CRYPTO_ERROR:
        raise CannotRun("cryptography is not importable (%s): Ed25519 cannot be checked" % _CRYPTO_ERROR)
    if len(sig) != 64:
        return False, "signature is not 64 bytes"
    if int.from_bytes(sig[32:], "little") >= _L:
        return False, "S >= L (RFC 8032 5.1.7)"
    R = ed_decode(sig[:32])
    if isinstance(R, str):
        return False, "R: " + R
    A = ed_decode(pub)
    if isinstance(A, str):
        return False, "public key: " + A
    if mode == "strict":
        if _pequal(_pmul(8, R), _IDENT):
            return False, "R has small order (strict mode)"
        ca = ed_point_class(pub)
        if ca != "prime-order":
            return False, "public key is %s (strict mode)" % ca
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
    except InvalidSignature:
        return False, "signature does not verify"
    except ValueError as e:
        return False, "public key rejected by the Ed25519 engine: %s" % e
    return True, None


# ======================================================================================= DER (X.690) parser
class Node(object):
    __slots__ = ("tag", "raw", "content", "_kids")

    def __init__(self, tag, raw, content):
        self.tag, self.raw, self.content, self._kids = tag, raw, content, None

    @property
    def constructed(self):
        return bool(self.tag & 0x20)

    def kids(self):
        if not self.constructed:
            raise Refusal("DER: primitive value used where a constructed one is required", "tag 0x%02x" % self.tag)
        if self._kids is None:
            self._kids = der_parse_all(self.content)
        return self._kids


def _der_tlv(buf, off):
    if off >= len(buf):
        raise Refusal("DER: truncated (no tag)")
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise Refusal("DER: high-tag-number form not used by any structure checked here")
    if off + 1 >= len(buf):
        raise Refusal("DER: truncated (no length)")
    lb = buf[off + 1]
    hdr = 2
    if lb < 0x80:
        ln = lb
    elif lb == 0x80:
        raise Refusal("DER: indefinite length (BER only)")
    elif lb == 0xFF:
        raise Refusal("DER: reserved length octet 0xFF")
    else:
        n = lb & 0x7F
        if n > 4:
            raise Refusal("DER: length of length > 4")
        if off + 2 + n > len(buf):
            raise Refusal("DER: truncated length")
        lbytes = buf[off + 2:off + 2 + n]
        if lbytes[0] == 0:
            raise Refusal("DER: non-minimal long-form length (leading zero)")
        ln = int.from_bytes(lbytes, "big")
        if ln < 0x80:
            raise Refusal("DER: long-form length for a value < 128")
        hdr = 2 + n
    end = off + hdr + ln
    if end > len(buf):
        raise Refusal("DER: value runs past the end of its container")
    return Node(tag, bytes(buf[off:end]), bytes(buf[off + hdr:end])), end


def der_parse_all(buf):
    out, off = [], 0
    while off < len(buf):
        n, off = _der_tlv(buf, off)
        out.append(n)
    return out


def der_parse_one(buf, what):
    n, end = _der_tlv(buf, 0)
    if end != len(buf):
        raise Refusal("DER: %d trailing byte(s) after %s" % (len(buf) - end, what))
    return n


def _expect(node, tag, what):
    if node.tag != tag:
        raise Refusal("DER: %s has tag 0x%02x, expected 0x%02x" % (what, node.tag, tag))
    return node


def der_int(node, what, tag=0x02):
    _expect(node, tag, what)
    c = node.content
    if not c:
        raise Refusal("DER: empty INTEGER (%s)" % what)
    if len(c) > 1 and ((c[0] == 0 and c[1] < 0x80) or (c[0] == 0xFF and c[1] >= 0x80)):
        raise Refusal("DER: non-minimal INTEGER (%s)" % what)
    return int.from_bytes(c, "big", signed=True)


def der_oid(node, what):
    _expect(node, 0x06, what)
    c = node.content
    if not c or c[-1] & 0x80:
        raise Refusal("DER: malformed OBJECT IDENTIFIER (%s)" % what)
    arcs, cur, start = [], 0, True
    for b in c:
        if start and b == 0x80:
            raise Refusal("DER: non-minimal OID sub-identifier (%s)" % what)
        cur = (cur << 7) | (b & 0x7F)
        start = False
        if not b & 0x80:
            arcs.append(cur)
            cur, start = 0, True
    first = arcs[0]
    head = [0, first] if first < 40 else ([1, first - 40] if first < 80 else [2, first - 80])
    return ".".join(str(a) for a in head + arcs[1:])


def der_octets(node, what):
    if node.tag == 0x24:
        raise Refusal("DER: constructed OCTET STRING (%s) is BER only" % what)
    return _expect(node, 0x04, what).content


def der_bool(node, what):
    _expect(node, 0x01, what)
    if node.content not in (b"\x00", b"\xff"):
        raise Refusal("DER: BOOLEAN must be 0x00 or 0xFF (%s)" % what)
    return node.content == b"\xff"


def der_set_ordered(node, what):
    """X.690 11.6: DER SET OF components in ascending order of their encodings."""
    kids = node.kids()
    enc = [k.raw for k in kids]
    for a, b in zip(enc, enc[1:]):
        n = max(len(a), len(b))
        if a.ljust(n, b"\x00") > b.ljust(n, b"\x00"):
            raise Refusal("DER: SET OF %s is not in DER order" % what)
    return kids


def der_alg_id(node, what):
    kids = _expect(node, 0x30, what).kids()
    if not 1 <= len(kids) <= 2:
        raise Refusal("DER: AlgorithmIdentifier with %d members (%s)" % (len(kids), what))
    oid = der_oid(kids[0], what)
    params = kids[1] if len(kids) == 2 else None
    return oid, params


# ===================================================================================== RFC 3161 / RFC 5652
def parse_tsr(raw, opts):
    """TimeStampResp (RFC 3161 2.4.2) -> dict. Raises Refusal on anything outside the grammar."""
    notes = []
    top = der_parse_one(raw, "TimeStampResp")
    kids = _expect(top, 0x30, "TimeStampResp").kids()
    if not 1 <= len(kids) <= 2:
        raise Refusal("TimeStampResp must have status and at most one token")
    si = _expect(kids[0], 0x30, "PKIStatusInfo").kids()
    if not si:
        raise Refusal("PKIStatusInfo is empty")
    status = der_int(si[0], "PKIStatus")
    if status not in (0, 1, 2, 3, 4, 5):
        raise Refusal("PKIStatus %d not understood (RFC 3161 2.4.2: clients MUST generate an error)" % status)
    rest = si[1:]
    if rest and rest[0].tag == 0x30:
        # statusString: PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String (RFC 3161 2.4.2, RFC 4210 5.1.1). Profile
        # 1.4.1 step 5 (bc5a138): imprint, genTime and accuracy come from the signed TSTInfo, "never other bytes of the
        # response, such as PKIStatusInfo.statusString". Vectors 50 and 51 fix one case outside the grammar: a
        # UTF8String whose bytes are not UTF-8 is not a reason to refuse (until 0.4.1 it was refused); it is listed in
        # notes. Anything else outside the grammar (an empty PKIFreeText, a member that is not a UTF8String) is not
        # fixed by the profile and is refused, closed by construction.
        texts = rest[0].kids()
        if not texts:
            raise Refusal("PKIStatusInfo.statusString is an empty PKIFreeText")
        bad_utf8 = False
        for t in texts:
            _expect(t, 0x0C, "PKIFreeText UTF8String")
            try:
                t.content.decode("utf-8")
            except UnicodeDecodeError:
                bad_utf8 = True
        rest = rest[1:]
        notes.append("PKIStatusInfo.statusString present (not read)" if not bad_utf8 else
                     "PKIStatusInfo.statusString holds a UTF8String that is not UTF-8 (RFC 4210 5.1.1): not read, "
                     "not a reason to refuse (profile 1.4.1 vectors 50, 51)")
    if rest and rest[0].tag == 0x03:
        c = rest[0].content                   # failInfo: PKIFailureInfo ::= BIT STRING { badAlg (0), ... }
        if not c or c[0] > 7 or (len(c) == 1 and c[0]) or (len(c) > 1 and c[-1] & ((1 << c[0]) - 1)):
            raise Refusal("DER: malformed BIT STRING (PKIStatusInfo.failInfo)")
        if len(c) > 1 and not (c[-1] >> c[0]) & 1:   # named bit list: trailing zero bits removed (X.690 11.2.2)
            raise Refusal("DER: BIT STRING with trailing zero bits (PKIStatusInfo.failInfo is a named bit list)")
        rest = rest[1:]
        notes.append("PKIStatusInfo.failInfo present")
    if rest:
        raise Refusal("PKIStatusInfo has unexpected members")
    tok = kids[1] if len(kids) == 2 else None
    if status in (0, 1) and tok is None:
        raise Refusal("PKIStatus granted but no TimeStampToken (RFC 3161 2.4.2)")
    if status not in (0, 1) and tok is not None:
        raise Refusal("TimeStampToken present with PKIStatus %d (RFC 3161 2.4.2)" % status)
    out = {"status": status, "token": None, "notes": notes}
    if tok is not None:
        out["token"] = parse_token(tok, opts, notes)
    return out


def parse_token(ci, opts, notes):
    kids = _expect(ci, 0x30, "ContentInfo").kids()
    if len(kids) != 2:
        raise Refusal("ContentInfo must have contentType and content")
    if der_oid(kids[0], "contentType") != OID_SIGNED_DATA:
        raise Refusal("TimeStampToken contentType is not id-signedData")
    wrap = _expect(kids[1], 0xA0, "ContentInfo.content").kids()
    if len(wrap) != 1:
        raise Refusal("ContentInfo.content [0] EXPLICIT must hold one SignedData")
    sd = _expect(wrap[0], 0x30, "SignedData").kids()
    if len(sd) < 3:
        raise Refusal("SignedData too short")
    version = der_int(sd[0], "SignedData.version")
    if version != 3:
        raise Refusal("SignedData.version %d; RFC 5652 5.1 requires 3 when eContentType is not id-data" % version)
    digest_algs = [der_alg_id(a, "digestAlgorithms") for a in der_set_ordered(_expect(sd[1], 0x31, "digestAlgorithms"), "digestAlgorithms")]
    eci = _expect(sd[2], 0x30, "EncapsulatedContentInfo").kids()
    if len(eci) != 2:
        raise Refusal("EncapsulatedContentInfo must carry eContent for a time-stamp token")
    if der_oid(eci[0], "eContentType") != OID_TSTINFO:
        raise Refusal("eContentType is not id-ct-TSTInfo")
    ew = _expect(eci[1], 0xA0, "eContent").kids()
    if len(ew) != 1:
        raise Refusal("eContent [0] EXPLICIT must hold one OCTET STRING")
    econtent = der_octets(ew[0], "eContent")
    i = 3
    certs, crls, signer_infos = [], None, None
    if i < len(sd) and sd[i].tag == 0xA0:
        certs = sd[i].kids()
        i += 1
    if i < len(sd) and sd[i].tag == 0xA1:
        crls = sd[i]
        i += 1
        notes.append("SignedData.crls present (not used)")
    if i < len(sd):
        signer_infos = der_set_ordered(_expect(sd[i], 0x31, "signerInfos"), "signerInfos")
        i += 1
    if i != len(sd):
        raise Refusal("SignedData has members after signerInfos")
    if signer_infos is None:
        # RFC 5652 5.1: signerInfos is not OPTIONAL. The profile README says the vector tokens are "structurally
        # valid but not signed"; they omit signerInfos. Accepted only in structural mode, and flagged.
        if opts["tokens"] != "structural":
            raise Refusal("SignedData has no signerInfos (RFC 5652 5.1: the field is required)")
        notes.append("X_TOKEN_NOT_CMS_CONFORMANT: SignedData has no signerInfos field (RFC 5652 5.1 requires it)")
    tst = parse_tstinfo(econtent, notes)
    return {"tst": tst, "econtent": econtent, "certs": certs, "signer_infos": signer_infos,
            "digest_algs": digest_algs}


def parse_tstinfo(raw, notes):
    """TSTInfo (RFC 3161 2.4.2). The eContent SHALL be DER: any non-DER encoding is refused."""
    kids = _expect(der_parse_one(raw, "TSTInfo"), 0x30, "TSTInfo").kids()
    if len(kids) < 5:
        raise Refusal("TSTInfo too short")
    if der_int(kids[0], "TSTInfo.version") != 1:
        raise Refusal("TSTInfo.version is not v1")
    policy = der_oid(kids[1], "TSTInfo.policy")
    mi = _expect(kids[2], 0x30, "messageImprint").kids()
    if len(mi) != 2:
        raise Refusal("MessageImprint must have hashAlgorithm and hashedMessage")
    halg, hparams = der_alg_id(mi[0], "messageImprint.hashAlgorithm")
    hparams_kind = "absent"
    if hparams is not None:
        if hparams.tag == 0x05 and not hparams.content:
            hparams_kind = "NULL"
        else:
            hparams_kind = "other"
    hashed = der_octets(mi[1], "hashedMessage")
    serial = der_int(kids[3], "TSTInfo.serialNumber")
    if serial < 0:
        notes.append("TSTInfo.serialNumber is negative")
    if serial.bit_length() > 160:
        notes.append("TSTInfo.serialNumber longer than 160 bits")
    _expect(kids[4], 0x18, "genTime")
    gen = parse_generalized_time(kids[4].content, "genTime")
    rest = kids[5:]
    accuracy = None
    ordering = False
    nonce = None
    tsa_name = None
    extensions = []
    if rest and rest[0].tag == 0x30:
        accuracy = _parse_accuracy(rest[0])
        rest = rest[1:]
    if rest and rest[0].tag == 0x01:
        ordering = der_bool(rest[0], "ordering")
        if not ordering:
            raise Refusal("TSTInfo.ordering encoded as FALSE: DER omits a DEFAULT value (X.690 11.5)")
        rest = rest[1:]
    if rest and rest[0].tag == 0x02:
        nonce = der_int(rest[0], "nonce")
        rest = rest[1:]
    if rest and rest[0].tag == 0xA0:
        tsa_name = rest[0]
        rest = rest[1:]
    if rest and rest[0].tag == 0xA1:
        for ext in rest[0].kids():
            ek = _expect(ext, 0x30, "Extension").kids()
            if not 2 <= len(ek) <= 3:
                raise Refusal("malformed TSTInfo extension")
            eoid = der_oid(ek[0], "extnID")
            crit = False
            if len(ek) == 3:
                crit = der_bool(ek[1], "critical")
                if not crit:
                    raise Refusal("Extension.critical encoded as FALSE (DER omits DEFAULT)")
            if crit:   # RFC 5280 4.2: unrecognised critical extension MUST be rejected
                raise Refusal("TSTInfo carries an unrecognised critical extension", eoid)
            extensions.append(eoid)
            notes.append("TSTInfo non-critical extension %s ignored (RFC 5280 4.2)" % eoid)
        rest = rest[1:]
    if rest:
        raise Refusal("TSTInfo has unexpected or out-of-order members")
    return {"policy": policy, "hash_alg": halg, "hash_params": hparams_kind, "hashed": hashed, "serial": serial,
            "gen": gen, "accuracy": accuracy, "ordering": ordering, "nonce": nonce,
            "tsa_name": tsa_name.raw if tsa_name is not None else None, "extensions": extensions}


def _parse_accuracy(node):
    secs, millis, micros = 0, 0, 0
    seen = []
    for k in node.kids():
        if k.tag == 0x02 and not seen:
            secs = der_int(k, "accuracy.seconds")
            if secs < 0:
                raise Refusal("accuracy.seconds negative")
            seen.append("s")
        elif k.tag == 0x80 and "ms" not in seen and "us" not in seen:
            millis = der_int(k, "accuracy.millis", tag=0x80)
            if not 1 <= millis <= 999:
                raise Refusal("accuracy.millis outside 1..999 (RFC 3161 2.4.2)")
            seen.append("ms")
        elif k.tag == 0x81 and "us" not in seen:
            micros = der_int(k, "accuracy.micros", tag=0x81)
            if not 1 <= micros <= 999:
                raise Refusal("accuracy.micros outside 1..999 (RFC 3161 2.4.2)")
            seen.append("us")
        else:
            raise Refusal("malformed Accuracy")
    return Fraction(secs) + Fraction(millis, 1000) + Fraction(micros, 1000000)


def imprint_status(tst, expected_digest):
    """'match' only if hashAlgorithm is SHA-256 with absent/NULL parameters and the 32 bytes are equal."""
    reasons = []
    if tst["hash_alg"] != OID_SHA256:
        reasons.append("hashAlgorithm %s is not SHA-256" % tst["hash_alg"])
    if tst["hash_params"] == "other":
        reasons.append("SHA-256 AlgorithmIdentifier with parameters other than NULL/absent")
    if tst["hashed"] != expected_digest:
        reasons.append("hashedMessage differs")
    known = HASH_OIDS.get(tst["hash_alg"])
    if known and len(tst["hashed"]) != hashlib.new(known).digest_size:
        reasons.append("X_IMPRINT_LENGTH_INCONSISTENT: %d bytes for %s (RFC 3161 2.4.1: length MUST match)"
                       % (len(tst["hashed"]), known))
    return ("match" if not reasons else "mismatch"), reasons


# ------------------------------------------------------------------------------- RFC 3161 TSA validation (pkix)
def _require_pkix():
    """TSA checks need `cryptography` with Certificate.verify_directly_issued_by (added in 40.0). Without it a chain
    could not be built and every token would read untrusted, so it is a check that cannot run (exit 74)."""
    if _CRYPTO_ERROR:
        raise CannotRun("cryptography is not importable: TSA certificates cannot be checked")
    from cryptography import x509
    if not hasattr(x509.Certificate, "verify_directly_issued_by"):
        import cryptography
        raise CannotRun("cryptography %s lacks Certificate.verify_directly_issued_by (40.0 or newer is needed for "
                        "TSA chains)" % cryptography.__version__)


def _load_cert(der):
    """DER X.509 certificate whose extensions parse. `cryptography` parses extensions on first access and raises
    ValueError, DuplicateExtension or UnsupportedGeneralNameType there; checked here once, so a certificate that is
    accepted never raises later (signer EKU and keyUsage, issuer basicConstraints, subjectKeyIdentifier lookups)."""
    from cryptography import x509
    errors = tuple(e for e in (ValueError, getattr(x509, "DuplicateExtension", None),
                               getattr(x509, "UnsupportedGeneralNameType", None)) if e is not None)
    try:
        cert = x509.load_der_x509_certificate(der)
        list(cert.extensions)
    except errors as e:
        raise ValueError(str(e) or type(e).__name__)
    return cert


def load_roots(path):
    _require_pkix()
    from cryptography import x509
    files = []
    if path and os.path.isdir(path):
        files = [os.path.join(path, f) for f in sorted(os.listdir(path))]
    elif path and os.path.isfile(path):
        files = [path]
    roots = []
    for f in files:
        try:
            with open(f, "rb") as fh:
                data = fh.read()
        except OSError as e:
            raise CannotRun("cannot read TSA root %s: %s" % (f, e))
        try:
            if b"-----BEGIN CERTIFICATE-----" in data:
                from cryptography.hazmat.primitives.serialization import Encoding
                roots.extend(_load_cert(c.public_bytes(Encoding.DER)) for c in x509.load_pem_x509_certificates(data))
            else:
                roots.append(_load_cert(data))
        except ValueError:
            continue
    if not roots:
        raise CannotRun("--tsa-roots %r holds no readable certificate" % path)
    return roots


# Profile 1.4.1 step 9: "RSA PKCS#1 v1.5 and ECDSA P-256/P-384 are required". Subject public key algorithms that can
# carry those keys (RFC 3279 2.3.1 rsaEncryption, RFC 5480 2.1.1 id-ecPublicKey); any other algorithm is `unsupported`.
KEY_ALGORITHMS = {"1.2.840.113549.1.1.1": "rsaEncryption", "1.2.840.10045.2.1": "id-ecPublicKey"}


def _spki_algorithm(cert_der):
    """Algorithm OID of a certificate's SubjectPublicKeyInfo (RFC 5280 4.1.2.7), read with this verifier's DER
    parser."""
    tbs = _expect(_expect(der_parse_one(cert_der, "Certificate"), 0x30, "Certificate").kids()[0], 0x30,
                  "tbsCertificate").kids()
    i = 6 if tbs and tbs[0].tag == 0xA0 else 5           # version [0] EXPLICIT is optional (RFC 5280 4.1)
    if len(tbs) <= i:
        raise Refusal("tbsCertificate has no subjectPublicKeyInfo")
    spki = _expect(tbs[i], 0x30, "subjectPublicKeyInfo").kids()
    if len(spki) != 2:
        raise Refusal("subjectPublicKeyInfo must hold algorithm and subjectPublicKey")
    return der_alg_id(spki[0], "subjectPublicKeyInfo.algorithm")[0]


def _cert_time_ok(cert, t):
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    nbs = Fraction(_days_from_civil(nb.year, nb.month, nb.day) * 86400 + nb.hour * 3600 + nb.minute * 60 + nb.second)
    nas = Fraction(_days_from_civil(na.year, na.month, na.day) * 86400 + na.hour * 3600 + na.minute * 60 + na.second)
    return nbs <= t <= nas


def _verify_sig(pub, sig, data, sig_alg_oid, digest_name):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    H = {"sha1": hashes.SHA1, "sha224": hashes.SHA224, "sha256": hashes.SHA256, "sha384": hashes.SHA384,
         "sha512": hashes.SHA512}
    rsa_oids = {"1.2.840.113549.1.1.1": None, "1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384",
                "1.2.840.113549.1.1.13": "sha512", "1.2.840.113549.1.1.5": "sha1", "1.2.840.113549.1.1.14": "sha224"}
    ec_oids = {"1.2.840.10045.4.3.2": "sha256", "1.2.840.10045.4.3.3": "sha384", "1.2.840.10045.4.3.4": "sha512",
               "1.2.840.10045.4.3.1": "sha224", "1.2.840.10045.4.1": "sha1"}
    if sig_alg_oid in rsa_oids:
        h = rsa_oids[sig_alg_oid] or digest_name
        if not isinstance(pub, rsa.RSAPublicKey) or h not in H:
            if not isinstance(pub, rsa.RSAPublicKey):
                return False, "RSA signature with a non-RSA key"
            return False, "RSA signature digest %s: %s" % (h, UNSUPPORTED_SUFFIX)
        pub.verify(sig, data, padding.PKCS1v15(), H[h]())
        return True, None
    if sig_alg_oid in ec_oids:
        h = ec_oids[sig_alg_oid]
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False, "ECDSA signature with a non-EC key"
        pub.verify(sig, data, ec.ECDSA(H[h]()))
        return True, None
    if sig_alg_oid == "1.3.101.112":
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            return False, "Ed25519 signature with a non-Ed25519 key"
        pub.verify(sig, data)
        return True, None
    return False, "signature algorithm %s: %s" % (sig_alg_oid, UNSUPPORTED_SUFFIX)


def verify_tsa(token, roots):
    """RFC 3161 2.3/2.4.2 + RFC 5652 5.4/11 + RFC 2634/5035 ESS signing-certificate + RFC 5280 path checks.
    Returns {"status": "valid"|"invalid"|"unsigned", "reasons": [...], ...}. Revocation is NOT checked."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID
    res = {"status": "invalid", "reasons": [], "classes": [], "revocation": "not checked"}

    def bad(cls, msg):
        res["reasons"].append(msg)
        res["classes"].append(cls)
    sis = token["signer_infos"]
    if not sis:
        res["status"] = "unsigned"
        bad("no_signer", "no SignerInfo")
        return res
    if len(sis) != 1:
        bad("failed", "%d SignerInfos; RFC 3161 2.4.2 allows only the TSA's signature" % len(sis))
        return res
    try:
        si = sis[0].kids()
        sv = der_int(si[0], "SignerInfo.version")
        sid = si[1]
        dalg, _ = der_alg_id(si[2], "SignerInfo.digestAlgorithm")
        idx = 3
        if idx >= len(si) or si[idx].tag != 0xA0:
            bad("failed", "no signedAttrs (RFC 3161 needs the ESS signing-certificate attribute)")
            return res
        sattrs_node = si[idx]
        idx += 1
        salg, _ = der_alg_id(si[idx], "SignerInfo.signatureAlgorithm")
        sig = der_octets(si[idx + 1], "SignerInfo.signature")
        if len(si) > idx + 3 or (len(si) == idx + 3 and si[idx + 2].tag != 0xA1):
            bad("failed", "SignerInfo has unexpected members")
            return res
        attrs = {}
        for a in der_set_ordered(sattrs_node, "signedAttrs"):
            ak = _expect(a, 0x30, "Attribute").kids()
            if len(ak) != 2:
                raise Refusal("malformed Attribute")
            aoid = der_oid(ak[0], "attrType")
            if aoid in attrs:
                bad("failed", "attribute %s appears twice (RFC 5652 11)" % aoid)
                return res
            attrs[aoid] = _expect(ak[1], 0x31, "attrValues").kids()
    except Refusal as e:
        bad("failed", "SignerInfo: %s" % e.reason)
        return res
    dname = HASH_OIDS.get(dalg)
    if dname not in ("sha1", "sha224", "sha256", "sha384", "sha512"):
        bad("unsupported", "digestAlgorithm %s not supported" % dalg)
        return res
    if dalg not in [d[0] for d in token["digest_algs"]]:
        bad("failed", "SignerInfo.digestAlgorithm not listed in SignedData.digestAlgorithms")
    ct = attrs.get(OID_CONTENT_TYPE)
    if not ct or len(ct) != 1 or der_oid(ct[0], "content-type attr") != OID_TSTINFO:
        bad("failed", "content-type attribute missing or not id-ct-TSTInfo (RFC 5652 11.1)")
    md = attrs.get(OID_MESSAGE_DIGEST)
    if not md or len(md) != 1:
        bad("failed", "message-digest attribute missing or multi-valued (RFC 5652 11.2)")
    elif der_octets(md[0], "message-digest") != hashlib.new(dname, token["econtent"]).digest():
        bad("failed", "message-digest attribute does not match the TSTInfo (RFC 5652 5.4)")
    certs = []
    for c in token["certs"]:
        if c.tag != 0x30:
            res["notes"] = res.get("notes", []) + ["non-X.509 certificate choice ignored"]
            continue
        try:
            certs.append(_load_cert(c.raw))
        except ValueError as e:
            bad("failed", "an embedded certificate does not parse: %s" % e)
    # signer identification (RFC 5652 5.3)
    signer = None
    try:
        if sv == 1:
            ias = _expect(sid, 0x30, "IssuerAndSerialNumber").kids()
            issuer_der, serial = ias[0].raw, der_int(ias[1], "serialNumber")
            for c in certs:
                if c.serial_number == serial and c.issuer.public_bytes() == issuer_der:
                    signer = c
        elif sv == 3:
            ski = _expect(sid, 0x80, "SubjectKeyIdentifier").content
            for c in certs:
                try:
                    if c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest == ski:
                        signer = c
                except x509.ExtensionNotFound:
                    pass
        else:
            bad("failed", "SignerInfo.version %d" % sv)
    except Refusal as e:
        bad("failed", "sid: %s" % e.reason)
    if signer is None:
        bad("no_signer", "signer certificate not found in the token")
        return res
    res["signer_subject"] = signer.subject.rfc4514_string()
    # ESS signing certificate (RFC 3161 2.4.2, RFC 2634 5.4, RFC 5035 / RFC 5816)
    ess = None
    if OID_SIGNING_CERT_V2 in attrs:
        ess = ("v2", attrs[OID_SIGNING_CERT_V2])
    elif OID_SIGNING_CERT in attrs:
        ess = ("v1", attrs[OID_SIGNING_CERT])
    if ess is None:
        bad("failed", "no ESS signing-certificate attribute (RFC 3161 2.4.2)")
    else:
        try:
            if len(ess[1]) != 1:
                raise Refusal("multi-valued signing-certificate attribute")
            sc = _expect(ess[1][0], 0x30, "SigningCertificate").kids()
            first = _expect(sc[0], 0x30, "certs").kids()[0].kids()
            j = 0
            halg = "sha1"
            if ess[0] == "v2":
                if first[0].tag == 0x30:
                    halg = HASH_OIDS.get(der_alg_id(first[0], "ESSCertIDv2.hashAlgorithm")[0])
                    j = 1
                else:
                    halg = "sha256"
            chash = der_octets(first[j], "certHash")
            from cryptography.hazmat.primitives.serialization import Encoding
            sder = signer.public_bytes(Encoding.DER)
            if halg is None or hashlib.new(halg, sder).digest() != chash:
                bad("failed", "ESSCertID%s certHash does not bind the signer certificate"
                                      % ("v2" if ess[0] == "v2" else ""))
            if len(first) > j + 1:
                iser = first[j + 1].kids()
                gnames = iser[0].kids()
                ok_issuer = any(g.tag == 0xA4 and g.kids()[0].raw == signer.issuer.public_bytes() for g in gnames)
                if not ok_issuer or der_int(iser[1], "issuerSerial.serial") != signer.serial_number:
                    bad("failed", "ESSCertID issuerSerial does not match the signer certificate")
            res["ess"] = "ESSCertIDv2" if ess[0] == "v2" else "ESSCertID"
        except (Refusal, IndexError) as e:
            bad("failed", "malformed signing-certificate attribute: %s" % getattr(e, "reason", e))
    # signature over DER(SET OF signedAttrs) (RFC 5652 5.4). Profile 1.4.1 step 9: "RSA PKCS#1 v1.5 and ECDSA
    # P-256/P-384 are required, RSASSA-PSS is optional"; `unsupported` "e.g. a curve other than P-256/P-384". Closed
    # list: only those two key types reach the signature check, anything else is `unsupported`.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    signed_bytes = b"\x31" + sattrs_node.raw[1:]
    # Closed list of key algorithms, read from the signer certificate's SubjectPublicKeyInfo by this verifier's own
    # DER parser: an algorithm outside it (Ed25519 included) is `unsupported` on every cryptography version, before the
    # engine is asked to load the key (cryptography >= 42 raises UnsupportedAlgorithm there, older versions ValueError).
    pub = None
    try:
        kalg = _spki_algorithm(signer.public_bytes(Encoding.DER))
    except Refusal as e:
        kalg = None
        bad("failed", "signer SubjectPublicKeyInfo: %s" % e.reason)
    if kalg is not None and kalg not in KEY_ALGORITHMS:
        bad("unsupported", "TSA key algorithm %s: %s" % (kalg, UNSUPPORTED_SUFFIX))
    elif kalg is not None:
        try:
            pub = signer.public_key()
        except Exception as e:                   # a key under a listed algorithm that the engine cannot load
            bad("failed", "TSA key does not parse: %s" % e)
    if pub is None:
        pass
    elif isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name not in ("secp256r1", "secp384r1"):
        bad("unsupported", "ECDSA curve %s: %s" % (pub.curve.name, UNSUPPORTED_SUFFIX))
    else:                                        # rsaEncryption or id-ecPublicKey on P-256/P-384: the listed set
        try:
            ok, why = _verify_sig(pub, sig, signed_bytes, salg, dname)
            if not ok:
                bad("unsupported" if why.endswith(UNSUPPORTED_SUFFIX) else "failed", why)
        except InvalidSignature:
            bad("failed", "TSA signature over signedAttrs does not verify")
        except UnsupportedAlgorithm as e:
            bad("unsupported", "TSA signature check: %s %s" % (UNSUPPORTED_SUFFIX, e))
        except Exception as e:  # malformed signature values, key/algorithm mismatches
            bad("failed", "TSA signature check failed: %s" % e)
    gen = token["tst"]["gen"]["instant"]
    # leaf: EKU (RFC 3161 2.3)
    try:
        eku = signer.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        ekus = [o.dotted_string for o in eku.value]
        if ekus != [OID_KP_TIMESTAMPING]:
            bad("failed", "EKU is %s, RFC 3161 2.3 requires only id-kp-timeStamping" % ekus)
        if not eku.critical:
            bad("failed", "EKU extension not critical (RFC 3161 2.3)")
    except x509.ExtensionNotFound:
        bad("failed", "no EKU extension (RFC 3161 2.3)")
    try:
        ku = signer.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        if not (ku.digital_signature or ku.content_commitment):
            bad("failed", "keyUsage allows neither digitalSignature nor nonRepudiation")
    except x509.ExtensionNotFound:
        pass
    if token["tst"]["tsa_name"] is not None:
        try:
            gn = der_parse_one(token["tst"]["tsa_name"], "tsa").kids()[0]
            if gn.tag != 0xA4 or gn.kids()[0].raw != signer.subject.public_bytes():
                bad("failed", "TSTInfo.tsa does not name the signer's subject (RFC 3161 2.4.2)")
        except (Refusal, IndexError) as e:
            bad("failed", "TSTInfo.tsa: %s" % getattr(e, "reason", "malformed GeneralName"))
    # path to a supplied root. Profile 1.4.1 step 9: "a chain of CA issuers reaching a supplied anchor, with the signer
    # and every issuer other than the anchor valid at genTime", and "a chain that reaches the anchor but fails a check
    # is `failed`"; no path to an anchor is `untrusted`. Issuer defects are collected and classed after the walk.
    root_ders = set()
    from cryptography.hazmat.primitives.serialization import Encoding
    for r in roots:
        root_ders.add(r.public_bytes(Encoding.DER))
    pool = certs + [r for r in roots]
    chain = [signer]
    cur = signer
    anchored = False
    issuer_defects = []
    if not _cert_time_ok(signer, gen):           # the signer, even when it is itself a supplied anchor
        bad("failed", "certificate %s not valid at genTime" % signer.subject.rfc4514_string())
    for _ in range(8):
        if cur.public_bytes(Encoding.DER) in root_ders:
            anchored = True
            break
        if cur is not signer and not _cert_time_ok(cur, gen):
            issuer_defects.append("certificate %s not valid at genTime" % cur.subject.rfc4514_string())
        parent = None
        for c in pool:
            if c.subject.public_bytes() == cur.issuer.public_bytes() and c is not cur:
                try:
                    cur.verify_directly_issued_by(c)
                    parent = c
                    if c.public_bytes(Encoding.DER) in root_ders:
                        break
                except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm):
                    continue                     # not this issuer; anything else (a missing API) is not swallowed
        if parent is None:
            break
        try:
            bc = parent.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            if not bc.ca:
                issuer_defects.append("issuer %s is not a CA" % parent.subject.rfc4514_string())
        except x509.ExtensionNotFound:
            issuer_defects.append("issuer %s has no basicConstraints" % parent.subject.rfc4514_string())
        try:
            pku = parent.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
            if not pku.key_cert_sign:
                issuer_defects.append("issuer %s keyUsage lacks keyCertSign" % parent.subject.rfc4514_string())
        except x509.ExtensionNotFound:
            pass
        chain.append(parent)
        cur = parent
    for msg in issuer_defects:   # 1.4.1 step 9 (bc5a138): "An issuer in the token that fails a check is `failed` whether
        bad("failed", msg)       # or not the chain reaches a supplied anchor" (vector 54; until 0.4.1, untrusted)
    if not anchored:
        bad("untrusted", "no path from the signer certificate to a supplied root")
    res["chain"] = [c.subject.rfc4514_string() for c in chain]
    if not res["reasons"]:
        res["status"] = "valid"
    return res


# ======================================================================================== input grammar
INPUT_MEMBERS = {"criteria_file_base64", "criteria_tsr_base64", "keys", "receipt", "receipt_tsr_base64",
                 "delivered_file_base64", "original_file_base64", "tsa_roots_base64"}
# Profile 1.4 step 9: "With anchors it is `verified` ..., `failed`, `untrusted`, `unsupported` ... or `no_signer`";
# without relying-party anchors (none supplied, or an empty list) `not_evaluated`. Profile 1.4.1 settles several
# defects: "`failed` if any check that can run fails; otherwise `no_signer`, then `unsupported`, then `untrusted`"
# (failed-first, the default). evaluability-first is the order reported for 1.4 by another verifier, kept for
# comparison only.
TSA_VALUES = ("verified", "failed", "untrusted", "unsupported", "no_signer", "not_evaluated")
TSA_PRECEDENCE = {"failed-first": ("failed", "no_signer", "unsupported", "untrusted"),
                  "evaluability-first": ("no_signer", "unsupported", "failed", "untrusted")}


def tsa_outcome(v, precedence):
    """verify_tsa() result -> one profile 1.4 `tsa_signature` value. failed-first (default): a check that could be
    run and failed decides, whatever could not be evaluated; untrusted only when everything else holds."""
    if v["status"] == "valid":
        return "verified"
    have = set(v["classes"])
    for c in TSA_PRECEDENCE[precedence]:
        if c in have:
            return c
    raise AssertionError("TSA result without a class: %r" % (v,))


def load_roots_b64(items):
    """inputs.tsa_roots_base64: a JSON array of base64 DER certificates (profile 1.4 vectors 31-36)."""
    if not isinstance(items, list):
        raise Refusal("inputs.tsa_roots_base64 is not an array")
    if not items:
        return []
    _require_pkix()
    out = []
    for i, it in enumerate(items):
        if not isinstance(it, str):
            raise Refusal("inputs.tsa_roots_base64[%d] is not a string" % i)
        der = b64_strict(it, "inputs.tsa_roots_base64[%d]" % i)
        try:
            cert = _load_cert(der)
        except ValueError:
            raise Refusal("inputs.tsa_roots_base64[%d] is not a DER X.509 certificate" % i)
        out.append(cert)
    return out
KEYFILE_MEMBERS = {"issuer", "keys", "version", "purpose", "also_published"}
KEY_MEMBERS = {"alg", "key_id", "public_key_base64", "status", "since"}
KEY_STATUSES = ("active", "test")
ENVELOPE_MEMBERS = {"receipt", "signature", "timestamp"}
SIGNATURE_MEMBERS = {"alg", "key_id", "value"}
TS_GRANTED = {"covers", "digest_sha256", "gen_time", "status", "tsa", "tsr_file"}
TS_NONE = {"reason", "status"}
RECEIPT_REQUIRED = {"canonicalization", "client_ref", "criteria", "files", "human_review", "independence",
                    "issued_utc", "issuer", "key_id", "notice", "parties", "receipt_id", "results", "revision",
                    "schema", "suite", "tools", "verdict"}
RECEIPT_OPTIONAL = {"payment"}
# Profile 1.4.1 (added at 06d3b94, outcome-neutral): optional body member `payment` = {protocol: "x402",
# scheme: "exact", network: "eip155:<chain id>", asset, payer, pay_to, amount, nonce} (optionally settlement_tx). bc5a138
# states the form (check_payment_form below) and "a member outside it changes no outcome" (vector 55): a payment outside
# the form is a note, not a refusal. `network` is a CAIP-2 chain id in the eip155 namespace: the EIP-155 chain id in
# decimal, no leading zeros, 1 to 32 digits.
PAYMENT_REQUIRED = {"protocol", "scheme", "network", "asset", "payer", "pay_to", "amount", "nonce"}
PAYMENT_OPTIONAL = {"settlement_tx"}
_EIP155 = re.compile(r"\Aeip155:[1-9][0-9]{0,31}\Z")
_DEC = re.compile(r"\A(0|[1-9][0-9]*)\Z")
CRITERIA_MEMBERS = {"commitment", "committed_at", "id", "sha256", "version"}
TOOLS_OPTIONAL = {"numbers_for_canonicalization"}   # bc5a138 vectors 52 and 57
FILE_REQUIRED = {"bytes", "name", "sha256"}
FILE_OPTIONAL = {"pages"}
RESULT_MEMBERS = {"finding", "id", "required", "result", "title"}
PARTY_MEMBERS = {"key_id", "name"}
_HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")


class Ctx(object):
    def __init__(self, opts):
        self.opts = opts
        self.notes = []

    def members(self, obj, path, required, optional=frozenset()):
        if not isinstance(obj, dict):
            raise Refusal("%s is not a JSON object" % path)
        missing = set(required) - set(obj)
        if missing:
            raise Refusal("%s lacks required member(s)" % path, ", ".join(sorted(missing)))
        unknown = set(obj) - set(required) - set(optional)
        if unknown:
            if self.opts["unknown_fields"] == "refuse":
                raise Refusal("unknown member(s) in %s" % path, ", ".join(sorted(unknown)))
            for u in sorted(unknown):
                self.notes.append("X_UNKNOWN_MEMBER: %s.%s (reported, not interpreted: --unknown-fields report)"
                                  % (path, u))


def _str(v, path, nullable=False, nonempty=False):
    if v is None and nullable:
        return None
    if not isinstance(v, str):
        raise Refusal("%s is not a string%s" % (path, " or null" if nullable else ""))
    if nonempty and v == "":
        raise Refusal("%s is empty" % path)
    return v


def _int(v, path, minimum=0):
    if isinstance(v, bool) or not isinstance(v, int):
        raise Refusal("%s is not a JSON integer" % path)
    if v < minimum:
        raise Refusal("%s is below %d" % (path, minimum))
    return v


def _hex64(v, path):
    if not isinstance(v, str) or not _HEX64.match(v):
        raise Refusal("%s is not 64 lowercase hexadecimal digits" % path)
    return v


def check_keyfile(ctx, kf):
    ctx.members(kf, "keys", {"issuer", "keys"}, KEYFILE_MEMBERS - {"issuer", "keys"})
    _str(kf["issuer"], "keys.issuer")
    for m in ("version", "purpose"):
        if m in kf:
            _str(kf[m], "keys." + m)
    if "also_published" in kf:
        if not isinstance(kf["also_published"], list) or not all(isinstance(x, str) for x in kf["also_published"]):
            raise Refusal("keys.also_published is not a list of strings")
    if not isinstance(kf["keys"], list) or not kf["keys"]:
        raise Refusal("keys.keys is not a non-empty list")
    table = {}
    for i, k in enumerate(kf["keys"]):
        p = "keys.keys[%d]" % i
        ctx.members(k, p, {"alg", "key_id", "public_key_base64", "status"}, {"since"})
        if k["alg"] != "Ed25519":
            raise Refusal("%s.alg is not Ed25519" % p)
        kid = _str(k["key_id"], p + ".key_id", nonempty=True)
        if kid in table:
            raise Refusal("duplicate key_id in the key file", kid)
        if k["status"] not in KEY_STATUSES:
            raise Refusal("%s.status %r is not one of %s" % (p, k["status"], KEY_STATUSES))
        if "since" in k:
            _str(k["since"], p + ".since")
        pub = b64_strict(k["public_key_base64"], p + ".public_key_base64")
        rejected = None
        if ctx.opts["key_rule"] == "refuse":            # 1.2.1 behaviour of this verifier
            if len(pub) != 32:
                raise Refusal("%s.public_key_base64 is not 32 bytes" % p)
            cls = ed_point_class(pub)
            if cls != "prime-order":
                if ctx.opts["ed25519"] == "strict" or cls not in ("small-order", "mixed-order"):
                    raise Refusal("%s public key is %s" % (p, cls), kid)
                ctx.notes.append("X_WEAK_KEY: %s is %s (accepted in --ed25519 rfc8032)" % (kid, cls))
        else:                                           # 1.3 key rule: a finding about the key list, not a refusal
            cls = ed_point_class(pub) if len(pub) == 32 else "not 32 bytes"
            if cls != "prime-order":
                rejected = cls
        table[kid] = {"pub": pub, "status": k["status"], "rejected": rejected}
    return table


def check_receipt_grammar(ctx, r):
    ctx.members(r, "receipt", RECEIPT_REQUIRED, RECEIPT_OPTIONAL)
    for m in ("client_ref", "issuer", "notice", "receipt_id"):
        _str(r[m], "receipt." + m)
    _str(r["key_id"], "receipt.key_id", nonempty=True)
    c = r["criteria"]
    ctx.members(c, "receipt.criteria", CRITERIA_MEMBERS)
    if c["commitment"] != "rfc3161":
        raise Refusal("receipt.criteria.commitment %r is not implemented (only rfc3161)" % (c["commitment"],))
    parse_rfc3339z(c["committed_at"], "receipt.criteria.committed_at")
    _str(c["id"], "receipt.criteria.id")
    _hex64(c["sha256"], "receipt.criteria.sha256")
    _str(c["version"], "receipt.criteria.version")
    f = r["files"]
    ctx.members(f, "receipt.files", {"remediated"}, {"original"})
    for name in ("remediated", "original"):
        if name in f:
            p = "receipt.files." + name
            ctx.members(f[name], p, FILE_REQUIRED, FILE_OPTIONAL)
            _int(f[name]["bytes"], p + ".bytes")
            _str(f[name]["name"], p + ".name")
            _hex64(f[name]["sha256"], p + ".sha256")
            if "pages" in f[name]:
                _int(f[name]["pages"], p + ".pages")
    h = r["human_review"]
    ctx.members(h, "receipt.human_review", {"scope", "status"})
    if not isinstance(h["scope"], list) or not all(isinstance(x, str) for x in h["scope"]):
        raise Refusal("receipt.human_review.scope is not a list of strings")
    _str(h["status"], "receipt.human_review.status")
    if r["independence"] not in ("independent", "self-checked"):
        raise Refusal("receipt.independence %r is neither independent nor self-checked" % (r["independence"],))
    parse_rfc3339z(r["issued_utc"], "receipt.issued_utc")
    p = r["parties"]
    ctx.members(p, "receipt.parties", {"checker", "producer"})
    for role in ("checker", "producer"):
        ctx.members(p[role], "receipt.parties." + role, PARTY_MEMBERS)
        _str(p[role]["key_id"], "receipt.parties.%s.key_id" % role, nullable=True)
        _str(p[role]["name"], "receipt.parties.%s.name" % role, nullable=True)
    if not isinstance(r["results"], list):
        raise Refusal("receipt.results is not a list")
    for i, res in enumerate(r["results"]):
        rp = "receipt.results[%d]" % i
        ctx.members(res, rp, RESULT_MEMBERS)
        for m in ("finding", "id", "result", "title"):
            _str(res[m], rp + "." + m)
        if not isinstance(res["required"], bool):
            raise Refusal("%s.required is not a boolean" % rp)
    _int(r["revision"], "receipt.revision")
    t = r["tools"]
    # 1.4.1 vectors 52 and 57 (bc5a138): a passing receipt whose tools carries numbers_for_canonicalization, an array
    # of numbers; the profile fixes its outcome (no problems), so it is listed in notes (until 0.4.1, refused). No
    # vector or sentence opens tools to other members: they stay unknown members (closed by construction).
    ctx.members(t, "receipt.tools", {"profile", "validator"}, TOOLS_OPTIONAL)
    if "numbers_for_canonicalization" in t:
        nums = t["numbers_for_canonicalization"]
        if not isinstance(nums, list) or any(isinstance(x, bool) or not isinstance(x, (int, float)) for x in nums):
            raise Refusal("receipt.tools.numbers_for_canonicalization is not an array of numbers")
        ctx.notes.append("receipt.tools.numbers_for_canonicalization not interpreted (profile 1.4.1 vectors 52, 57: "
                         "outcome-neutral)")
    _str(t["profile"], "receipt.tools.profile")
    _str(t["validator"], "receipt.tools.validator")
    _str(r["verdict"], "receipt.verdict")
    if "payment" in r:
        # 1.4.1 (bc5a138): "the payment form is stated and a member outside it changes no outcome" (vector 55); a
        # chain checker reports it as unsupported. Until 0.4.1 a payment outside the form was refused.
        try:
            check_payment_form(r["payment"])
            ctx.notes.append("receipt.payment present: inside the stated form; not checked against a chain "
                             "(outcome-neutral)")
        except Refusal as e:
            ctx.notes.append("receipt.payment outside the stated form (%s%s): unsupported, outcome-neutral"
                             % (e.reason, ": %s" % (e.detail,) if e.detail not in ("", None) else ""))


def check_payment_form(pm):
    """The stated payment form (README, check_payment.py of bc5a138): all members strings, network eip155: plus a
    decimal chain id, amount a decimal string, 0x-hex addresses and nonce, no other members."""
    if not isinstance(pm, dict):
        raise Refusal("receipt.payment is not a JSON object")
    missing, unknown = PAYMENT_REQUIRED - set(pm), set(pm) - PAYMENT_REQUIRED - PAYMENT_OPTIONAL
    if missing or unknown:
        raise Refusal("receipt.payment members", ", ".join(sorted(missing | unknown)))
    for m in sorted(pm):
        _str(pm[m], "receipt.payment." + m, nonempty=True)
    if pm["protocol"] != "x402" or pm["scheme"] != "exact":
        raise Refusal("receipt.payment %r/%r is not x402/exact" % (pm["protocol"], pm["scheme"]))
    if not _EIP155.match(pm["network"]):
        raise Refusal("receipt.payment.network %r is not eip155:<chain id>" % (pm["network"],))
    if not _DEC.match(pm["amount"]):
        raise Refusal("receipt.payment.amount is not a decimal string of atomic units")
    for m, n in (("asset", 20), ("payer", 20), ("pay_to", 20), ("nonce", 32), ("settlement_tx", 32)):
        if m in pm and not re.match(r"\A0x[0-9a-fA-F]{%d}\Z" % (2 * n), pm[m]):
            raise Refusal("receipt.payment.%s is not 0x-prefixed hex of %d bytes" % (m, n))


def check_envelope_timestamp(ctx, ts):
    """The issuer's form of the unsigned envelope.timestamp -> (granted?, parsed gen_time or None, digest well-formed?);
    Refusal outside it, except digest_sha256: README step 6, "the unsigned timestamp.digest_sha256 field is informative
    and never decides the outcome", so a digest_sha256 outside its form is a note, never a refusal (until 0.4.1,
    refused). The other members are not named by the profile and keep the issuer's form (closed by construction)."""
    if not isinstance(ts, dict):
        raise Refusal("envelope.timestamp is not an object or null")
    if ts.get("status") == "granted":
        ctx.members(ts, "envelope.timestamp", TS_GRANTED)
        if ts["covers"] != COVERS:
            raise Refusal("envelope.timestamp.covers names another object", ts["covers"])
        try:
            _hex64(ts["digest_sha256"], "envelope.timestamp.digest_sha256")
            digest_ok = True
        except Refusal as e:
            digest_ok = False
            ctx.notes.append("X_TIMESTAMP_METADATA_MALFORMED: %s (unsigned, informative, never decides the outcome: "
                             "profile step 6)" % e.reason)
        meta_gen = parse_generalized_time(_str(ts["gen_time"], "envelope.timestamp.gen_time"),
                                          "envelope.timestamp.gen_time")
        _str(ts["tsa"], "envelope.timestamp.tsa")
        _str(ts["tsr_file"], "envelope.timestamp.tsr_file")
        return True, meta_gen, digest_ok
    if ts.get("status") == "none":
        ctx.members(ts, "envelope.timestamp", TS_NONE)
        _str(ts["reason"], "envelope.timestamp.reason")
        return False, None, True
    raise Refusal("envelope.timestamp.status is neither granted nor none")


def check_step1(r):
    """README step 1: refuse an unknown schema, canonicalization or suite (before the 1.2 grammar applies)."""
    if not isinstance(r, dict):
        raise Refusal("receipt is not a JSON object")
    schema, canon, suite = r.get("schema"), r.get("canonicalization"), r.get("suite")
    if schema != SCHEMA:
        raise Refusal(STEP1_REASON, "schema %r" % (schema,))
    if canon != CANONICALIZATION:
        raise Refusal(STEP1_REASON, "canonicalization %r" % (canon,))
    if not isinstance(suite, dict) or suite != SUITE:
        raise Refusal(STEP1_REASON, "suite %r" % (suite,))


def _norm_name(s, mode):
    if s is None:
        return None
    if mode == "exact":
        return s
    return " ".join(unicodedata.normalize("NFKC", s).casefold().split())


def recompute_verdict(results):
    req = [x["result"] for x in results if x["required"]]
    if any(v == "fail" for v in req):
        return "fail"
    if all(v == "pass" for v in req):
        return "pass"
    return "incomplete"


# ============================================================================================ verification
def verify(inputs, options=None, keys_override=None):
    """inputs: the vector's `inputs` object (already strictly parsed). Returns a report dict; raises Refusal."""
    opts = dict(DEFAULT_OPTIONS)
    opts.update(options or {})
    for k, allowed in OPTION_VALUES.items():
        if opts[k] not in allowed:
            raise ValueError("option %s=%r" % (k, opts[k]))
    ctx = Ctx(opts)
    ext = set()
    details = {}
    if not isinstance(inputs, dict):
        raise Refusal("inputs is not a JSON object")
    ctx.members(inputs, "inputs", {"keys", "receipt"}, INPUT_MEMBERS - {"keys", "receipt"})
    env = inputs["receipt"]
    if not isinstance(env, dict):
        raise Refusal("inputs.receipt is not a JSON object")
    ctx.members(env, "envelope", {"receipt", "signature"}, {"timestamp"})
    r = env["receipt"]
    check_step1(r)
    check_receipt_grammar(ctx, r)
    sig = env["signature"]
    ctx.members(sig, "signature", SIGNATURE_MEMBERS)
    if sig["alg"] != "Ed25519":
        raise Refusal(STEP1_REASON, "signature.alg %r" % (sig["alg"],))
    _str(sig["key_id"], "signature.key_id", nonempty=True)
    sig_bytes = b64_strict(sig["value"], "signature.value")
    # envelope.timestamp is outside the signature: README step 6, "the unsigned timestamp.digest_sha256 field is
    # informative and never decides the outcome", and the token is read instead (R6). From 0.5.0 a digest_sha256
    # outside its form is X_TIMESTAMP_METADATA_MALFORMED plus a note, never a refusal (until 0.4.1, refused); the
    # other members keep the issuer's form.
    ts = env.get("timestamp")
    ts_declared = False
    ts_digest_ok = True
    meta_gen = None
    if ts is not None:
        ts_declared, meta_gen, ts_digest_ok = check_envelope_timestamp(ctx, ts)
    if keys_override is not None:
        keytable = check_keyfile(ctx, keys_override)
        ctx.notes.append("inputs.keys not used: the key file was supplied with --keys")
    else:
        keytable = check_keyfile(ctx, inputs["keys"])

    def opt_b64(name):
        v = inputs.get(name)
        if v is None:
            return None
        return b64_strict(v, "inputs." + name)

    crit_file = opt_b64("criteria_file_base64")
    crit_tsr = opt_b64("criteria_tsr_base64")
    rec_tsr = opt_b64("receipt_tsr_base64")
    delivered = opt_b64("delivered_file_base64")
    original = opt_b64("original_file_base64")
    roots = None
    cannot = []
    if opts["tokens"] == "pkix" or opts["tsa_roots"]:
        try:
            roots = load_roots(opts["tsa_roots"])
        except CannotRun as e:
            cannot.append("TSA validation: %s" % e)
    # Relying-party anchors for profile 1.4 `tsa_signature`: --tsa-roots when given, else inputs.tsa_roots_base64.
    anchors = None
    if opts["tsa_roots"]:
        anchors = roots
        if "tsa_roots_base64" in inputs:
            if roots is not None:
                load_roots_b64(inputs["tsa_roots_base64"])       # grammar still closed; the value is not used
            ctx.notes.append("inputs.tsa_roots_base64 not used: anchors were supplied with --tsa-roots")
    elif "tsa_roots_base64" in inputs:
        try:
            anchors = load_roots_b64(inputs["tsa_roots_base64"]) or None
        except CannotRun as e:
            cannot.append("TSA validation: %s" % e)
        if inputs["tsa_roots_base64"] == []:
            ctx.notes.append("inputs.tsa_roots_base64 is empty: read as no relying-party anchors (not_evaluated)")
    crit_parsed = parse_tsr(crit_tsr, opts) if crit_tsr is not None else None
    rec_parsed = parse_tsr(rec_tsr, opts) if rec_tsr is not None else None
    for nm, prs in (("criteria token", crit_parsed), ("record token", rec_parsed)):
        if prs:
            for n in prs["notes"]:
                ctx.notes.append("%s: %s" % (nm, n))
                if n.startswith("X_"):
                    ext.add(n.split(":")[0])

    problems, warnings = set(), set()

    # ---- step 2: signature
    canon = jcs(r)
    receipt_digest = hashlib.sha256(canon).digest()
    details["canonical_receipt_sha256"] = receipt_digest.hex()
    used_kid = sig["key_id"] if opts["key_id_source"] == "envelope" else r["key_id"]
    details["verification_key_id"] = used_kid
    if sig["key_id"] != r["key_id"]:
        ext.add("X_KEY_ID_SPLIT")
        ctx.notes.append("X_KEY_ID_SPLIT: signature.key_id %r != receipt.key_id %r (README step 2 names `key_id`)"
                         % (sig["key_id"], r["key_id"]))
    entry = keytable.get(used_kid)
    rejected_keys = sorted(k for k, v in keytable.items() if v.get("rejected"))
    if rejected_keys:
        details["rejected_keys"] = {k: keytable[k]["rejected"] for k in rejected_keys}
    details["key_source"] = ("--keys (supplied by the relying party)" if keys_override is not None
                             else "inputs.keys (travels with the record: not a trust anchor)")
    if keys_override is None:
        ext.add("X_KEY_FROM_INPUT")
    if entry is not None:
        details["signer_key_status"] = entry["status"]
        if entry["status"] == "test":
            ext.add("X_TEST_KEY")
    key_rejected = False
    if opts["key_rule"] == "all-keys" and rejected_keys:
        problems.add("KEY_REJECTED")
    if entry is None:
        sig_ok, why = False, "key_id %r not in the key file" % used_kid
    elif entry.get("rejected"):                 # 1.3 step 2: "no signature check is run"
        sig_ok, why, key_rejected = False, "KEY_REJECTED: key %r is %s" % (used_kid, entry["rejected"]), True
        problems.add("KEY_REJECTED")
    else:
        try:
            sig_ok, why = ed25519_verify(entry["pub"], canon, sig_bytes, opts["ed25519"])
        except CannotRun as e:
            sig_ok, why = None, str(e)
            cannot.append("signature: %s" % e)
    if opts["key_rule"] == "signer" and any(k != used_kid for k in rejected_keys):
        ext.add("X_UNUSED_KEY_REJECTED")
    if sig_ok is False and not key_rejected:
        problems.add("SIGNATURE_INVALID")
    if sig_ok is False:
        details["signature_reason"] = why
    if opts["key_id_agreement"] == "signature-invalid" and sig["key_id"] != r["key_id"]:
        # 1.3 step 2: "The envelope's `signature.key_id` must equal it, else `SIGNATURE_INVALID`"
        problems.add("SIGNATURE_INVALID")
        details["signature_reason"] = ((why + "; ") if sig_ok is False else "") + \
            "signature.key_id %r differs from the signed receipt.key_id %r" % (sig["key_id"], r["key_id"])
        if sig_ok is True:
            sig_ok = False

    # ---- step 3: delivered / original files (no problem code in the profile: extension codes only)
    files_out = {}
    for nm, data in (("remediated", delivered), ("original", original)):
        if data is None:
            files_out[nm] = "not-supplied"
            continue
        fr = r["files"].get(nm)
        if fr is None:
            files_out[nm] = "not-in-record"
            ext.add("X_FILE_NOT_IN_RECORD")
            continue
        okh = hashlib.sha256(data).hexdigest() == fr["sha256"]
        okb = len(data) == fr["bytes"]
        files_out[nm] = "match" if okh and okb else "mismatch"
        if not okh:
            ext.add("X_%s_FILE_HASH_MISMATCH" % nm.upper())
        if okh and not okb:
            ext.add("X_%s_FILE_BYTES_MISMATCH" % nm.upper())

    # ---- step 4: criteria document
    crit_hash = "not-supplied"
    if crit_file is not None:
        crit_hash = "match" if hashlib.sha256(crit_file).hexdigest() == r["criteria"]["sha256"] else "mismatch"
        if crit_hash == "mismatch":
            problems.add("CRITERIA_HASH_MISMATCH")
        else:
            mism = _correspondence(ctx, crit_file, r["results"], opts["correspondence"])
            if mism:
                problems.add("CRITERIA_RESULTS_MISMATCH")
                details["criteria_results_mismatch"] = mism
    result_ids = [x["id"] for x in r["results"]]
    if len(set(result_ids)) != len(result_ids):
        ext.add("X_DUPLICATE_RESULT_ID")

    # ---- TSA validation (pkix only)
    def token_usable(parsed, label):
        if parsed is None or parsed["token"] is None:
            return None
        tok = parsed["token"]
        if opts["tokens"] == "pkix":
            if roots is None:            # cannot run: the token is not evidence of time, and the report says why
                ext.add("X_TSA_UNVERIFIED")
                return None
            v = verify_tsa(tok, roots)
            details[label + "_tsa"] = v
            if v["status"] != "valid":
                ext.add("X_TSA_UNVERIFIED")
                return None
        return tok

    crit_tok = token_usable(crit_parsed, "criteria_token")
    rec_tok = token_usable(rec_parsed, "record_token")

    # ---- profile 1.4 step 9: authority signature, one key per token present; never changes another member
    tsa_sig = {}
    for key, label, prs in (("criteria", "criteria_token", crit_parsed), ("receipt", "record_token", rec_parsed)):
        if prs is None or prs["token"] is None:
            continue
        if anchors is None:
            tsa_sig[key] = "not_evaluated"
            continue
        v = details.get(label + "_tsa") if anchors is roots else None
        if v is None:
            v = verify_tsa(prs["token"], anchors)
            details[label + "_tsa_signature"] = v
        tsa_sig[key] = tsa_outcome(v, opts["tsa_precedence"])
    if crit_parsed is not None and crit_parsed["token"] is None:
        ext.add("X_CRITERIA_TOKEN_NOT_GRANTED")
    if rec_parsed is not None and rec_parsed["token"] is None:
        ext.add("X_RECORD_TOKEN_NOT_GRANTED")

    # ---- step 6: record token
    rec_ts = "none"
    covering = None
    if rec_parsed is not None and rec_parsed["token"] is not None and not ts_declared:
        ext.add("X_TOKEN_SUPPLIED_RECORD_DECLARES_NONE")
    if rec_parsed is not None and rec_parsed["token"] is not None:      # R6: the token, never the unsigned envelope
        st, why_r = imprint_status(rec_parsed["token"]["tst"], receipt_digest)
        rec_ts = "imprint_match" if st == "match" else "imprint_mismatch"
        details["record_token_genTime"] = rec_parsed["token"]["tst"]["gen"]["text"]
        if why_r:
            details["record_token_imprint"] = why_r
            for w in why_r:
                if w.startswith("X_"):
                    ext.add(w.split(":")[0])
        if st == "match" and rec_tok is not None:
            covering = rec_tok["tst"]
        if ts_declared and ((ts_digest_ok and ts["digest_sha256"] != rec_parsed["token"]["tst"]["hashed"].hex()) or
                            meta_gen["instant"] != rec_parsed["token"]["tst"]["gen"]["instant"]):
            ext.add("X_TIMESTAMP_METADATA_DISAGREES")
    if ts_declared and ts_digest_ok and ts["digest_sha256"] != receipt_digest.hex():
        ext.add("X_TIMESTAMP_METADATA_DISAGREES")

    # ---- step 5: criteria commitment
    issued = parse_rfc3339z(r["issued_utc"], "issued_utc")
    committed_at = parse_rfc3339z(r["criteria"]["committed_at"], "committed_at")
    crit_digest = bytes.fromhex(r["criteria"]["sha256"])
    commit_time, commit_acc, commit_tst = None, None, None
    if crit_parsed is not None and crit_parsed["token"] is not None:
        st, why_c = imprint_status(crit_parsed["token"]["tst"], crit_digest)
        details["criteria_token_genTime"] = crit_parsed["token"]["tst"]["gen"]["text"]
        if st != "match":
            problems.add("CRITERIA_TIMESTAMP_MISMATCH")
            details["criteria_token_imprint"] = why_c
            for w in why_c:
                if w.startswith("X_"):
                    ext.add(w.split(":")[0])
        elif crit_tok is not None:
            commit_tst = crit_tok["tst"]
    if commit_tst is not None:
        commit_time = commit_tst["gen"]["instant"]
        commit_acc = commit_tst["accuracy"]
        if not _times_agree(committed_at, commit_tst["gen"], opts["time_agreement"]):
            problems.add("CRITERIA_TIME_MISMATCH")
    else:
        warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")
        commit_time = committed_at["instant"]
    if covering is not None:
        ref_time = covering["gen"]["instant"]
        ref_src = "record token genTime"
        if opts["reference_time"] == "earlier" and issued["instant"] < ref_time:
            ref_time, ref_src = issued["instant"], "issued_utc (earlier than the covering token)"
    else:
        ref_time, ref_src = issued["instant"], "issued_utc"
    auth = {}
    for label, prs, used in (("criteria_token", crit_parsed, commit_tst is not None),
                             ("record_token", rec_parsed, covering is not None)):
        if prs is None or prs["token"] is None:
            auth[label] = "not supplied"
        elif opts["tokens"] == "structural":
            auth[label] = "unauthenticated (--tokens structural: TSA signature not checked)"
        else:
            auth[label] = details.get(label + "_tsa", {}).get("status", "not checked")
        if used and opts["tokens"] == "structural":
            ext.add("X_TSA_NOT_VERIFIED")
    details["token_authentication"] = auth
    if "X_TSA_NOT_VERIFIED" in ext:
        ctx.notes.append("X_TSA_NOT_VERIFIED: a genTime was taken from a token whose TSA signature was not checked; "
                         "the profile fields follow the profile, exit 0 needs --tokens pkix --tsa-roots")
    details["commitment_time"] = fmt_instant(commit_time)
    details["reference_time"] = fmt_instant(ref_time)
    details["reference_source"] = ref_src
    if opts["accuracy"] == "widen":
        # 1.3 step 5: "A token's stated `accuracy` widens its time against 'committed before'; a token stating none
        # is taken at its genTime; `ordering` is ignored". The commitment is taken at its latest (genTime +
        # accuracy) and the reference at its earliest: issued_utc, or a covering token's genTime - accuracy, whichever
        # is earlier (with no stated accuracy this is exactly the earlier-of rule above).
        acc_c = (commit_tst["accuracy"] or Fraction(0)) if commit_tst is not None else Fraction(0)
        commit_hi = commit_time + acc_c
        if covering is not None:
            acc_r = covering["accuracy"] or Fraction(0)
            lo_tok = covering["gen"]["instant"] - acc_r
            if opts["reference_time"] == "earlier" and issued["instant"] < lo_tok:
                ref_lo, ref_src = issued["instant"], "issued_utc (earlier than the covering token's earliest time)"
            else:
                ref_lo = lo_tok
                ref_src = "record token genTime" + (" - accuracy" if acc_r else "")
        else:
            ref_lo = issued["instant"]
        details["reference_source"] = ref_src
        details["commitment_time_latest"] = fmt_instant(commit_hi)
        details["reference_time_earliest"] = fmt_instant(ref_lo)
        before = "yes" if commit_hi < ref_lo else "no"
    else:
        before = "yes" if commit_time < ref_time else "no"
    order = _provable_order(commit_tst, covering if ref_src.startswith("record token") else None, commit_time,
                            ref_time)
    details["ordering_provable_under_accuracy"] = order
    if order != "yes" and before == "yes":
        ext.add("X_ORDER_NOT_PROVABLE_UNDER_ACCURACY")
    if opts["accuracy"] == "interval" and before == "yes" and order != "yes":
        before = "undetermined"
    if before == "no":
        problems.add("CRITERIA_COMMITTED_AFTER_CHECK")

    # ---- step 7: verdict
    for x in r["results"]:
        if x["result"] not in VOCAB:
            problems.add("RESULT_VOCABULARY")
    recomputed = recompute_verdict(r["results"])
    if recomputed != r["verdict"]:
        problems.add("VERDICT_MISMATCH")
    if not any(x["required"] for x in r["results"]):
        ext.add("X_NO_REQUIRED_CRITERION")

    # ---- independence (property 3, step 8)
    parties = r["parties"]
    ck, pk = parties["checker"]["key_id"], parties["producer"]["key_id"]
    signer_pub = entry["pub"] if entry else None
    ck_pub = keytable.get(ck, {}).get("pub") if ck else None
    pk_pub = keytable.get(pk, {}).get("pub") if pk else None
    if ck is None or ck_pub is None or signer_pub is None or ck_pub != signer_pub:
        problems.add("CHECKER_NOT_SIGNER")
    if r["key_id"] != used_kid and (keytable.get(r["key_id"], {}).get("pub") != signer_pub):
        ext.add("X_RECEIPT_KEY_ID_NOT_SIGNER")
    collision = pk is not None and (pk == ck or pk == used_kid or (pk_pub is not None and any(
        q is not None and ed_same_key(pk_pub, q) for q in (ck_pub, signer_pub))))
    if collision:
        problems.add("KEY_COLLISION")
    if r["independence"] == "self-checked":
        warnings.add("SELF_CHECKED")
    cn = _norm_name(parties["checker"]["name"], opts["name_compare"])
    pn = _norm_name(parties["producer"]["name"], opts["name_compare"])
    same_name = cn is not None and pn is not None and cn == pn
    pname = parties["producer"]["name"]
    undeclared = (pname is None or pname.strip() == "") and pk is None
    derived = "undeclared" if undeclared else ("self-checked" if (same_name or collision) else "independent")
    details["independence_derived"] = derived
    if opts["independence_rule"] == "derived":
        # 1.3 step 8: "a stated `independence` that differs from the derived one is also `INDEPENDENCE_INCONSISTENT`"
        if r["independence"] != derived:
            problems.add("INDEPENDENCE_INCONSISTENT")
    elif r["independence"] == "independent" and (same_name or collision):
        problems.add("INDEPENDENCE_INCONSISTENT")
    if opts["name_compare"] == "exact" and not same_name and cn is not None and pn is not None and \
            _norm_name(cn, "normalized") == _norm_name(pn, "normalized"):
        ext.add("X_NAMES_EQUAL_AFTER_NORMALIZATION")
    if undeclared:                     # 1.3: "follows the parties block (no producer named), whatever the record states"
        warnings.add("PRODUCER_UNDECLARED")

    for n in ctx.notes:                                   # R11: every X_ note is also an extension code
        if n.startswith("X_"):
            ext.add(n.split(":")[0])
    blocks = {"X_KEY_FROM_INPUT", "X_TEST_KEY", "X_TSA_NOT_VERIFIED", "X_FILE_NOT_IN_RECORD",
              "X_REMEDIATED_FILE_HASH_MISMATCH", "X_ORIGINAL_FILE_HASH_MISMATCH",
              "X_REMEDIATED_FILE_BYTES_MISMATCH", "X_ORIGINAL_FILE_BYTES_MISMATCH", "X_WEAK_KEY",
              "X_UNUSED_KEY_REJECTED"}
    if opts["key_id_agreement"] in ("require", "signature-invalid"):
        blocks |= {"X_KEY_ID_SPLIT", "X_RECEIPT_KEY_ID_NOT_SIGNER"}
    local_blocks = sorted(ext & blocks)
    assert problems <= PROBLEM_CODES and warnings <= WARNING_CODES
    accepted = sig_ok is True and not problems and before != "undetermined" and not cannot
    report = {
        "signature_valid": sig_ok,
        "criteria_hash": crit_hash,
        "independence": r["independence"],
        "problem_codes": sorted(problems),
        "warning_codes": sorted(warnings),
        "receipt_timestamp": rec_ts,
        "verdict_recomputed": recomputed,
        "verdict_stated": r["verdict"],
        "criteria_committed_before_check": before,
        "accepted_as_stated": accepted,
        "results_presented": sig_ok is True,
        "cannot_run": cannot,
        "files": files_out,
        "extension_codes": sorted(ext),
        "local_blocks": local_blocks,
        "notes": ctx.notes,
        "details": details,
        "options": {k: v for k, v in opts.items() if k != "tsa_roots"},
    }
    if tsa_sig:
        report["tsa_signature"] = tsa_sig
    return report


def _times_agree(claim, gen, mode):
    if mode == "exact":
        return claim["instant"] == gen["instant"]
    q = Fraction(1, 10 ** claim["digits"])
    g = gen["instant"]
    return claim["instant"] == (g // q) * q


def _provable_order(commit_tst, ref_tst, commit_time, ref_time):
    """RFC 3161 2.4.2: two tokens are ordered only if |difference| > sum of accuracies, unless both carry
    ordering TRUE and come from the same TSA. A time with no accuracy information (a JSON self-claim, or a token
    without the accuracy field) has an unknown error bound: the order is then 'not provable' unless the ordering
    clause applies."""
    if commit_tst is not None and ref_tst is not None and commit_tst["ordering"] and ref_tst["ordering"] and \
            commit_tst["tsa_name"] is not None and commit_tst["tsa_name"] == ref_tst["tsa_name"]:
        return "yes" if commit_time < ref_time else "no"
    acc_c = commit_tst["accuracy"] if commit_tst is not None else Fraction(0)
    acc_r = ref_tst["accuracy"] if ref_tst is not None else Fraction(0)
    if commit_tst is not None and acc_c is None:
        return "not-provable (criteria token has no accuracy field)"
    if ref_tst is not None and acc_r is None:
        return "not-provable (record token has no accuracy field)"
    return "yes" if ref_time - commit_time > acc_c + acc_r else "not-provable (difference <= sum of accuracies)"


def _correspondence(ctx, crit_bytes, results, mode):
    """README step 4: 'check the results correspond to the criteria'. The criteria document format is not
    defined by the profile; every member other than `criteria`, and every member of a criterion other than
    `id`, `required` and `title`, is listed in notes as not interpreted."""
    try:
        doc = strict_json_loads(crit_bytes)
    except Refusal as e:
        return ["criteria document is not strict JSON: %s" % e.reason]
    if not isinstance(doc, dict) or not isinstance(doc.get("criteria"), list):
        return ["criteria document has no `criteria` list"]
    for m in sorted(set(doc) - {"criteria"}):
        ctx.notes.append("criteria document member %r not interpreted" % m)
    crit = {}
    out = []
    for i, c in enumerate(doc["criteria"]):
        if not isinstance(c, dict) or not isinstance(c.get("id"), str) or not isinstance(c.get("required"), bool):
            out.append("criteria[%d] lacks a string id or boolean required" % i)
            continue
        for m in sorted(set(c) - {"id", "required", "title"}):
            ctx.notes.append("criteria document member criteria[%d].%s not interpreted" % (i, m))
        if c["id"] in crit:
            out.append("criteria id %r appears twice" % c["id"])
        crit[c["id"]] = c
    seen = set()
    for x in results:
        if x["id"] in seen:
            out.append("result id %r appears twice" % x["id"])
        seen.add(x["id"])
        c = crit.get(x["id"])
        if c is None:
            out.append("result %r is not a criterion" % x["id"])
            continue
        if c["required"] != x["required"]:
            out.append("result %r required=%s, criteria say %s" % (x["id"], x["required"], c["required"]))
        if mode == "strict" and c.get("title") != x["title"]:
            out.append("result %r title differs from the criteria" % x["id"])
    for cid in crit:
        if cid not in seen:
            out.append("criterion %r has no result" % cid)
    return out


# ================================================================================================= CLI
VECTOR_META = {"description", "expected", "inputs", "license", "spec", "title", "vector", "warning",
               "contributed_by", "expected_is", "source", "pins", "name", "test_key", "kills",
               "expected_extensions", "reading", "difference", "expected_1_2_1", "tsa_signature_accepted"}
COMPARED = ("criteria_committed_before_check", "criteria_hash", "independence", "problem_codes",
            "receipt_timestamp", "signature_valid", "verdict_recomputed", "verdict_stated", "warning_codes")


def run_vector(doc, options=None, keys_override=None):
    """A vector-layout document -> (report, comparison or None)."""
    if not isinstance(doc, dict):
        raise Refusal("document is not a JSON object")
    if "inputs" in doc:
        unknown = set(doc) - VECTOR_META
        if unknown:
            raise Refusal("unknown member(s) in the vector document", ", ".join(sorted(unknown)))
        inputs = doc["inputs"]
    else:
        inputs = doc
    try:
        rep = verify(inputs, options, keys_override)
    except Refusal as e:
        rep = {"refused": True, "reason": e.reason, "reason_detail": e.detail}
    accepted = tsa_accepted(doc.get("tsa_signature_accepted")) if isinstance(doc, dict) and "inputs" in doc else {}
    cmp_ = compare(rep, doc.get("expected"), accepted) if isinstance(doc.get("expected"), dict) else None
    ee = doc.get("expected_extensions")
    if cmp_ is not None and isinstance(ee, dict):     # this verifier's own (non-profile) codes, new vectors only
        have = set(rep.get("extension_codes", []))
        for k in ("include", "exclude"):
            want = set(ee.get(k, []))
            ok = want <= have if k == "include" else not (want & have)
            cmp_["fields"].append({"field": "extension_codes(%s)" % k, "expected": sorted(want),
                                   "ours": sorted(have), "agree": ok})
        cmp_["agree"] = all(r["agree"] for r in cmp_["fields"])
    return rep, cmp_


def run_vector_bytes(raw, options=None, keys_override=None, module_json=json):
    """For a whole vector FILE: if the file itself is outside the grammar (duplicate member, lone surrogate, ...),
    the verdict is a refusal; `expected` is then read with the stdlib parser only to compare."""
    try:
        doc = strict_json_loads(raw)
    except Refusal as e:
        rep = {"refused": True, "reason": e.reason, "reason_detail": e.detail}
        try:
            exp = module_json.loads(raw.decode("utf-8", "surrogatepass")).get("expected")
        except Exception:
            exp = None
        return rep, (compare(rep, exp) if isinstance(exp, dict) else None)
    return run_vector(doc, options, keys_override)


def tsa_accepted(v):
    """Profile 1.4.1 vector member `tsa_signature_accepted` (vector 40): per token, further values that also conform.
    Absent = none. Closed grammar: an object with keys criteria/receipt, each a non-empty array of distinct values."""
    if v is None:
        return {}
    if not isinstance(v, dict) or not v or set(v) - {"criteria", "receipt"}:
        raise Refusal("tsa_signature_accepted is not an object with keys criteria and/or receipt")
    for t, vals in v.items():
        if not isinstance(vals, list) or not vals or len(set(map(repr, vals))) != len(vals) \
                or any(not isinstance(x, str) or x not in TSA_VALUES for x in vals):
            raise Refusal("tsa_signature_accepted.%s is not a non-empty array of distinct step-9 values" % t)
    return v


def compare(rep, exp, accepted=None):
    accepted = accepted or {}
    rows = []
    for k in sorted(exp):
        mine = rep.get(k, "<absent>")
        theirs = exp[k]
        if k in ("problem_codes", "warning_codes") and isinstance(theirs, list) and isinstance(mine, list):
            ok = set(mine) == set(theirs) and len(set(theirs)) == len(theirs)
        elif k == "reason" and rep.get("refused"):
            ok = mine == theirs
        elif k == "tsa_signature":
            # 1.4: "an absent field reads the same" as not_evaluated, key by key
            mine = rep.get("tsa_signature", {}) if not rep.get("refused") else "<absent>"
            ok = isinstance(theirs, dict) and isinstance(mine, dict) and set(theirs) <= {"criteria", "receipt"} \
                and all(theirs[t] in TSA_VALUES for t in theirs) \
                and all(mine.get(t, "not_evaluated") == theirs[t] or mine.get(t, "not_evaluated") in accepted.get(t, ())
                        for t in theirs) \
                and all(mine[t] == "not_evaluated" for t in set(mine) - set(theirs))
        else:
            ok = mine == theirs and type(mine) == type(theirs)
        rows.append({"field": k, "expected": theirs, "ours": mine, "agree": ok})
    return {"agree": all(r["agree"] for r in rows), "fields": rows}


USAGE = """usage: war_verify.py [options] FILE.json
  FILE is a vector-layout document ({"inputs": {...}, "expected": {...}}) or a bare inputs object.
  --vector                     compare with the document's "expected" object (exit 0 agree, 3 disagree)
  --keys KEYFILE.json          use this key file instead of inputs.keys
  defaults follow profile 1.4.1 (maximusrufus/work-acceptance-record@bc5a138; steps 1-8 as in 1.3)
  --profile 1.2.1              this verifier's profile 1.2.1 readings (key-id-source envelope, reference-time
                               covering-token, accuracy ignore, key-id-agreement require, key-rule refuse,
                               independence-rule stated-independent); a switch given explicitly overrides it
  --key-id-source receipt|envelope   (default receipt)
  --reference-time earlier|covering-token   (default earlier)
  --time-agreement truncate|exact     (default truncate)
  --accuracy widen|ignore|interval    (default widen)
  --tokens structural|pkix            (default structural)
  --tsa-roots DIR_OR_FILE             relying-party anchors for `tsa_signature` (1.4 step 9), replacing a vector's
                                      inputs.tsa_roots_base64; required with --tokens pkix
  --tsa-precedence failed-first|evaluability-first   (default failed-first)
  --name-compare exact|normalized     (default exact)
  --unknown-fields refuse|report      (default refuse)
  --ed25519 strict|rfc8032            (default strict)
  --correspondence ids-required|strict  (default ids-required)
  --key-id-agreement signature-invalid|require|ignore   (default signature-invalid)
  --key-rule signer|all-keys|refuse   (default signer)
  --independence-rule derived|stated-independent   (default derived)
  exit 0 needs: accepted as stated, --keys, no test key, no rejected key in the key file, tokens authenticated
  (--tokens pkix) when their time is used, supplied files matching, receipt.key_id == signature.key_id (unless
  --key-id-agreement ignore); otherwise 1 with "local_blocks" listed
"""


def main(argv):
    args = list(argv[1:])
    opts = {}
    vector_mode = False
    keyfile = None
    path = None
    flagmap = {"--key-id-source": "key_id_source", "--reference-time": "reference_time",
               "--time-agreement": "time_agreement", "--accuracy": "accuracy", "--tokens": "tokens",
               "--tsa-roots": "tsa_roots", "--name-compare": "name_compare", "--unknown-fields": "unknown_fields",
               "--ed25519": "ed25519", "--correspondence": "correspondence",
               "--key-id-agreement": "key_id_agreement", "--key-rule": "key_rule",
               "--independence-rule": "independence_rule", "--tsa-precedence": "tsa_precedence"}
    profile = None
    while args:
        a = args.pop(0)
        if a == "--vector":
            vector_mode = True
        elif a == "--profile" and args:
            if profile is not None or args[0] != "1.2.1":
                sys.stderr.write("--profile takes 1.2.1, once\n")
                return 64
            profile = args.pop(0)
        elif a == "--keys" and args:
            if keyfile is not None or args[0] == "":          # R2: never fall back silently
                sys.stderr.write("--keys given twice or empty\n")
                return 64
            keyfile = args.pop(0)
        elif a in flagmap and args:
            if flagmap[a] in opts or args[0] == "":           # R3: no silent last-wins
                sys.stderr.write("%s given twice or empty\n" % a)
                return 64
            opts[flagmap[a]] = args.pop(0)
        elif a in ("-h", "--help"):
            sys.stdout.write(USAGE)
            return 0
        elif a.startswith("-") or path is not None:
            sys.stderr.write(USAGE)
            return 64
        else:
            path = a
    if path is None:
        sys.stderr.write(USAGE)
        return 64
    for k, v in opts.items():
        if k != "tsa_roots" and v not in OPTION_VALUES[k]:
            sys.stderr.write("bad value %r for %s\n" % (v, k))
            return 64
    if profile == "1.2.1":
        opts = dict(PROFILE_1_2_1, **opts)
    if opts.get("tokens") == "pkix" and not opts.get("tsa_roots"):
        sys.stderr.write("--tokens pkix needs --tsa-roots\n")
        return 64

    def emit(obj):
        sys.stdout.write(json.dumps(obj, indent=1, sort_keys=True, default=str) + "\n")

    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        override = None
        if keyfile:
            with open(keyfile, "rb") as fh:
                override = strict_json_loads(fh.read())
        if vector_mode:
            rep, cmp_ = run_vector_bytes(raw, opts, override)
        else:
            rep, cmp_ = run_vector(strict_json_loads(raw), opts, override)
    except CannotRun as e:
        emit({"cannot_run": True, "reason": str(e), "verifier": VERSION, "python": sys.version.split()[0]})
        return 74
    except Refusal as e:
        emit({"refused": True, "reason": e.reason, "reason_detail": e.detail})
        return 2
    except OSError as e:
        emit({"cannot_run": True, "reason": "cannot read input: %s" % e})
        return 74
    out = {"report": rep, "verifier": VERSION}
    if vector_mode:
        out["comparison"] = cmp_
        emit(out)
        if cmp_ is None:
            return 64
        if rep.get("cannot_run"):
            return 74
        return 0 if cmp_["agree"] else 3
    emit(out)
    if rep.get("refused"):
        return 2
    if rep.get("cannot_run"):
        return 74
    return 0 if rep.get("accepted_as_stated") and not rep.get("local_blocks") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
