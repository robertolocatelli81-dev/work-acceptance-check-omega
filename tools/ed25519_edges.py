#!/usr/bin/env python3
"""Measure Ed25519 edge cases: what the `cryptography` engine accepts, what RFC 8032 pure verification accepts,
and what war_verify (strict / rfc8032 modes) accepts. Prints one line per case."""
import hashlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import war_verify as wv
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

def engine(pub, msg, sig):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg); return True
    except (InvalidSignature, ValueError):
        return False

P, L = wv._P, wv._L
def enc_int(n): return n.to_bytes(32, "little")
# the 8-torsion points: find all by decoding small-order candidates
def torsion_points():
    pts = {}
    # order-8 point: known y value
    y8 = 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7 % P
    T8 = wv.ed_decode(enc_int(y8)); assert not isinstance(T8, str)
    for i in range(8):
        Q = wv._pmul(i, T8); pts[i] = wv._encode_point(Q)
    return pts, T8
def run():
    rows = []
    seed = hashlib.sha256(b"war-verify ed25519 edge test key (TEST, never trust)").digest()
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pub = sk.public_key().public_bytes_raw() if hasattr(sk.public_key(), "public_bytes_raw") else None
    from cryptography.hazmat.primitives import serialization
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    msg = b"war-verify edge message"
    sig = sk.sign(msg)
    def row(name, pk, m, sg):
        r = {"case": name, "engine": engine(pk, m, sg), "pure_rfc8032": wv.ed_verify_pure(pk, m, sg)}
        for mode in ("rfc8032", "strict"):
            try: r[mode] = wv.ed25519_verify(pk, m, sg, mode)[0]
            except Exception as e: r[mode] = "ERR " + str(e)
        rows.append(r)
    row("valid signature", pub, msg, sig)
    S = int.from_bytes(sig[32:], "little")
    row("S + L (non-canonical S)", pub, msg, sig[:32] + enc_int(S + L))
    pts, T8 = torsion_points()
    ident = pts[0]
    # identity public key, identity R, S = 0: verifies cofactorless for every message
    row("A = identity, R = identity, S = 0", ident, msg, ident + enc_int(0))
    row("A = identity, R = identity, S = 0, other msg", ident, b"anything at all", ident + enc_int(0))
    # non-canonical encoding of the identity: y = 1 + p
    nc_ident = enc_int(1 + P)
    row("A = identity, R = identity non-canonical (y=1+p), S = 0", ident, msg, nc_ident + enc_int(0))
    row("A = identity non-canonical (y=1+p), R = identity, S = 0", nc_ident, msg, ident + enc_int(0))
    # small-order A of order 2 (y = -1): sig R=identity S=0 verifies when k is even
    a2 = pts[4]
    ok = sum(engine(a2, b"m%d" % i, ident + enc_int(0)) for i in range(64))
    rows.append({"case": "A order 2, R = identity, S = 0: engine accepts N/64 messages", "engine": ok,
                 "pure_rfc8032": sum(wv.ed_verify_pure(a2, b"m%d" % i, ident + enc_int(0)) for i in range(64)),
                 "rfc8032": sum(wv.ed25519_verify(a2, b"m%d" % i, ident + enc_int(0), "rfc8032")[0] for i in range(64)),
                 "strict": sum(wv.ed25519_verify(a2, b"m%d" % i, ident + enc_int(0), "strict")[0] for i in range(64))})
    # mixed-order key A' = A + T8: signatures by A's private key verify under A' when k = 0 mod 8
    A = wv.ed_decode(pub)
    Amix = wv._encode_point(wv._padd(A, T8))
    n = 256
    msgs = [b"mixed %d" % i for i in range(n)]
    sigs = [sk.sign(m) for m in msgs]
    rows.append({"case": "A' = A + T8 (mixed order): signatures by A accepted under A' out of %d" % n,
                 "engine": sum(engine(Amix, m, s) for m, s in zip(msgs, sigs)),
                 "pure_rfc8032": sum(wv.ed_verify_pure(Amix, m, s) for m, s in zip(msgs, sigs)),
                 "rfc8032": sum(wv.ed25519_verify(Amix, m, s, "rfc8032")[0] for m, s in zip(msgs, sigs)),
                 "strict": sum(wv.ed25519_verify(Amix, m, s, "strict")[0] for m, s in zip(msgs, sigs))})
    rows.append({"case": "point class of A, A' and identity", "engine": "-", "pure_rfc8032": "-",
                 "rfc8032": [wv.ed_point_class(pub), wv.ed_point_class(Amix), wv.ed_point_class(ident)], "strict": "-"})
    return rows, {"A": pub.hex(), "Amix": Amix.hex(), "seed": seed.hex()}

if __name__ == "__main__":
    rows, info = run()
    for r in rows:
        print("%-75s engine=%-5s pure=%-5s rfc8032=%-5s strict=%s" % (r["case"], r["engine"], r["pure_rfc8032"], r["rfc8032"], r["strict"]))
    print(info)


def same_scalar_mixed_key(n=256):
    """The holder of A's private scalar a signs FOR A' = A + T8 (k' hashed over A'). Cofactorless verification
    accepts when 8 | k' (expected ~1/8); the signer can grind the nonce until it does. Returns counts."""
    seed = hashlib.sha256(b"war-verify ed25519 edge test key (TEST, never trust)").digest()
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pts, T8 = torsion_points()
    A = wv._pmul(a, wv._BASE)
    Amix = wv._encode_point(wv._padd(A, T8))
    res = {"engine": 0, "pure_rfc8032": 0, "rfc8032": 0, "strict": 0, "ground": 0}
    for i in range(n):
        m = b"mixed %d" % i
        r = int.from_bytes(hashlib.sha512(prefix + m).digest(), "little") % L
        R = wv._encode_point(wv._pmul(r, wv._BASE))
        k = int.from_bytes(hashlib.sha512(R + Amix + m).digest(), "little") % L
        S = (r + k * a) % L
        sig = R + enc_int(S)
        res["engine"] += engine(Amix, m, sig)
        res["pure_rfc8032"] += wv.ed_verify_pure(Amix, m, sig)
        res["rfc8032"] += wv.ed25519_verify(Amix, m, sig, "rfc8032")[0]
        res["strict"] += wv.ed25519_verify(Amix, m, sig, "strict")[0]
    # grinding: for one fixed message, try nonces until the engine accepts
    m = b"chosen record bytes"
    for j in range(1, 200):
        r = int.from_bytes(hashlib.sha512(prefix + m + bytes([j])).digest(), "little") % L
        R = wv._encode_point(wv._pmul(r, wv._BASE))
        k = int.from_bytes(hashlib.sha512(R + Amix + m).digest(), "little") % L
        if engine(Amix, m, R + enc_int((r + k * a) % L)):
            res["ground"] = j
            break
    return res, Amix.hex()


if __name__ == "__main__":
    print("same scalar, signing for A+T8, n=256:", same_scalar_mixed_key())
