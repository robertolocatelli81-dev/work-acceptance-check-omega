"""Test-only DER encoder and a throw-away RFC 3161 TSA, used to build positive controls and new vectors.
Nothing here is trusted by war_verify.py; it only produces inputs for it. Keys are generated per run unless a
seed is given (Ed25519 test keys for records are deterministic from a published seed)."""
import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


# ------------------------------------------------------------------------------------------- DER encoder
def _len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + _len(len(content)) + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def set_of(*items, sort=True):
    items = list(items)
    if sort:
        items.sort(key=lambda e: e + b"\x00" * 0)  # DER: compare encodings
        n = max([len(i) for i in items] or [0])
        items.sort(key=lambda e: e.ljust(n, b"\x00"))
    return tlv(0x31, b"".join(items))


def integer(n):
    if n == 0:
        return tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    while len(b) > 1 and ((b[0] == 0 and b[1] < 0x80) or (b[0] == 0xFF and b[1] >= 0x80)):
        b = b[1:]
    return tlv(0x02, b)


def oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    out = [40 * arcs[0] + arcs[1]] + arcs[2:]
    body = b""
    for a in out:
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        body += bytes(reversed(chunk))
    return tlv(0x06, body)


def octets(b):
    return tlv(0x04, b)


def null():
    return b"\x05\x00"


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def gentime(s):
    return tlv(0x18, s.encode("ascii"))


def explicit(n, inner):
    return tlv(0xA0 | n, inner)


def alg(o, params=b"NULL"):
    if params == b"NULL":
        return seq(oid(o), null())
    if params is None:
        return seq(oid(o))
    return seq(oid(o), params)


SHA = {"sha256": "2.16.840.1.101.3.4.2.1", "sha384": "2.16.840.1.101.3.4.2.2", "sha512": "2.16.840.1.101.3.4.2.3",
       "sha1": "1.3.14.3.2.26", "sha224": "2.16.840.1.101.3.4.2.4", "sha3-256": "2.16.840.1.101.3.4.2.8",
       "sha3-384": "2.16.840.1.101.3.4.2.9", "sha3-512": "2.16.840.1.101.3.4.2.10",
       "sha512-256": "2.16.840.1.101.3.4.2.6", "sha512-224": "2.16.840.1.101.3.4.2.5"}


def tstinfo(digest, gen="20260301000000Z", hash_oid=SHA["sha256"], params=b"NULL", policy="1.2.3.4", serial=7,
            accuracy=None, ordering=None, nonce=None, tsa_name_der=None, extensions=None, version=1):
    parts = [integer(version), oid(policy), seq(alg(hash_oid, params), octets(digest)), integer(serial),
             gentime(gen)]
    if accuracy is not None:
        s, ms, us = accuracy
        acc = b""
        if s is not None:
            acc += integer(s)
        if ms is not None:
            acc += tlv(0x80, integer(ms)[2:])
        if us is not None:
            acc += tlv(0x81, integer(us)[2:])
        parts.append(tlv(0x30, acc))
    if ordering is not None:
        parts.append(boolean(ordering))
    if nonce is not None:
        parts.append(integer(nonce))
    if tsa_name_der is not None:
        parts.append(explicit(0, tlv(0xA4, tsa_name_der)))
    if extensions is not None:
        parts.append(tlv(0xA1, b"".join(extensions)))
    return seq(*parts)


def unsigned_tsr(tst_der, with_signerinfos=False, status=0):
    """The shape of the profile's vector tokens: SignedData without any signature."""
    eci = seq(oid("1.2.840.113549.1.9.16.1.4"), explicit(0, octets(tst_der)))
    body = integer(3) + tlv(0x31, b"") + eci + (tlv(0x31, b"") if with_signerinfos else b"")
    ci = seq(oid("1.2.840.113549.1.7.2"), explicit(0, tlv(0x30, body)))
    return seq(seq(integer(status)), ci)


# ------------------------------------------------------------------------------------------ test TSA
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "war-verify TEST"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _dt(s):
    return datetime.datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)


def make_ca(cn="war-verify TEST root", nb="20200101000000Z", na="20400101000000Z"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(_dt(nb)).not_valid_after(_dt(na))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def make_tsa(ca, cn="war-verify TEST TSA", nb="20200101000000Z", na="20400101000000Z", eku=("ts",),
             eku_critical=True, ca_flag=False):
    ca_key, ca_cert = ca
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(_dt(nb)).not_valid_after(_dt(na))
         .add_extension(x509.BasicConstraints(ca=ca_flag, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(True, True, False, False, False, False, False, False, False), critical=True))
    m = {"ts": ExtendedKeyUsageOID.TIME_STAMPING, "server": ExtendedKeyUsageOID.SERVER_AUTH,
         "code": ExtendedKeyUsageOID.CODE_SIGNING}
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([m[e] for e in eku]), critical=eku_critical)
    cert = b.sign(ca_key, hashes.SHA256())
    return key, cert


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def signed_tsr(tst_der, tsa, ca_cert, ess="v2", md_override=None, flip_sig=False, extra_signer=False,
               include_certs=True, ess_hash_override=None, status=0, sign_key=None, content_type_oid=None):
    key, cert = tsa
    md = md_override if md_override is not None else hashlib.sha256(tst_der).digest()
    attrs = [seq(oid("1.2.840.113549.1.9.3"), set_of(oid(content_type_oid or "1.2.840.113549.1.9.16.1.4"))),
             seq(oid("1.2.840.113549.1.9.4"), set_of(octets(md)))]
    cd = der(cert)
    if ess == "v2":
        h = ess_hash_override if ess_hash_override is not None else hashlib.sha256(cd).digest()
        attrs.append(seq(oid("1.2.840.113549.1.9.16.2.47"), set_of(seq(seq(seq(octets(h)))))))
    elif ess == "v1":
        h = ess_hash_override if ess_hash_override is not None else hashlib.sha1(cd).digest()
        attrs.append(seq(oid("1.2.840.113549.1.9.16.2.12"), set_of(seq(seq(seq(octets(h)))))))
    sattrs = set_of(*attrs)
    sig = (sign_key or key).sign(sattrs, ec.ECDSA(hashes.SHA256()))
    if flip_sig:
        sig = sig[:-1] + bytes([sig[-1] ^ 1])
    sid = seq(cert.issuer.public_bytes(), integer(cert.serial_number))
    si = seq(integer(1), sid, alg(SHA["sha256"]), b"\xa0" + sattrs[1:], seq(oid("1.2.840.10045.4.3.2")),
             octets(sig))
    sis = [si, si] if extra_signer else [si]
    eci = seq(oid("1.2.840.113549.1.9.16.1.4"), explicit(0, octets(tst_der)))
    body = integer(3) + set_of(alg(SHA["sha256"])) + eci
    if include_certs:
        body += tlv(0xA0, b"".join(sorted([cd, der(ca_cert)], key=lambda e: e.ljust(4096, b"\x00"))))
    body += set_of(*sis) if not extra_signer else tlv(0x31, b"".join(sis))
    ci = seq(oid("1.2.840.113549.1.7.2"), explicit(0, tlv(0x30, body)))
    return seq(seq(integer(status)), ci)


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)
