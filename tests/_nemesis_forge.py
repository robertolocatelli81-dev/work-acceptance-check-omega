# NEMESIS own builder: signed receipts + structural RFC 3161 TimeStampResp (DER written here, independent of tools/)
import json, base64, hashlib, copy, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
def L(n):
    if n<128: return bytes([n])
    b=n.to_bytes((n.bit_length()+7)//8,'big'); return bytes([0x80|len(b)])+b
def tlv(t,c): return bytes([t])+L(len(c))+c
def seq(*k): return tlv(0x30,b''.join(k))
def oid(s):
    a=[int(x) for x in s.split('.')]; out=bytes([a[0]*40+a[1]])
    for v in a[2:]:
        enc=[v&0x7f]; v>>=7
        while v: enc.append(0x80|(v&0x7f)); v>>=7
        out+=bytes(reversed(enc))
    return tlv(6,out)
def integer(v):
    b=v.to_bytes((v.bit_length()+8)//8 or 1,'big',signed=True); return tlv(2,b)
def tst(digest, gentime, halg='2.16.840.1.101.3.4.2.1', extra=b'', null_params=True):
    alg=seq(oid(halg), tlv(5,b'')) if null_params else seq(oid(halg))
    return seq(integer(1), oid('1.2.3.4'), seq(alg, tlv(4,digest)), integer(1), tlv(0x18,gentime.encode()), extra)
def tsr(tstinfo, signer_infos=b''):
    sd=seq(integer(3), tlv(0x31,b''), seq(oid('1.2.840.113549.1.9.16.1.4'), tlv(0xA0, tlv(4,tstinfo))), signer_infos)
    ci=seq(oid('1.2.840.113549.1.7.2'), tlv(0xA0, sd))
    return seq(seq(integer(0)), ci)
def b64(b): return base64.b64encode(b).decode()
def jcs(o):  # independent JCS for the ASCII/int-only receipts used here
    return json.dumps(o, sort_keys=True, separators=(',',':'), ensure_ascii=False).encode()
class Key:
    def __init__(self, seed_byte, kid):
        self.sk=Ed25519PrivateKey.from_private_bytes(bytes([seed_byte])*32); self.kid=kid
        self.pub=self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    def entry(self, status='active'): return {"alg":"Ed25519","key_id":self.kid,"public_key_base64":b64(self.pub),"status":status}
def base_receipt(snap):
    d=json.load(open(snap+'/fonti/upstream_f7d8984/vectors/01-valid.json')); return copy.deepcopy(d['inputs'])
def build(inputs, key, receipt=None, sig_kid=None, crit_gen=None, rec_gen=None, ts_meta='granted', keys=None, crit_digest=None):
    i=copy.deepcopy(inputs); r=receipt if receipt is not None else i['receipt']['receipt']
    canon=jcs(r); sig=key.sk.sign(canon)
    env={"receipt":r,"signature":{"alg":"Ed25519","key_id":sig_kid or key.kid,"value":b64(sig)}}
    dig=hashlib.sha256(canon).digest()
    if rec_gen:
        i['receipt_tsr_base64']=b64(tsr(tst(dig,rec_gen)))
        if ts_meta=='granted':
            env['timestamp']={"covers":"sha256 of the canonical receipt object","digest_sha256":dig.hex(),"gen_time":rec_gen,"status":"granted","tsa":"x","tsr_file":"r.tsr"}
        elif ts_meta=='none': env['timestamp']={"status":"none","reason":"x"}
    else:
        i.pop('receipt_tsr_base64',None)
    if crit_gen:
        i['criteria_tsr_base64']=b64(tsr(tst(crit_digest or bytes.fromhex(r['criteria']['sha256']),crit_gen)))
    i['receipt']=env; i['keys']=keys or {"issuer":"x","keys":[key.entry()]}
    return i
