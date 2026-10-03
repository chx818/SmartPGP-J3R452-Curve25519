"""Read-only inventory by default. --exercise signs test data and uses ECDH.
NEVER generates/imports keys or changes PINs/attributes. --exercise does increment
the signature counter and a wrong PIN consumes a retry. Use a dedicated test card.
Requires pyscard and cryptography. Not run on a physical card during this audit.
Does not implement SCP11b or derived PINs; refuses exercise if KDF DO is active.
"""
import argparse
import getpass
import hmac
import json
import os
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def apdu(ins, p1, p2, data=b"", le=True):
    if len(data)>255:
        raise ValueError("short APDUs only")
    return bytes([0,ins,p1,p2])+(bytes([len(data)])+data if data else b"")+(b"\x00" if le else b"")


def exchange(conn, cmd):
    # A 6C correction is allowed ONLY for commands known not to change state.
    data,s1,s2=conn.transmit(list(cmd))
    if s1==0x6c and cmd[1] in (0xa4,0xca,0xc0):
        data,s1,s2=conn.transmit(list(cmd[:-1]+bytes([s2])))
    out=bytes(data)
    for _ in range(32):
        if s1!=0x61:
            return out,(s1<<8)|s2
        data,s1,s2=conn.transmit([0,0xc0,0,0,s2])
        out+=bytes(data)
    raise RuntimeError("too many response segments")


def need(conn, cmd):
    data,sw=exchange(conn,cmd)
    if sw!=0x9000:
        # Do not log PIN-bearing commands.
        raise RuntimeError(f"INS={cmd[1]:02x} failed SW={sw:04x}")
    return data


def tlv(blob):
    off=0
    while off<len(blob):
        tag=blob[off];off+=1
        if tag&31==31:
            if off>=len(blob): raise ValueError("truncated tag")
            tag=(tag<<8)|blob[off];off+=1
        if off>=len(blob): raise ValueError("truncated length")
        length=blob[off];off+=1
        if length&128:
            count=length&127
            if count not in (1,2) or off+count>len(blob): raise ValueError("invalid length")
            length=int.from_bytes(blob[off:off+count],"big");off+=count
        if off+length>len(blob): raise ValueError("truncated value")
        yield tag,blob[off:off+length]
        off+=length


def pubkey(blob):
    outer=list(tlv(blob))
    if len(outer)!=1 or outer[0][0]!=0x7f49: raise ValueError("public key DO expected")
    inner=list(tlv(outer[0][1]))
    if len(inner)!=1 or inner[0][0]!=0x86: raise ValueError("EC key expected")
    key=inner[0][1]
    if len(key)==33 and key[0]==0x40: key=key[1:]
    if len(key)!=32: raise ValueError("25519 public key expected")
    return key


def verify_pin(conn, mode, pin):
    need(conn,apdu(0x20,0,mode,pin,le=False))


def decipher(conn, point):
    return exchange(conn,apdu(0x2a,0x80,0x86,b"\xa6\x25\x7f\x49\x22\x86\x20"+point))


def exercise(conn, pin, sigpub, decpub):
    # Random payload with an explicit test-only label; verification is independent.
    msg=b"SmartPGP audit test " + os.urandom(32)
    verify_pin(conn,0x81,pin)
    signature=need(conn,apdu(0x2a,0x9e,0x9a,msg))
    ed25519.Ed25519PublicKey.from_public_bytes(sigpub).verify(signature,msg)
    verify_pin(conn,0x82,pin)
    eph=x25519.X25519PrivateKey.generate()
    point=eph.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    expected=eph.exchange(x25519.X25519PublicKey.from_public_bytes(decpub))
    received,sw=decipher(conn,point)
    if sw!=0x9000 or not hmac.compare_digest(received,expected):
        raise RuntimeError("X25519 host/card result mismatch")
    high=bytearray(point);high[31]^=128
    alias,sw=decipher(conn,bytes(high))
    high_ok=sw==0x9000 and hmac.compare_digest(alias,expected)
    # Check 9 versus 9+p: required noncanonical u-coordinate handling.
    p=2**255-19
    base,bsw=decipher(conn,(9).to_bytes(32,"little"))
    noncanonical,nsw=decipher(conn,(p+9).to_bytes(32,"little"))
    canonical_ok=bsw==nsw==0x9000 and len(base)==32 and hmac.compare_digest(base,noncanonical)
    low=[(n.to_bytes(32,"little")) for n in [0,1,p-1,p,p+1]]
    low += [bytes.fromhex(x) for x in [
      "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
      "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"]]
    results=[]
    for point in low:
        for highbit in (False,True):
            v=bytearray(point)
            if highbit: v[31]|=128
            verify_pin(conn,0x82,pin)
            data,sw=decipher(conn,bytes(v))
            results.append({"u":bytes(v).hex(),"sw":f"{sw:04x}","rejected":sw in (0x6a80,0x6985) and not data})
    return {"ed25519_independent_verify":True,"x25519_independent_compare":True,"top_bit_alias":high_ok,"noncanonical_p_plus_9":canonical_ok,"low_order_tests":results}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list",action="store_true")
    parser.add_argument("--reader",help="exact PC/SC reader name; never auto-select")
    parser.add_argument("--exercise",action="store_true")
    args=parser.parse_args()
    from smartcard.System import readers
    rs=readers()
    if args.list:
        print("\n".join(map(str,rs)));return
    matches=[r for r in rs if str(r)==args.reader]
    if len(matches)!=1: parser.error("specify one exact --reader (use --list first)")
    conn=matches[0].createConnection();conn.connect()
    try:
        need(conn,apdu(0xa4,4,0,bytes.fromhex("d27600012401")))
        attrs={tag:need(conn,apdu(0xca,0,tag)) for tag in (0xc1,0xc2,0xc4,0xf9)}
        for tag in (0xc1,0xc2):
            parsed=list(tlv(attrs[tag]))
            if len(parsed)==1 and parsed[0][0]==tag: attrs[tag]=parsed[0][1]
        print(json.dumps({"reader":str(matches[0]),"atr":bytes(conn.getATR()).hex(),"data_objects":{f"{k:02x}":v.hex() for k,v in attrs.items()}},indent=2))
        if not args.exercise: return
        if attrs[0xc1].rstrip(b"\xff")!=bytes.fromhex("162b06010401da470f01") or attrs[0xc2].rstrip(b"\xff")!=bytes.fromhex("122b060104019755010501"):
            raise RuntimeError("existing SIG=Ed25519 and DEC=X25519 required; no attributes changed")
        if attrs[0xf9]!=bytes.fromhex("810100"):
            raise RuntimeError("derived PIN/unknown KDF configuration unsupported")
        if len(attrs[0xc4])!=7 or attrs[0xc4][4]<2:
            raise RuntimeError("PW1 retry budget insufficient or malformed PW status")
        sigpub=pubkey(need(conn,apdu(0x47,0x81,0,b"\xb6\x00")))
        decpub=pubkey(need(conn,apdu(0x47,0x81,0,b"\xb8\x00")))
        pin=getpass.getpass("Test-card PW1 (one attempt per verification; no automatic retry): ").encode("utf-8")
        if not 6<=len(pin)<=127: raise ValueError("PIN length out of supported range")
        results=exercise(conn,pin,sigpub,decpub)
        print(json.dumps(results,indent=2))
        if not (results["top_bit_alias"] and results["noncanonical_p_plus_9"] and all(x["rejected"] for x in results["low_order_tests"])):
            raise SystemExit("conformance/low-order checks failed; see results")
    finally:
        # Clear both PW1 modes even if an exercise failed, without changing PINs.
        if args.exercise:
            for mode in (0x81,0x82):
                try: exchange(conn,bytes([0,0x20,0xff,mode]))
                except Exception: pass
        conn.disconnect()

if __name__=="__main__": main()
