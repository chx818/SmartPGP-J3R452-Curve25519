"""Offline applet crypto regression. Requires cryptography and a JDK.
Uses independent CMAC references and the actual Java native-CMAC adapter with API
doubles; curve parameter checks use host EC. No card or physical SCA simulation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SRC = ROOT / "src/fr/anssi/smartpgp"


def method(text, signature):
    start = text.index(signature)
    pos = text.index("{", start)
    depth = 1
    end = pos + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


def ladder(k, u):
    # RFC 7748 reference arithmetic, variable time; test inputs ONLY.
    p = 2**255 - 19
    scalar = bytearray(k)
    scalar[0] &= 248
    scalar[31] = (scalar[31] & 127) | 64
    scalar = int.from_bytes(scalar, "little")
    x1 = (int.from_bytes(u, "little") & (2**255 - 1)) % p
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (scalar >> t) & 1
        swap ^= kt
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a*a % p, b*b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d*a % p, c*b % p
        x3, z3 = (da+cb)**2 % p, x1*(da-cb)**2 % p
        x2, z2 = aa*bb % p, e*(aa+121665*e) % p
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, p-2, p) % p).to_bytes(32, "little")


# Adapter sequencing is tested using independent host cryptography; the native
# implementation itself is additionally exercised by on-card SM/probe tests.
from native_cmac_host import java_checks


def curve_checks():
    source=(SRC/"ECConstants.java").read_text(encoding='utf-8')
    def const(name):
        value=re.search(name+r"\s*=\s*\{(.*?)\};",source,re.S).group(1)
        return bytes(int(x,16) for x in re.findall(r"0x([0-9a-fA-F]{1,2})",value))
    result=[]
    for prefix,curve in [("ansix9p256r1",ec.SECP256R1()),("ansix9p384r1",ec.SECP384R1()),("ansix9p521r1",ec.SECP521R1()),("brainpoolP256r1",ec.BrainpoolP256R1()),("brainpoolP384r1",ec.BrainpoolP384R1()),("brainpoolP512r1",ec.BrainpoolP512R1())]:
        p,a,b,n=[int.from_bytes(const(prefix+"_"+v),"big") for v in ["field","a","b","r"]]
        g=const(prefix+"_g"); size=(len(g)-1)//2
        x,y=int.from_bytes(g[1:1+size],"big"),int.from_bytes(g[1+size:],"big")
        oncurve=(y*y-x*x*x-a*x-b)%p==0
        host=ec.derive_private_key(1,curve).public_key().public_numbers()
        def add(P,Q):
            if P is None:return Q
            if Q is None:return P
            xx,yy=P;xx2,yy2=Q
            if xx==xx2 and (yy+yy2)%p==0:return None
            m=((3*xx*xx+a)*pow(2*yy,-1,p) if P==Q else (yy2-yy)*pow(xx2-xx,-1,p))%p
            rx=(m*m-xx-xx2)%p
            return rx,(m*(xx-rx)-yy)%p
        R=None;Q=(x,y);k=n
        while k:
            if k&1:R=add(R,Q)
            Q=add(Q,Q);k>>=1
        record={"curve":prefix,"G_on_curve":oncurve,"G_matches_host":(x,y)==(host.x,host.y),"nG_is_infinity":R is None}
        if not all(record[k] for k in ["G_on_curve","G_matches_host","nG_is_infinity"]):raise RuntimeError(record)
        result.append(record)
    return result


if __name__ == "__main__":
    rows=java_checks(ROOT.parent/"build_tools/jdk_extracted/jdk-11.0.32.1+1")
    print("\n".join(rows))
    if any("ok=false" in r or "is_zero=false" in r for r in rows):
        raise SystemExit("CMAC regression failure")
    print(json.dumps(curve_checks(),indent=2))
    source=(SRC/"PGPKey.java").read_text(encoding="utf-8")
    init=method(source,"    protected final boolean isInitialized(")
    if "KEY_VALID" not in init or "key_state_inverse" not in init or "resetKeys" in init:
        raise SystemExit("key state invariant regression")
    if "LOW_ORDER_ROOT" in source or "zero_key_buf" in source:
        raise SystemExit("obsolete unsafe key workaround restored")
    print("Key activation/query source invariants passed")
    print("Host security regression passed")
