"""Offline audit evidence, no reader access and no production source edits.
Requires Python cryptography and a JDK. This is NOT a Java Card simulator.
Runs original CmacKey/CmacSignature with narrow JCE-backed API doubles;
Common's two array helpers are extracted verbatim from the audited source.
Outputs observations (including defects), not a claim that the project is safe.
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


def java_checks(jdk):
    work = ROOT / "build/host-security-tests"
    work.mkdir(exist_ok=True)
    common = (SRC / "Common.java").read_text(encoding='utf-8')
    helpers = "\n".join(method(common, "    protected static final void " + n)
                         for n in ["arrayLeftShift(", "arrayXor("])
    files = {
      "fr/anssi/smartpgp/Common.java": "package fr.anssi.smartpgp; public class Common {" + helpers + "}",
      "fr/anssi/smartpgp/Constants.java": "package fr.anssi.smartpgp; public class Constants { static final short AES_BLOCK_SIZE=16;}",
      "javacard/framework/JCSystem.java": """package javacard.framework;
public class JCSystem { public static final byte CLEAR_ON_DESELECT=2;
public static byte[] makeTransientByteArray(short n, byte e){return new byte[n];} }""",
      "javacard/framework/Util.java": """package javacard.framework;
public class Util {
public static short makeShort(byte a,byte b){return (short)(((a&255)<<8)|(b&255));}
public static short arrayCopyNonAtomic(byte[] a,short b,byte[] c,short d,short e){System.arraycopy(a,b,c,d,e);return (short)(d+e);}
public static short arrayFillNonAtomic(byte[] a,short b,short c,byte d){java.util.Arrays.fill(a,b,b+c,d);return (short)(b+c);}
}""",
      "javacard/security/CryptoException.java": """package javacard.security;
public class CryptoException extends RuntimeException {
public static final short UNINITIALIZED_KEY=2, INVALID_INIT=4, ILLEGAL_USE=5, ILLEGAL_VALUE=1;
public static void throwIt(short s){throw new CryptoException();}}
""",
      "javacard/security/AESKey.java": """package javacard.security;
public class AESKey { public byte[] value; private boolean initialized;
public AESKey(short bits){value=new byte[bits/8];}
public void setKey(byte[] b,short off){System.arraycopy(b,off,value,0,value.length);initialized=true;}
public short getSize(){return (short)(value.length*8);}
public boolean isInitialized(){return initialized;}
public void clearKey(){java.util.Arrays.fill(value,(byte)0);initialized=false;}}
""",
      "javacard/security/KeyBuilder.java": """package javacard.security;
public class KeyBuilder { public static final byte TYPE_AES_TRANSIENT_DESELECT=15;
public static AESKey buildKey(byte t,short bits,boolean enc){return new AESKey(bits);}}
""",
      "javacardx/crypto/Cipher.java": """package javacardx.crypto;
import javacard.security.AESKey;
public class Cipher {
 public static final byte MODE_ENCRYPT=1; private javax.crypto.Cipher impl;
 public void init(AESKey key,byte mode) {try {
 impl=javax.crypto.Cipher.getInstance("AES/CBC/NoPadding");
 impl.init(javax.crypto.Cipher.ENCRYPT_MODE,new javax.crypto.spec.SecretKeySpec(key.value,"AES"),new javax.crypto.spec.IvParameterSpec(new byte[16]));
 }catch(Exception e){throw new RuntimeException(e);}}
 public short doFinal(byte[] a,short off,short len,byte[] out,short dest){try{
 byte[] v=impl.doFinal(a,off,len);System.arraycopy(v,0,out,dest,v.length);return (short)v.length;
 }catch(Exception e){throw new RuntimeException(e);}}
}
""",
      "fr/anssi/smartpgp/AuditHarness.java": r"""package fr.anssi.smartpgp;
import java.util.Arrays;
import javacardx.crypto.Cipher;
public class AuditHarness {
 static byte[] hex(String s){byte[] b=new byte[s.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);return b;}
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte v:b)s.append(String.format("%02x",v&255));return s.toString();}
 public static void main(String[] args){
 Cipher cipher=new Cipher(); CmacKey key=new CmacKey((short)16);
 key.setKey(cipher,hex("2b7e151628aed2a6abf7158809cf4f3c"),(short)0);
 CmacSignature sig=new CmacSignature(cipher);
 byte[] msg=hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
 int[] lens={0,16,40,64};
 String[] expected={"bb1d6929e95937287fa37d129b756746","070a16b46b4d4144f79bdd9dd04a287c","dfa66747de9ae63030ca32611497c827","51f0bebf7e3b9d92fc49741779363cfe"};
 int checked=0;
 for(int j=0;j<lens.length;j++) {
  for(int split=0;split<=lens[j];split++) {
   byte[] out=new byte[16]; sig.init(key);
   if(split>0)sig.update(msg,(short)0,(short)split);
   sig.sign(msg,(short)split,(short)(lens[j]-split),out,(short)0,(short)16);
   boolean ok=hex(out).equals(expected[j]); checked++;
   if(split==0||!ok)System.out.println("cmac length="+lens[j]+" split="+split+" ok="+ok+" output="+hex(out));
  }
 }
 System.out.println("cmac_split_cases="+checked);
 for(int j=0;j<lens.length;j++) {
  byte[] out=new byte[16];sig.init(key);
  for(int i=0;i<lens[j];i++)sig.updateByte(msg[i]);
  sig.sign(null,(short)0,(short)0,out,(short)0,(short)16);
  System.out.println("cmac_byte_updates="+lens[j]+" ok="+hex(out).equals(expected[j]));
 }
 // The private compute buffers can retain state when clear() is used mid-stream.
 sig.init(key);sig.update(msg,(short)0,(short)17);sig.clear();
 try { java.lang.reflect.Field f=CmacSignature.class.getDeclaredField("block");f.setAccessible(true);
 System.out.println("cmac_clear_block_is_zero="+Arrays.equals((byte[])f.get(sig),new byte[16]));
 }catch(Exception e){throw new RuntimeException(e);}
 }
}
"""
    }
    for n in ["CmacKey", "CmacSignature"]:
        files[f"fr/anssi/smartpgp/{n}.java"] = (SRC / (n+".java")).read_text(encoding='utf-8')
    for name, text in files.items():
        p = work / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    classes = work / "classes"
    classes.mkdir(exist_ok=True)
    javac, java = (str(Path(jdk)/"bin"/(n+(".exe" if os.name=="nt" else ""))) for n in ["javac","java"])
    subprocess.run([javac,"-encoding","UTF-8","-d",str(classes)]+[str(work/n) for n in files],check=True,capture_output=True,text=True)
    return (subprocess.check_output([java,"-cp",str(classes),"fr.anssi.smartpgp.AuditHarness"],text=True)).splitlines()



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
