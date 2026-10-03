"""Exercise the actual native-CMAC adapter with an independent JCE-backed API double.
The double models functional sequencing only; actual on-card CMAC is tested separately.
"""
import json
from pathlib import Path
import subprocess
import tempfile
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms
ROOT=Path(__file__).resolve().parents[1]


def java_checks(jdk):
    vectors=[]
    for keylen in (16,32):
        key=bytes(range(keylen))
        for size in (0,1,15,16,17,32,40,64):
            message=bytes((i*23+size)%256 for i in range(size))
            mac=CMAC(algorithms.AES(key));mac.update(message)
            vectors.append((key.hex(),message.hex(),mac.finalize().hex()))
    rows=',\n'.join('{'+','.join(json.dumps(x) for x in row)+'}' for row in vectors)
    files={
'javacard/framework/JCSystem.java':'''package javacard.framework; public class JCSystem {public static final byte CLEAR_ON_DESELECT=2;public static byte[] makeTransientByteArray(short n,byte t){return new byte[n];}}''',
'javacard/framework/Util.java':'''package javacard.framework; public class Util {
public static short arrayFillNonAtomic(byte[] b,short o,short n,byte v){java.util.Arrays.fill(b,o,o+n,v);return (short)(o+n);}
public static short arrayCopyNonAtomic(byte[] b,short o,byte[] d,short x,short n){System.arraycopy(b,o,d,x,n);return (short)(x+n);}
public static short setShort(byte[] b,short o,short v){b[o]=(byte)(v>>8);b[o+1]=(byte)v;return (short)(o+2);}}
''',
'javacard/security/AESKey.java':'''package javacard.security; public class AESKey {
public byte[] value;private boolean ready;public boolean failClear;
public AESKey(short bits){value=new byte[bits/8];}public short getSize(){return (short)(value.length*8);}
public void setKey(byte[] b,short o){System.arraycopy(b,o,value,0,value.length);ready=true;}
public boolean isInitialized(){return ready;}public void clearKey(){if(failClear)throw new RuntimeException("native failure");java.util.Arrays.fill(value,(byte)0);ready=false;}}
''',
'javacard/security/KeyBuilder.java':'''package javacard.security;public class KeyBuilder {public static final byte TYPE_AES_TRANSIENT_DESELECT=15;public static AESKey buildKey(byte t,short b,boolean x){return new AESKey(b);}}''',
'javacard/security/CryptoException.java':'''package javacard.security;public class CryptoException extends RuntimeException {public static final short ILLEGAL_VALUE=1,UNINITIALIZED_KEY=2,NO_SUCH_ALGORITHM=3,INVALID_INIT=4,ILLEGAL_USE=5;public final short reason;public CryptoException(short r){reason=r;}public static void throwIt(short r){throw new CryptoException(r);}}''',
'javacard/security/Signature.java':r'''package javacard.security;
import java.util.*;import java.io.*;
public class Signature {
 public static final byte ALG_AES_CMAC_128=49,MODE_SIGN=1;public static boolean supported=true;public static short resultSize=16;public static boolean failSign=false;
 private AESKey key;private ByteArrayOutputStream input=new ByteArrayOutputStream();
 public static Signature getInstance(byte a,boolean external){if(!supported||a!=ALG_AES_CMAC_128)CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);return new Signature();}
 public void init(AESKey k,byte m){key=k;input.reset();}
 public void update(byte[] b,short o,short n){input.write(b,o,n);}
 static byte[] doubleBlock(byte[] b){byte[] out=new byte[16];int carry=0;for(int i=15;i>=0;i--){int v=b[i]&255;out[i]=(byte)((v<<1)|carry);carry=v>>>7;}if(carry!=0)out[15]^=(byte)0x87;return out;}
 public short sign(byte[] b,short o,short n,byte[] dst,short off){if(failSign)throw new RuntimeException("simulated native sign failure");if(b==null)throw new NullPointerException();if(!key.isInitialized())CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);input.write(b,o,n);byte[] msg=input.toByteArray();try{
 javax.crypto.Cipher aes=javax.crypto.Cipher.getInstance("AES/ECB/NoPadding");aes.init(javax.crypto.Cipher.ENCRYPT_MODE,new javax.crypto.spec.SecretKeySpec(key.value,"AES"));
 byte[] k1=doubleBlock(aes.doFinal(new byte[16]));byte[] k2=doubleBlock(k1);int blocks=Math.max(1,(msg.length+15)/16);byte[] prev=new byte[16];
 for(int block=0;block<blocks;block++){byte[] piece=new byte[16];int start=block*16;int count=Math.min(16,msg.length-start);if(count>0)System.arraycopy(msg,start,piece,0,count);
 if(block==blocks-1){byte[] k=count==16?k1:k2;if(count!=16)piece[count]=(byte)128;for(int i=0;i<16;i++)piece[i]^=k[i];}
 for(int i=0;i<16;i++)piece[i]^=prev[i];prev=aes.doFinal(piece);}
 System.arraycopy(prev,0,dst,off,16);input.reset();return resultSize;
 }catch(Exception e){throw new RuntimeException(e);}}
}
''',
'fr/anssi/smartpgp/Harness.java':r'''package fr.anssi.smartpgp;
import java.util.*;import javacard.security.*;
public class Harness {
 static int checks;
 static byte[] hex(String s){byte[] b=new byte[s.length()/2];for(int i=0;i<b.length;i++)b[i]=(byte)Integer.parseInt(s.substring(i*2,i*2+2),16);return b;}
 static void ck(boolean v){checks++;if(!v)throw new AssertionError("check "+checks);}
 static void erased(CmacSignature sig)throws Exception{for(String name:new String[]{"result","short_input"}){java.lang.reflect.Field f=CmacSignature.class.getDeclaredField(name);f.setAccessible(true);byte[] b=(byte[])f.get(sig);ck(Arrays.equals(b,new byte[b.length]));}}
 public static void main(String[] args)throws Exception{
 String[][] vectors={VECTORS};int splits=0;
 for(String[] row:vectors){byte[] k=hex(row[0]),m=hex(row[1]),expected=hex(row[2]);CmacKey key=new CmacKey((short)k.length);key.setKey(k,(short)0);CmacSignature sig=new CmacSignature();
 for(int split=0;split<=m.length;split++)for(short outlen:new short[]{8,16}){
  sig.init(key);sig.update(m,(short)0,(short)split);byte[] out=new byte[outlen];sig.sign(m,(short)split,(short)(m.length-split),out,(short)0,outlen);ck(Arrays.equals(out,Arrays.copyOf(expected,outlen)));erased(sig);splits++;
 }
 sig.init(key);for(byte v:m)sig.updateByte(v);byte[] out=new byte[16];sig.sign(null,(short)0,(short)0,out,(short)0,(short)16);ck(Arrays.equals(out,expected));erased(sig);
 sig.init(key);int pos=0;for(;pos+1<m.length;pos+=2)sig.updateShort((short)(((m[pos]&255)<<8)|(m[pos+1]&255)));if(pos<m.length)sig.updateByte(m[pos]);sig.sign(null,(short)0,(short)0,out,(short)0,(short)16);ck(Arrays.equals(out,expected));erased(sig);
 sig.init(key);key.key.clearKey();sig.clear();ck(!sig.isInitialized());erased(sig);
 key.setKey(k,(short)0);sig.init(key);key.key.failClear=true;boolean threw=false;try{sig.clear();}catch(RuntimeException e){threw=true;}ck(threw);ck(!sig.isInitialized());erased(sig);
 }
 CmacKey failureKey=new CmacKey((short)16);failureKey.setKey(new byte[16],(short)0);CmacSignature failureSig=new CmacSignature();
 for(int scenario=0;scenario<2;scenario++){
  failureSig.init(failureKey);byte[] out=new byte[16];Arrays.fill(out,(byte)0x55);byte[] unchanged=out.clone();
  Signature.resultSize=(short)(scenario==0?15:16);Signature.failSign=scenario==1;
  boolean rejected=false;try{failureSig.sign(null,(short)0,(short)0,out,(short)0,(short)16);}catch(RuntimeException e){rejected=true;}
  ck(rejected);ck(Arrays.equals(out,unchanged));erased(failureSig);
 }
 Signature.resultSize=16;Signature.failSign=false;
 Signature.supported=false;CmacKey k=new CmacKey((short)16);k.setKey(new byte[16],(short)0);boolean failed=false;try{new CmacSignature().init(k);}catch(CryptoException e){failed=e.reason==CryptoException.NO_SUCH_ALGORITHM;}ck(failed);
 ck(CmacKey.class.getDeclaredFields().length==1);
 System.out.println("Native CMAC adapter: "+splits+" split/truncation cases; "+checks+" assertions; 128/256-bit independent references passed.");
 System.out.println("Native unavailable fails closed; no Java subkey arrays; scratch cleared on native cleanup exception.");
 }
}
'''.replace('VECTORS',rows)
    }
    for name in ('CmacKey','CmacSignature'):
        files['fr/anssi/smartpgp/'+name+'.java']=(ROOT/'src/fr/anssi/smartpgp'/(name+'.java')).read_text(encoding='utf-8')
    parent=ROOT/'build/host-native-cmac-tests';parent.mkdir(parents=True,exist_ok=True)
    work=Path(tempfile.mkdtemp(dir=parent,prefix='run-'));classes=work/'classes';classes.mkdir()
    for n,s in files.items():p=work/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s,encoding='utf-8')
    p=subprocess.run([str(Path(jdk)/'bin/javac.exe'),'-encoding','UTF-8','-d',str(classes),*[str(work/n) for n in files]],capture_output=True,text=True)
    if p.returncode:raise RuntimeError(p.stdout+p.stderr)
    return subprocess.check_output([str(Path(jdk)/'bin/java.exe'),'-cp',str(classes),'fr.anssi.smartpgp.Harness'],text=True).splitlines()
