"""Compile the actual streaming parser with narrow API doubles. No card access.
Checks arbitrary splits, truncation/abort and validation before replacing an old key.
Crypto operations themselves are covered by the separate physical-card suite.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
JDK=Path(os.environ.get('JAVA_HOME', str(ROOT.parents[2]/'build_tools/jdk_extracted/jdk-11.0.32.1+1')))

class ParserTests(unittest.TestCase):
    def test_actual_java_stream_parser(self):
        javac=JDK/'bin/javac.exe';java=JDK/'bin/java.exe'
        if not javac.exists():
            candidate=ROOT
            while candidate.parent!=candidate:
                fallback=candidate/'build_tools/jdk_extracted/jdk-11.0.32.1+1'
                if (fallback/'bin/javac.exe').exists():javac=fallback/'bin/javac.exe';java=fallback/'bin/java.exe';break
                candidate=candidate.parent
        self.assertTrue(javac.exists(),'JDK is required')
        files={
'javacard/framework/ISO7816.java':'''package javacard.framework; public interface ISO7816 {short SW_WRONG_DATA=(short)0x6a80, SW_WRONG_LENGTH=(short)0x6700;}''',
'javacard/framework/ISOException.java':'''package javacard.framework; public class ISOException extends RuntimeException {public final short sw; public ISOException(short s){sw=s;} public static void throwIt(short s){throw new ISOException(s);}}''',
'javacard/framework/JCSystem.java':'''package javacard.framework; public class JCSystem {public static final byte CLEAR_ON_DESELECT=2;public static short[] makeTransientShortArray(short n,byte e){return new short[n];}}''',
'javacard/framework/Util.java':'''package javacard.framework; public class Util {public static short getShort(byte[] b,short o){return (short)(((b[o]&255)<<8)|(b[o+1]&255));}public static short arrayFillNonAtomic(byte[] b,short o,short n,byte v){java.util.Arrays.fill(b,o,o+n,v);return (short)(o+n);}}''',
'fr/anssi/smartpgp/Constants.java':'''package fr.anssi.smartpgp; class Constants {static final short SW_CHAINING_ERROR=(short)0x6883;}''',
'fr/anssi/smartpgp/Common.java':'''package fr.anssi.smartpgp; class Common {static short bitsToBytes(short n){return (short)((n+7)/8);}}''',
'fr/anssi/smartpgp/ECCurves.java':'''package fr.anssi.smartpgp; class ECCurves {}''',
'fr/anssi/smartpgp/Persistent.java':'''package fr.anssi.smartpgp; class Persistent {static final byte PGP_KEYS_OFFSET_SIG=0,PGP_KEYS_OFFSET_DEC=1,PGP_KEYS_OFFSET_AUT=2;}''',
'fr/anssi/smartpgp/PGPKey.java':'''package fr.anssi.smartpgp;
class PGPKey {short bits; boolean old=true,valid=true,started=false,throwAbort=false;int begins,sets,aborts;byte[][] parts=new byte[7][];
PGPKey(short b){bits=b;}boolean isRsa(){return true;}short rsaModulusBitSize(){return bits;}
void beginStreamImport(){begins++;old=false;valid=false;started=true;}
void setStreamComponent(short c,byte[] b,short n){if(!started||valid)throw new AssertionError();parts[c]=java.util.Arrays.copyOf(b,n);sets++;}
void finishStreamImport(Common c,ECCurves e,byte[] b){if(sets!=7)throw new AssertionError();valid=true;started=false;}
void abortStreamImport(){aborts++;if(throwAbort)throw new RuntimeException("simulated native cleanup failure");valid=false;started=false;for(int i=0;i<7;i++)parts[i]=null;}}
''',
'fr/anssi/smartpgp/Harness.java':r'''package fr.anssi.smartpgp;
import java.io.*;import java.util.*;import javacard.framework.ISOException;
public class Harness {
 static int checks=0;
 static void ck(boolean v){checks++;if(!v)throw new AssertionError("check "+checks);}
 static byte[] len(int n){return n<128?new byte[]{(byte)n}:n<256?new byte[]{(byte)0x81,(byte)n}:new byte[]{(byte)0x82,(byte)(n>>8),(byte)n};}
 static byte[] cat(byte[]...a){ByteArrayOutputStream b=new ByteArrayOutputStream();for(byte[] v:a)b.write(v,0,v.length);return b.toByteArray();}
 static byte[] tl(byte[] t,byte[] v){return cat(t,len(v.length),v);}
 static byte[][] values(int bits){byte[][] a=new byte[7][];for(int i=0;i<7;i++){a[i]=new byte[i==0?3:i==6?bits/8:bits/16];for(int j=0;j<a[i].length;j++)a[i][j]=(byte)(i*19+j);}return a;}
 static byte[] make(int bits,int slot,boolean extended){byte[][] vs=values(bits);byte[] t=new byte[0];for(int i=0;i<7;i++)t=cat(t,new byte[]{(byte)(0x91+i)},len(vs[i].length));byte crt=(byte)(slot==0?0xb6:slot==1?0xb8:0xa4);
 byte[] body=cat(extended?new byte[]{crt,3,(byte)0x84,1,(byte)(slot+1)}:new byte[]{crt,0},tl(new byte[]{0x7f,0x48},t),tl(new byte[]{0x5f,0x48},cat(vs)));return tl(new byte[]{0x4d},body);}
 static PGPKey[] keys(int bits){return new PGPKey[]{new PGPKey((short)bits),new PGPKey((short)bits),new PGPKey((short)bits)};}
 static void feed(RsaImportStream s,PGPKey[] k,byte[] work,byte[] body,int count,int split){for(int off=0;off<count;){int n=Math.min(split,count-off);s.accept(body,(short)off,(short)n,work,k);off+=n;}}
 static void success(int bits,int slot,boolean ext,int split){byte[] body=make(bits,slot,ext),work=new byte[1280];PGPKey[] k=keys(bits);RsaImportStream s=new RsaImportStream();s.begin();feed(s,k,work,body,body.length,split);ck(!k[slot].valid);ck(s.finish(new Common(),new ECCurves(),work,k)==slot);ck(k[slot].valid);ck(!s.active());byte[][] expected=values(bits);for(int i=0;i<7;i++)ck(Arrays.equals(expected[i],k[slot].parts[i]));s.clear(k);ck(k[slot].valid);}
 public static void main(String[] args){
 for(int bits:new int[]{3072,4096})for(int slot=0;slot<3;slot++)for(boolean ext:new boolean[]{false,true})for(int split:new int[]{1,2,3,5,7,16,127,200,255,512,2000})success(bits,slot,ext,split);
 byte[] body=make(4096,0,false);
 for(int cut=0;cut<body.length;cut++){PGPKey[] k=keys(4096);RsaImportStream s=new RsaImportStream();s.begin();byte[] w=new byte[1280];feed(s,k,w,body,cut,37);boolean rejected=false;try{s.finish(new Common(),new ECCurves(),w,k);}catch(ISOException e){rejected=true;}ck(rejected);s.clear(k);ck(k[0].begins==0?k[0].old&&!k[0].started:!k[0].valid&&!k[0].started);}
 for(int at:new int[]{0,1,4,5,6,7,10,11,12}){byte[] bad=body.clone();bad[at]=(byte)0xff;PGPKey[] k=keys(4096);RsaImportStream s=new RsaImportStream();s.begin();boolean rejected=false;try{feed(s,k,new byte[1280],bad,bad.length,1);s.requireFinalLength();}catch(ISOException e){rejected=true;}ck(rejected);ck(k[0].begins==0);s.clear(k);}
 // Trailing bytes are rejected and incomplete/newly written key stays unactivated.
 PGPKey[] k=keys(4096);RsaImportStream s=new RsaImportStream();s.begin();byte[] extra=cat(body,new byte[]{1});boolean rejected=false;try{feed(s,k,new byte[1280],extra,extra.length,113);}catch(ISOException e){rejected=true;}ck(rejected);ck(!k[0].valid);s.clear(k);ck(!k[0].valid);
 // RSA2048 uses the old full-buffer parser without touching native key objects.
 body=make(2048,0,false);k=keys(2048);s=new RsaImportStream();s.begin();byte[] w=new byte[1280];feed(s,k,w,body,body.length,1);s.requireFinalLength();ck(!s.streamed());ck(s.bufferedLength()==body.length);ck(Arrays.equals(body,Arrays.copyOf(w,body.length)));ck(k[0].begins==0);s.clear(k);
 // Even a native cleanup exception must clear transient parser state.
 k=keys(4096);s=new RsaImportStream();s.begin();body=make(4096,0,false);feed(s,k,new byte[1280],body,100,100);k[0].throwAbort=true;
 boolean failed=false;try{s.clear(k);}catch(RuntimeException e){failed=true;}ck(failed);ck(!s.active());ck(!k[0].valid);
 System.out.println("Actual parser checks passed: "+checks+"; 132 fragmentation variants and every RSA4096 truncation offset.");
 }
}'''
        }
        work=ROOT/'build/parser-tests';work.mkdir(parents=True,exist_ok=True)
        for n,t in files.items():p=work/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(t,encoding='utf-8')
        n='fr/anssi/smartpgp/RsaImportStream.java';(work/n).write_bytes((ROOT/'src'/n).read_bytes());files[n]=''
        classes=work/'classes';classes.mkdir(exist_ok=True)
        proc=subprocess.run([str(javac),'-encoding','UTF-8','-d',str(classes),*[str(work/n) for n in files]],capture_output=True,text=True)
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        proc=subprocess.run([str(java),'-cp',str(classes),'fr.anssi.smartpgp.Harness'],capture_output=True,text=True)
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr);print(proc.stdout)

if __name__=='__main__':unittest.main()
