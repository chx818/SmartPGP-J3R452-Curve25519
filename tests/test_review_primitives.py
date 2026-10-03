"""Execute exact Java helpers on host. Finite functional tests, not timing/SCA certification."""
from pathlib import Path
import os
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]

def extract(text, signature):
    start=text.index(signature);off=text.index('{',start);depth=1;end=off+1
    while depth:
        depth+=(text[end]=='{')-(text[end]=='}');end+=1
    return text[start:end]

class ReviewPrimitives(unittest.TestCase):
    def test_padding_and_pin_bounds_actual_java(self):
        jdk=Path(os.environ.get('JAVA_HOME',''))
        if not (jdk/'bin/javac.exe').exists():jdk=ROOT.parent/'build_tools/jdk_extracted/jdk-11.0.32.1+1'
        self.assertTrue((jdk/'bin/javac.exe').exists())
        work=ROOT/'build/review-primitive-tests';work.mkdir(parents=True,exist_ok=True)
        src=(ROOT/'src/fr/anssi/smartpgp/Common.java').read_text(encoding='utf-8')
        helpers='\n'.join(extract(src,s) for s in ['    protected static short unpad80(', '    protected static short newPinLength('])
        # Detect accidental reintroduction of a content-controlled loop into the padding helper.
        unpad=extract(src,'    protected static short unpad80(')
        self.assertNotIn('while(',unpad);self.assertEqual(unpad.count('buf['),1)
        files={
          'javacard/framework/ISOException.java':'package javacard.framework; public class ISOException extends RuntimeException {public static void throwIt(short v){throw new ISOException();}}',
          'javacard/framework/ISO7816.java':'package javacard.framework; public interface ISO7816 {short SW_WRONG_LENGTH=(short)0x6700,SW_SECURITY_STATUS_NOT_SATISFIED=(short)0x6982;}',
          'fr/anssi/smartpgp/Constants.java':'package fr.anssi.smartpgp; class Constants {static final short AES_BLOCK_SIZE=16;}',
          'fr/anssi/smartpgp/Common.java':'package fr.anssi.smartpgp; import javacard.framework.*; class Common {'+helpers+'}',
          'fr/anssi/smartpgp/Harness.java':r'''package fr.anssi.smartpgp;
import java.util.*;import javacard.framework.ISOException;
public class Harness {
 static int checks;
 static void ck(boolean c){checks++;if(!c)throw new AssertionError("case "+checks);}
 static int reference(byte[] b){int i=b.length-1;int limit=b.length-16;while(i>=limit&&b[i]==0)i--;return i>=limit&&b[i]==(byte)128?i:-1;}
 static int actual(byte[] b){try{return Common.unpad80(b,(short)b.length);}catch(ISOException e){return -1;}}
 public static void main(String[] args){
 Random random=new Random(20261003L);
 for(int blocks=1;blocks<=8;blocks++)for(int pad=1;pad<=16;pad++) {
  byte[] b=new byte[blocks*16];random.nextBytes(b);int end=b.length-pad;b[end]=(byte)128;Arrays.fill(b,end+1,b.length,(byte)0);
  ck(actual(b)==end);
  for(int where=b.length-16;where<b.length;where++)for(int value=0;value<256;value++) {
   byte[] c=b.clone();c[where]=(byte)value;ck(actual(c)==reference(c));
  }
 }
 for(int i=0;i<10000;i++){byte[] b=new byte[32];random.nextBytes(b);ck(actual(b)==reference(b));}
 byte[] bad=new byte[32];bad[15]=(byte)128;ck(actual(bad)==-1);ck(actual(new byte[0])==-1);ck(actual(new byte[15])==-1);
 for(short old=0;old<=127;old++)for(short size=0;size<=300;size++) {
  boolean plain=size>=6&&size<=127;boolean accepted=true;
  try{ck(Common.newPinLength((short)(old+size),old,(short)6,(short)0)==size);}catch(ISOException e){accepted=false;}
  ck(accepted==plain);
  accepted=true;try{Common.newPinLength((short)(old+size),old,(short)6,(short)64);}catch(ISOException e){accepted=false;}
  ck(accepted==(size==64));
 }
 boolean rejected=false;try{Common.newPinLength((short)12,(short)64,(short)6,(short)0);}catch(ISOException e){rejected=true;}ck(rejected);
 System.out.println("Actual padding/PIN helper checks passed: "+checks);
 }
}'''}
        for n,s in files.items():p=work/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(s,encoding='utf-8')
        classes=work/'classes';classes.mkdir(exist_ok=True)
        for cmd in [[jdk/'bin/javac.exe','-encoding','UTF-8','-d',classes,*[work/n for n in files]], [jdk/'bin/java.exe','-cp',classes,'fr.anssi.smartpgp.Harness']]:
            result=subprocess.run(list(map(str,cmd)),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            print(result.stdout)

if __name__=='__main__':unittest.main()
