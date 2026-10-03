"""Destructive large RSA import experiment on an explicitly authorized test card.
Independent host key generation, public readback, signature verification and decrypt.
Never invoke on a card containing production keys.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
from security_card import Card, Suite, helper, ROOT


def length(n):
    return bytes([n]) if n<128 else (b'\x81'+bytes([n]) if n<256 else b'\x82'+n.to_bytes(2,'big'))
def tl(tag,v):return tag+length(len(v))+v

def import_body(key,crt,extended=False):
    n=key.private_numbers();pub=n.public_numbers;w=key.key_size//8;half=w//2
    parts=[pub.e.to_bytes(3,'big'),n.p.to_bytes(half,'big'),n.q.to_bytes(half,'big'),
           n.iqmp.to_bytes(half,'big'),n.dmp1.to_bytes(half,'big'),n.dmq1.to_bytes(half,'big'),pub.n.to_bytes(w,'big')]
    template=b''.join(bytes([0x91+i])+length(len(v)) for i,v in enumerate(parts))
    crt_body=bytes([crt,3,0x84,1,{0xb6:1,0xb8:2,0xa4:3}[crt]]) if extended else bytes([crt,0])
    return tl(b'\x4d',crt_body+tl(b'\x7f\x48',template)+tl(b'\x5f\x48',b''.join(parts)))

class StreamSuite(Suite):
    def transfer(self,blob,split=200,leading_bytes=0,allow_rejection=False):
        count=0
        while len(blob)>split or leading_bytes>0:
            n=1 if leading_bytes else split
            n=min(n,len(blob))
            if n==len(blob):break
            data,sw=self.exchange(bytes([0x10,0xdb,0x3f,0xff,n])+blob[:n])
            if sw!=0x9000 and allow_rejection:return data,sw
            if sw!=0x9000 or data:raise RuntimeError(f'import intermediate fragment #{count} failed SW={sw:04x}')
            blob=blob[n:];count+=1;leading_bytes=max(0,leading_bytes-1)
        return self.exchange(helper.apdu(0xdb,0x3f,0xff,blob,False))
    def verify_key(self,key,crt,name):
        pub=key.public_key();want=pub.public_numbers()
        d=dict(helper.tlv(dict(helper.tlv(self.pub(crt)))[0x7f49]))
        self.check(name+'_public_key_matches',int.from_bytes(d[0x81],'big')==want.n and int.from_bytes(d[0x82],'big')==want.e)
        digest=os.urandom(32)
        if crt==0xb6:
            self.pin(0x81)
            sig=self.need(helper.apdu(0x2a,0x9e,0x9a,bytes.fromhex('3031300d060960864801650304020105000420')+digest))
            pub.verify(sig,digest,padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()))
            self.check(name+'_independent_signature',True)
        elif crt==0xa4:
            self.pin(0x82)
            sig=self.need(helper.apdu(0x88,0,0,digest))
            # INTERNAL AUTHENTICATE's raw payload is PKCS#1 type-1 padded, no DigestInfo.
            block=pow(int.from_bytes(sig,'big'),want.e,want.n).to_bytes(key.key_size//8,'big')
            self.check(name+'_independent_auth',block==b'\x00\x01'+b'\xff'*(len(block)-len(digest)-3)+b'\x00'+digest)
        else:
            plain=b'RSA streaming import test '+os.urandom(16);ct=pub.encrypt(plain,padding.PKCS1v15())
            self.pin(0x82);got,sw=self.long(0x2a,0x80,0x86,b'\x00'+ct)
            self.check(name+'_independent_decrypt',sw==0x9000 and got==plain)
    def run_stream(self):
        self.select()
        for bits in (3072,4096):
            key=rsa.generate_private_key(public_exponent=65537,key_size=bits)
            for crt,tag,label,split in [(0xb6,0xc1,'SIG',200),(0xb8,0xc2,'DEC',127),(0xa4,0xc3,'AUT',255)]:
                self.attr(tag,f'01{bits:04x}001103')
                blob=import_body(key,crt,extended=crt==0xa4)
                self.pin();data,sw=self.transfer(blob,split,leading_bytes=48 if crt==0xb6 else 0)
                self.check(f'RSA{bits}_{label}_external_import',sw==0x9000 and not data)
                self.verify_key(key,crt,f'RSA{bits}_{label}')
            self.negative_cases(key)
        constants=(ROOT/'src/fr/anssi/smartpgp/Constants.java').read_text(encoding='utf-8')
        self.check('work_buffer_remains_1280','(short)0x500;' in constants)
    def negative_cases(self,key):
        bits=key.key_size;blob=import_body(key,0xb6);before=self.pub(0xb6)
        # Malformed metadata must not destroy the previously validated SIG key.
        bad=bytearray(blob);index=bad.index(bytes.fromhex('7f48'))+3;bad[index]=0x99
        self.pin();_,sw=self.transfer(bytes(bad),allow_rejection=True)
        self.check(f'RSA{bits}_malformed_header_rejected',sw==0x6a80)
        self.check(f'RSA{bits}_malformed_header_keeps_key',self.pub(0xb6)==before)
        # Once valid header starts native writes, interrupting the command cannot expose partial key.
        self.pin();_,sw=self.exchange(bytes([0x10,0xdb,0x3f,0xff,200])+blob[:200]);self.check(f'RSA{bits}_partial_fragment_accepted',sw==0x9000)
        _,sw=self.exchange(helper.apdu(0xca,0,0xc4));self.check(f'RSA{bits}_interleaved_command_rejected',sw==0x6883)
        _,sw=self.exchange(helper.apdu(0x47,0x81,0,b'\xb6\x00'));self.check(f'RSA{bits}_partial_key_unavailable',sw==0x6a88)
        # Recovery after interrupted import.
        self.pin();_,sw=self.transfer(blob,200);self.check(f'RSA{bits}_recovery_import',sw==0x9000)
        self.verify_key(key,0xb6,f'RSA{bits}_recovered')
        # Final fragment too short and extra final bytes are both rejected before activation.
        self.pin();_,sw=self.transfer(blob[:-1]);self.check(f'RSA{bits}_truncated_rejected',sw==0x6700)
        _,sw=self.exchange(helper.apdu(0x47,0x81,0,b'\xb6\x00'));self.check(f'RSA{bits}_truncated_key_unavailable',sw==0x6a88)
        self.pin();_,sw=self.transfer(blob+b'\x00');self.check(f'RSA{bits}_extra_data_rejected',sw==0x6700)
        self.pin();_,sw=self.transfer(blob);self.check(f'RSA{bits}_restore_valid_key',sw==0x9000)
        # Reselect must abort pending import while leaving the other two slots intact.
        dec=self.pub(0xb8);auth=self.pub(0xa4)
        self.pin();_,sw=self.exchange(bytes([0x10,0xdb,0x3f,0xff,200])+blob[:200]);self.check(f'RSA{bits}_reselect_setup',sw==0x9000)
        self.select();_,sw=self.exchange(helper.apdu(0x47,0x81,0,b'\xb6\x00'));self.check(f'RSA{bits}_reselect_clears_partial',sw==0x6a88)
        self.check(f'RSA{bits}_other_slots_preserved',self.pub(0xb8)==dec and self.pub(0xa4)==auth)
        # No admin verification since SELECT: a fragment must not begin import.
        _,sw=self.exchange(bytes([0x10,0xdb,0x3f,0xff,200])+blob[:200]);self.check(f'RSA{bits}_unauthorized_import_rejected',sw==0x6982)
        self.pin();_,sw=self.transfer(blob);self.check(f'RSA{bits}_final_restore',sw==0x9000)
        # Corrupt the separately imported public modulus: activation must fail.
        mismatched=bytearray(blob);mismatched[-1]^=2
        self.pin();data,sw=self.transfer(bytes(mismatched),allow_rejection=True)
        self.check(f'RSA{bits}_pair_mismatch_rejected',sw in (0x6a80,0x6f00,0x6985) and not data)
        _,sw=self.exchange(helper.apdu(0x47,0x81,0,b'\xb6\x00'));self.check(f'RSA{bits}_mismatched_key_unavailable',sw==0x6a88)
        self.pin();_,sw=self.transfer(blob);self.check(f'RSA{bits}_recover_from_pair_mismatch',sw==0x9000)
        self.verify_key(key,0xb6,f'RSA{bits}_final')
        # Controlled reset at a completed APDU boundary, not arbitrary physical tearing.
        self.pin();_,sw=self.exchange(bytes([0x10,0xdb,0x3f,0xff,200])+blob[:200]);self.check(f'RSA{bits}_reset_setup',sw==0x9000)
        old=self.c;reader=old.reader
        old.check(old.dll.SCardDisconnect(old.h,1));old.h.value=0;old.close()
        self.c=Card(reader);self.select()
        _,sw=self.exchange(helper.apdu(0x47,0x81,0,b'\xb6\x00'));self.check(f'RSA{bits}_reset_partial_key_unavailable',sw==0x6a88)
        self.pin();_,sw=self.transfer(blob);self.check(f'RSA{bits}_recover_after_reset',sw==0x9000)
        self.verify_key(key,0xb6,f'RSA{bits}_after_reset')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reader',required=True);p.add_argument('--allow-key-replacement',action='store_true');p.add_argument('--expect-aid',required=True);p.add_argument('--report',type=Path,default=ROOT/'build/test-results/rsa-stream-card.json');args=p.parse_args()
    if not args.allow_key_replacement:p.error('explicit destructive-test flag required')
    card=Card(args.reader);suite=StreamSuite(card);completed=False
    try:
        suite.select();actual=suite.need(helper.apdu(0xca,0,0x4f)).hex().upper()
        if actual!=args.expect_aid.upper():raise RuntimeError('Unexpected card; no key-changing command sent')
        suite.run_stream();completed=True
    finally:
        suite.c.close();args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps({'completed':completed,'reader':card.reader,'cap_sha256':hashlib.sha256((ROOT/'dist/SmartPGPApplet.cap').read_bytes()).hexdigest(),'results':suite.results},indent=2),encoding='utf-8')
if __name__=='__main__':main()
