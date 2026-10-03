"""Destructive full-review regressions: PIN/PUK changes and SCP11b malformed input.
Only an explicitly selected test instance. The suite restores PINs on normal paths,
but reinstall after tests: it provisions a static SM key and writes test metadata.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from security_card import Card, Suite, helper, ROOT


def cmac(key,data):
    c=CMAC(algorithms.AES(key));c.update(data);return c.finalize()
def aes(key,data,iv=None,decrypt=False):
    c=Cipher(algorithms.AES(key),modes.ECB() if iv is None else modes.CBC(iv))
    op=c.decryptor() if decrypt else c.encryptor();return op.update(data)+op.finalize()

class SmSession:
    def __init__(self,suite):
        self.suite=suite
        blob=suite.pub(0xa6);static=dict(helper.tlv(dict(helper.tlv(blob))[0x7f49]))[0x86]
        host=ec.generate_private_key(ec.SECP256R1());hp=host.public_key().public_bytes(Encoding.X962,PublicFormat.UncompressedPoint)
        request=bytes.fromhex('a60d9002110095013c8001888101105f4941')+hp
        reply=suite.need(helper.apdu(0x88,1,0,request));parts=dict(helper.tlv(reply));ep=parts[0x5f49];receipt=parts[0x86]
        shared=host.exchange(ec.ECDH(),ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),ep))+host.exchange(ec.ECDH(),ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),static))
        material=b''.join(hashlib.sha256(shared+i.to_bytes(4,'big')+bytes.fromhex('3c8810')).digest() for i in (1,2))
        kr,self.ke,self.km,self.krm=[material[i:i+16] for i in range(0,64,16)]
        if not hmac.compare_digest(receipt,cmac(kr,request+bytes.fromhex('5f4941')+ep)):raise RuntimeError('Bad SM receipt')
        self.chain=receipt;self.counter=0
    def command(self,ins,p1,p2,plain=b'',raw_padded=None,tamper_mac=None):
        self.counter+=1;encrypted=b''
        if raw_padded is not None or plain:
            data=raw_padded if raw_padded is not None else plain+b'\x80'+bytes((-len(plain)-1)%16)
            encrypted=aes(self.ke,data,aes(self.ke,self.counter.to_bytes(16,'big')))
        if len(encrypted)+8>255:raise ValueError('test supports short protected commands only')
        header=bytes([4,ins,p1,p2,len(encrypted)+8]);self.chain=cmac(self.km,self.chain+header+encrypted);tag=bytearray(self.chain[:8])
        if tamper_mac is not None:tag[tamper_mac]^=1
        reply,sw=self.suite.exchange(header+encrypted+tag+b'\x00')
        if not reply:return b'',sw
        if len(reply)<8:raise RuntimeError('Truncated protected response')
        ct,mac=reply[:-8],reply[-8:]
        if not hmac.compare_digest(mac,cmac(self.krm,self.chain+ct+sw.to_bytes(2,'big'))[:8]):raise RuntimeError('Bad protected response MAC')
        if not ct:return b'',sw
        iv=bytearray(self.counter.to_bytes(16,'big'));iv[0]=128
        padded=aes(self.ke,ct,aes(self.ke,bytes(iv)),True);decoded=padded.rstrip(b'\x00')
        if not decoded.endswith(b'\x80') or len(padded)-len(decoded)+1>16:raise RuntimeError('Bad response padding')
        return decoded[:-1],sw
    def need(self,ins,p1,p2,plain=b'',**kwargs):
        result,sw=self.command(ins,p1,p2,plain,**kwargs)
        if sw!=0x9000:raise RuntimeError(f'SM INS={ins:02x},SW={sw:04x}')
        return result

class ReviewSuite(Suite):
    def raw_change(self,mode,old,new):return self.exchange(helper.apdu(0x24,0,mode,old+new,False))
    def pin_bounds(self,baseline=False):
        self.select();observations=[]
        for mode,index,default,long in [(0x81,4,b'123456',b'U'*64),(0x83,6,b'12345678',b'A'*64)]:
            data,sw=self.raw_change(mode,default,long)
            self.check(f'PW{mode:02x}_set_long_test_PIN',sw==0x9000)
            try:
                before=self.need(helper.apdu(0xca,0,0xc4))[index]
                data,sw=self.exchange(helper.apdu(0x24,0,mode,b'X'*16,False))
                after=self.need(helper.apdu(0xca,0,0xc4))[index]
                observations.append({'PIN_reference':f'{mode:02x}','truncated_command_SW':f'{sw:04x}','tries_before':before,'tries_after':after})
                if not baseline:self.check(f'PW{mode:02x}_truncated_change_no_PIN_attempt',sw==0x6700 and not data and before==after)
            finally:
                _,sw=self.raw_change(mode,long,default)
                if sw!=0x9000:raise RuntimeError('Could not restore test PIN; stop and reinstall')
            self.check(f'PW{mode:02x}_restored_default',True)
        self.pin();self.need(helper.apdu(0xda,0,0xd3,b'P'*64,False))
        try:
            before=self.need(helper.apdu(0xca,0,0xc4))[5]
            _,sw=self.exchange(helper.apdu(0x2c,0,0x81,b'X'*16,False))
            after=self.need(helper.apdu(0xca,0,0xc4))[5]
            observations.append({'PIN_reference':'PUK','truncated_command_SW':f'{sw:04x}','tries_before':before,'tries_after':after})
            if not baseline:self.check('PUK_truncated_reset_no_PIN_attempt',sw==0x6700 and before==after)
            self.need(helper.apdu(0x2c,0,0x81,b'P'*64+b'123456',False))
            self.check('PUK_valid_reset_works',True)
        finally:self.select()
        return observations
    def protocol_and_crypto(self):
        # Data objects protected by the correct reference, not just any PIN.
        for tag,mode in [(0x0103,0x82),(0x0104,0x83)]:
            self.pin(mode);value=b'private DO test '+bytes([tag&255]);self.need(helper.apdu(0xda,tag>>8,tag&255,value,False));self.select()
            data,sw=self.exchange(helper.apdu(0xca,tag>>8,tag&255));self.check(f'DO{tag:04x}_unauth_read_rejected',sw==0x6982 and not data)
            self.pin(mode);self.check(f'DO{tag:04x}_authorized_read',self.need(helper.apdu(0xca,tag>>8,tag&255))==value)
        # Slot selection must survive unrelated GET DATA then a new SELECT DATA.
        for occurrence in (0,1,2):
            self.need(helper.apdu(0xa5,occurrence,4,bytes.fromhex('60045c027f21'),False));self.pin()
            cert=bytes([0x40+occurrence])*17;self.need(helper.apdu(0xda,0x7f,0x21,cert,False))
            self.check(f'certificate_occurrence_{occurrence}',self.need(helper.apdu(0xca,0x7f,0x21))==cert)
        self.need(helper.apdu(0xca,0,0xc4));self.need(helper.apdu(0xa5,1,4,bytes.fromhex('60045c027f21'),False))
        self.check('certificate_select_after_different_DO',self.need(helper.apdu(0xca,0x7f,0x21))==bytes([0x41])*17)
        self.attr(0xc2,'122a8648ce3d030107');self.gen(0xb8)
        for name,point in [('wrong_form',b'\x02'+bytes(64)),('off_curve',b'\x04'+bytes(64))]:
            self.pin(0x82);data,sw=self.exchange(helper.apdu(0x2a,0x80,0x86,bytes.fromhex('a6467f49438641')+point))
            self.check('ECDH_'+name+'_rejected',sw!=0x9000 and not data)
        self.gen(0xa6);self.select()
        session=SmSession(self)
        # A plain rehandshake must not inherit a previously authenticated admin PIN.
        session.need(0x20,0,0x83,b'12345678');new=SmSession(self)
        data,sw=new.command(0xda,0,0x5e,b'unauthorized')
        self.check('SM_rekey_does_not_inherit_admin',sw==0x6982 and not data)
        # Every legal padding length, including empty plaintext with a full padding block.
        session=SmSession(self);session.need(0x20,0,0x83,b'12345678')
        for size in [0,*range(1,33),63,64,65,127,223]:
            value=bytes((i*13+size)%256 for i in range(size))
            session.need(0xda,0x01,0x04,value)
            self.check(f'SM_padding_length_roundtrip_{size}',session.need(0xca,0x01,0x04)==value)
        session.need(0xda,0x01,0x04,raw_padded=b'\x80'+bytes(15))
        self.check('SM_explicit_empty_padded_command',session.need(0xca,0x01,0x04)==b'')
        # Authenticated bad padding must fail and leave DO unchanged.
        for label,bad in [('zeros16',bytes(16)),('zeros32',bytes(32)),('padding_over_one_block',b'\x80'+bytes(31)),('missing_marker',b'X'+bytes(15)),('garbage_after_marker',b'\x80'+bytes(14)+b'\x01')]:
            session=SmSession(self);session.need(0x20,0,0x83,b'12345678');session.need(0xda,0x01,0x04,b'unchanged')
            data,sw=session.command(0xda,0x01,0x04,raw_padded=bad)
            self.check('SM_authenticated_bad_padding_'+label,sw==0x6982 and not data)
            session=SmSession(self);session.need(0x20,0,0x83,b'12345678')
            self.check('SM_bad_padding_keeps_DO_'+label,session.need(0xca,0x01,0x04)==b'unchanged')
        for position in range(8):
            session=SmSession(self);data,sw=session.command(0xca,0,0xc4,tamper_mac=position)
            self.check(f'SM_bad_MAC_byte_{position}',sw==0x6982 and not data)
        session=SmSession(self);session.need(0x20,0,0x83,b'12345678')
        self.check('SM_recovers_after_errors',len(session.need(0xca,0,0xc4))==7)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reader',required=True);p.add_argument('--expect-aid',required=True);p.add_argument('--allow-key-replacement',action='store_true');p.add_argument('--baseline-pin-only',action='store_true');p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if not a.allow_key_replacement:p.error('destructive test flag required')
    card=Card(a.reader);s=ReviewSuite(card);done=False;observations=[]
    try:
        s.select()
        if s.need(helper.apdu(0xca,0,0x4f)).hex().upper()!=a.expect_aid.upper():raise RuntimeError('Wrong card AID')
        observations=s.pin_bounds(a.baseline_pin_only)
        if not a.baseline_pin_only:s.protocol_and_crypto()
        done=True
    finally:
        card.close();a.report.parent.mkdir(parents=True,exist_ok=True)
        a.report.write_text(json.dumps({'completed':done,'baseline_pin_only':a.baseline_pin_only,'pin_observations':observations,'checks':s.results},indent=2),encoding='utf-8')
if __name__=='__main__':main()
