"""Destructive test: all advertised SCP11b EC curves and 128/256-bit AES sessions.
Uses host-generated ephemeral keys and independent cryptography. Resets the applet
between cases. Never run on an instance with production keys or user data.
"""
import argparse
import json
from pathlib import Path
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from security_review_card import Card,ReviewSuite,SmSession,helper,ROOT

CASES=[('P256','122a8648ce3d030107',ec.SECP256R1()),
       ('P384','122b81040022',ec.SECP384R1()),
       ('P521','122b81040023',ec.SECP521R1()),
       ('brainpoolP256','122b2403030208010107',ec.BrainpoolP256R1()),
       ('brainpoolP384','122b240303020801010b',ec.BrainpoolP384R1()),
       ('brainpoolP512','122b240303020801010d',ec.BrainpoolP512R1())]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reader',required=True);p.add_argument('--expect-aid',required=True);p.add_argument('--allow-key-replacement',action='store_true');p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if not a.allow_key_replacement:p.error('Explicit destructive test authorization required')
    c=Card(a.reader);s=ReviewSuite(c);done=False
    try:
        s.select()
        if s.need(helper.apdu(0xca,0,0x4f)).hex().upper()!=a.expect_aid.upper():raise RuntimeError('Wrong card AID')
        for label,attr,curve in CASES:
            s.attr(0xd4,attr);s.gen(0xa6);s.select()
            session=SmSession(s,curve);s.check(label+'_independent_SCP11b_receipt',True)
            session.need(0x20,0,0x83,b'12345678')
            for size in (0,1,15,16,17,127,223):
                value=bytes((i*29+size)%256 for i in range(size))
                session.need(0xda,1,4,value)
                s.check(label+'_AES'+str(len(session.ke)*8)+'_encrypted_roundtrip_'+str(size),session.need(0xca,1,4)==value)
            # Rekey clears previous authorization; authenticate only in the new session.
            new=SmSession(s,curve);data,sw=new.command(0xda,1,4,b'must fail')
            s.check(label+'_rekey_revokes_authorization',sw==0x6982 and not data)
            session=SmSession(s,curve);session.need(0x20,0,0x83,b'12345678')
            data,sw=session.command(0xca,0,0xc4,tamper_mac=7)
            s.check(label+'_bad_MAC_rejected',sw==0x6982 and not data)
            session=SmSession(s,curve);session.need(0x20,0,0x83,b'12345678');session.need(0xe6,0,0)
            s.need(bytes.fromhex('00440001'));s.select()
            s.check(label+'_reset_clears_static_and_data_keys',s.need(helper.apdu(0xca,0,0xde))==bytes.fromhex('de06010002000300'))
            s.pin();s.select()
        done=True
    finally:
        c.close();a.report.parent.mkdir(parents=True,exist_ok=True)
        a.report.write_text(json.dumps({'completed':done,'checks':s.results,'tested_cap_sha256':hashlib.sha256((ROOT/'dist/SmartPGPApplet.cap').read_bytes()).hexdigest()},indent=2),encoding='utf-8')

if __name__=='__main__':main()
