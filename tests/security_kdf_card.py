"""Destructive PIN-format migration tests. Host-derived test values only, no SM.
Checks the card-side 32/64-byte KDF data-object contract; not a full GnuPG S2K test.
Restores default PINs/KDF on successful completion; reinstall after a failed run.
"""
import argparse
import hashlib
import json
from pathlib import Path
from security_card import Card,Suite,helper,ROOT

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reader',required=True);p.add_argument('--expect-aid',required=True);p.add_argument('--allow-key-replacement',action='store_true');p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if not a.allow_key_replacement:p.error('Explicit destructive flag required')
    card=Card(a.reader);s=Suite(card);done=False
    def verify(mode,value):return s.need(helper.apdu(0x20,0,mode,value,False))
    def change(mode,old,new):return s.need(helper.apdu(0x24,0,mode,old+new,False))
    try:
        s.select()
        if s.need(helper.apdu(0xca,0,0x4f)).hex().upper()!=a.expect_aid.upper():raise RuntimeError('Wrong card AID')
        for size,algo,digest in [(32,8,hashlib.sha256),(64,10,hashlib.sha512)]:
            user=digest(b'public KDF test user').digest();admin=digest(b'public KDF test admin').digest();reset=digest(b'public KDF test reset').digest();newuser=digest(b'public KDF changed user').digest()
            # Provision complete opaque derived credentials while KDF mode is still off.
            change(0x81,b'123456',user);change(0x83,b'12345678',admin)
            s.need(helper.apdu(0xda,0,0xd3,reset,False))
            kdf=bytes([0x81,1,3,0x82,1,algo,0x83,4,0,1,0,0,0x84,8])+bytes(range(8))
            s.need(helper.apdu(0xda,0,0xf9,kdf,False));s.select()
            s.check(f'KDF{size}_metadata_readback',s.need(helper.apdu(0xca,0,0xf9))==kdf)
            verify(0x81,user);verify(0x83,admin)
            s.check(f'KDF{size}_credential_sizes',s.need(helper.apdu(0xca,0,0xc4))[1:4]==bytes([size]*3))
            before=s.need(helper.apdu(0xca,0,0xc4))[4:]
            data,sw=s.exchange(helper.apdu(0x24,0,0x81,user+newuser[:-1],False))
            s.check(f'KDF{size}_short_new_PIN_rejected',sw==0x6700 and not data)
            s.check(f'KDF{size}_bad_length_preserves_tries',s.need(helper.apdu(0xca,0,0xc4))[4:]==before)
            change(0x81,user,newuser);verify(0x81,newuser);s.check(f'KDF{size}_valid_change',True)
            s.need(helper.apdu(0x2c,0,0x81,reset+user,False));verify(0x81,user);s.check(f'KDF{size}_PUK_reset',True)
            verify(0x83,admin)
            bad=bytes([0x81,1,3,0x82,1,algo,0x83,4,0,1,0,0,0x84,8])+bytes(8)+bytes([0x84,8])+bytes(8)
            data,sw=s.exchange(helper.apdu(0xda,0,0xf9,bad,False));s.check(f'KDF{size}_duplicate_tag_rejected',sw==0x6a80 and not data)
            s.check(f'KDF{size}_invalid_update_keeps_metadata',s.need(helper.apdu(0xca,0,0xf9))==kdf)
            verify(0x83,admin);s.need(helper.apdu(0xda,0,0xf9,bytes.fromhex('810100'),False))
            change(0x81,user,b'123456');change(0x83,admin,b'12345678');s.select();s.pin();s.pin(0x81)
            s.check(f'KDF{size}_defaults_restored',s.need(helper.apdu(0xca,0,0xf9))==bytes.fromhex('810100'))
        s.select();s.pin();s.need(bytes.fromhex('00e60000'));s.need(bytes.fromhex('00440001'));s.select()
        s.check('KDF_final_reset_disables_reset_code',s.need(helper.apdu(0xca,0,0xc4))[4:]==bytes([3,0,3]))
        done=True
    finally:
        card.close();a.report.parent.mkdir(parents=True,exist_ok=True)
        a.report.write_text(json.dumps({'completed':done,'checks':s.results,'tested_cap_sha256':hashlib.sha256((ROOT/'dist/SmartPGPApplet.cap').read_bytes()).hexdigest(),'scope':'card-side KDF credential format transitions; not full host S2K interoperability'},indent=2),encoding='utf-8')
if __name__=='__main__':main()
