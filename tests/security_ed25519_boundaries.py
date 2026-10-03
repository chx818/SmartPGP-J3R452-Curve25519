"""Destructive independent Ed25519 seed/message-boundary regression on a test card."""
import argparse
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from security_card import Card,Suite,helper,ROOT


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reader',required=True);p.add_argument('--expect-aid',required=True);p.add_argument('--allow-key-replacement',action='store_true');p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    if not a.allow_key_replacement:p.error('Explicit destructive flag required')
    c=Card(a.reader);s=Suite(c);ok=False
    try:
        s.select()
        if s.need(helper.apdu(0xca,0,0x4f)).hex().upper()!=a.expect_aid.upper():raise RuntimeError('Wrong card')
        s.attr(0xc1,'162b06010401da470f01')
        seed=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
        key=ed25519.Ed25519PrivateKey.from_private_bytes(seed);public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        body=bytes.fromhex('b6007f4804922099205f4840')+seed+public
        s.pin();s.need(helper.apdu(0xdb,0x3f,0xff,bytes([0x4d,len(body)])+body,False))
        for size in [0,1,15,16,31,32,64,255,256,1024,1216]:
            message=bytes((i*37+size)%256 for i in range(size));s.pin(0x81)
            if size<=255:signature=s.need(helper.apdu(0x2a,0x9e,0x9a,message))
            else:
                signature,sw=s.long(0x2a,0x9e,0x9a,message)
                if sw!=0x9000:raise RuntimeError(f'Signature length {size}: {sw:04x}')
            s.check('Ed25519_exact_signature_length_'+str(size),signature==key.sign(message))
        s.pin(0x81);data,sw=s.long(0x2a,0x9e,0x9a,bytes(1217))
        s.check('Ed25519_capacity_rejected_before_output',sw==0x6700 and not data)
        ok=True
    finally:
        c.close();a.report.parent.mkdir(parents=True,exist_ok=True)
        a.report.write_text(json.dumps({'completed':ok,'checks':s.results},indent=2),encoding='utf-8')
if __name__=='__main__':main()
