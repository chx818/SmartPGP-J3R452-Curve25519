"""Additional destructive regression; dedicated disposable instance only."""
import argparse,json,os
from pathlib import Path
from security_card import Card,Suite,helper,ROOT
from cryptography.hazmat.primitives.asymmetric import rsa,padding,utils,ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--reader',required=True);p.add_argument('--allow-key-replacement',action='store_true');args=p.parse_args()
 if not args.allow_key_replacement:p.error('--allow-key-replacement is required')
 c=Card(args.reader);s=Suite(c);ok=False
 try:
  s.select()
  # ECDH on a Weierstrass curve through independent host exchange.
  s.attr(0xc2,'122a8648ce3d030107');blob=s.gen(0xb8);point=dict(helper.tlv(dict(helper.tlv(blob))[0x7f49]))[0x86]
  pub=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),point);host=ec.generate_private_key(ec.SECP256R1());hp=host.public_key().public_bytes(Encoding.X962,PublicFormat.UncompressedPoint)
  s.pin(0x82);got=s.need(helper.apdu(0x2a,0x80,0x86,bytes.fromhex('a6467f49438641')+hp));s.check('P256_ECDH_independent_exchange',got==host.exchange(ec.ECDH(),pub))
  for bits in (3072,4096):
   s.attr(0xc1,f'01{bits:04x}001103');blob=s.gen(0xb6);d=dict(helper.tlv(dict(helper.tlv(blob))[0x7f49]));pub=rsa.RSAPublicNumbers(int.from_bytes(d[0x82],'big'),int.from_bytes(d[0x81],'big')).public_key()
   h=os.urandom(32);s.pin(0x81);sig=s.need(helper.apdu(0x2a,0x9e,0x9a,bytes.fromhex('3031300d060960864801650304020105000420')+h))
   pub.verify(sig,h,padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()));s.check(f'RSA{bits}_independent_verify',len(sig)==bits//8)
  # Install public test RSA key using strict CRT format 3, then verify a signature.
  s.attr(0xc1,'010800001103');priv=rsa.generate_private_key(public_exponent=65537,key_size=2048);n=priv.private_numbers();pn=n.public_numbers
  vals=[pn.e.to_bytes(3,'big'),n.p.to_bytes(128,'big'),n.q.to_bytes(128,'big'),n.iqmp.to_bytes(128,'big'),n.dmp1.to_bytes(128,'big'),n.dmq1.to_bytes(128,'big'),pn.n.to_bytes(256,'big')]
  def length(n):return bytes([n]) if n<128 else (b'\x81'+bytes([n]) if n<256 else b'\x82'+n.to_bytes(2,'big'))
  def tl(tag,val):return tag+length(len(val))+val
  template=b''.join(bytes([0x91+i])+length(len(v)) for i,v in enumerate(vals));body=b'\xb6\x00'+tl(b'\x7f\x48',template)+tl(b'\x5f\x48',b''.join(vals));s.pin();_,sw=s.long(0xdb,0x3f,0xff,tl(b'\x4d',body));s.check('RSA2048_CRT_import_pair_check',sw==0x9000)
  h=os.urandom(32);s.pin(0x81);sig=s.need(helper.apdu(0x2a,0x9e,0x9a,bytes.fromhex('3031300d060960864801650304020105000420')+h));priv.public_key().verify(sig,h,padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()));s.check('RSA2048_import_independent_verify',True)
  ok=True
 finally:
  c.close();manifest=json.loads((ROOT/'dist/build-manifest.json').read_text())
  report=ROOT/'build/test-results/card-extended.json';report.parent.mkdir(parents=True,exist_ok=True)
  report.write_text(json.dumps({'completed':ok,'tested_cap_sha256':manifest['cap_sha256'],'results':s.results},indent=2),encoding='utf-8')
if __name__=='__main__':main()
