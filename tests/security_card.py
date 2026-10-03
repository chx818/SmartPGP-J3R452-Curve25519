"""Destructive regression for an explicitly selected, disposable SmartPGP test instance.
Changes algorithm attributes, keys, PIN state and metadata. Never use on production keys.
Only runs with --allow-key-replacement. Finalize reinstallation separately after testing.
"""
import argparse,importlib.util,json,os,sys,time,hashlib,hmac
from pathlib import Path
from pcsc_transport import Card
from cryptography.hazmat.primitives.asymmetric import ed25519,x25519,ec,rsa,padding,utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('audit_card',ROOT/'tests/card_crypto_helpers.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
class Suite:
 def __init__(self,c):self.c=c;self.results=[]
 def exchange(self,cmd):return helper.exchange(self.c,cmd)
 def need(self,cmd):return helper.need(self.c,cmd)
 def check(self,name,condition):
  self.results.append({'test':name,'passed':bool(condition)})
  print(name,'PASS' if condition else 'FAIL',flush=True)
  if not condition:raise RuntimeError(name)
 def select(self):self.need(helper.apdu(0xa4,4,0,bytes.fromhex('d27600012401')))
 def pin(self,mode=0x83):self.need(helper.apdu(0x20,0,mode,b'12345678' if mode==0x83 else b'123456',False))
 def put(self,tag,data):self.pin();return self.need(helper.apdu(0xda,tag>>8,tag&255,data,False))
 def attr(self,tag,value):self.put(tag,bytes.fromhex(value))
 def gen(self,crt):self.pin();return self.need(helper.apdu(0x47,0x80,0,bytes([crt,0])))
 def pub(self,crt):return self.need(helper.apdu(0x47,0x81,0,bytes([crt,0])))
 def long(self,ins,p1,p2,data):
  while len(data)>200:
   _,sw=self.exchange(bytes([0x10,ins,p1,p2,200])+data[:200]);self.check('chain_fragment',sw==0x9000);data=data[200:]
  return self.exchange(helper.apdu(ins,p1,p2,data,False))
 def run(self):
  self.select()
  _,sw=self.exchange(helper.apdu(0x2a,0x9e,0x9a,bytes(32)));self.check('unauthenticated_sign_rejected',sw==0x6982)
  _,sw=self.exchange(bytes.fromhex('0120008100'));self.check('logical_channel_rejected',sw in (0x6e00,0x6881))
  self.attr(0xc1,'162b06010401da470f01');self.attr(0xc2,'122b060104019755010501');self.attr(0xc3,'162b06010401da470f01')
  sigpub=helper.pubkey(self.gen(0xb6));decpub=helper.pubkey(self.gen(0xb8));authpub=helper.pubkey(self.gen(0xa4))
  r=helper.exercise(self.c,b'123456',sigpub,decpub)
  self.check('ed25519_independent_verify',r['ed25519_independent_verify']);self.check('x25519_independent_exchange',r['x25519_independent_compare'])
  # Firmware may reject noncanonical encodings; conformance is a release requirement.
  self.check('x25519_top_bit_alias',r['top_bit_alias']);self.check('x25519_p_plus_9',r['noncanonical_p_plus_9'])
  self.check('x25519_low_order_14',all(x['rejected'] for x in r['low_order_tests']))
  self.select();self.pin(0x82)
  msg=os.urandom(32);sig=self.need(helper.apdu(0x88,0,0,msg));ed25519.Ed25519PublicKey.from_public_bytes(authpub).verify(sig,msg);self.check('auth_slot_independent_verify',True)
  _,sw=self.exchange(helper.apdu(0x2a,0x9e,0x9a,msg));self.check('mode82_cannot_sign_SIG',sw==0x6982)
  self.pin(0x81);sig=self.need(helper.apdu(0x2a,0x9e,0x9a,msg));ed25519.Ed25519PublicKey.from_public_bytes(sigpub).verify(sig,msg)
  _,sw=self.exchange(helper.apdu(0x2a,0x9e,0x9a,msg));self.check('one_signature_per_verify',sw==0x6982)
  before=self.need(helper.apdu(0xca,0,0x7a));old=self.pub(0xb6);self.pin()
  _,sw=self.exchange(helper.apdu(0xdb,0x3f,0xff,bytes.fromhex('4d06b60100000000'),False));self.check('malformed_import_rejected',sw==0x6700)
  self.check('malformed_import_keeps_counter',self.need(helper.apdu(0xca,0,0x7a))==before)
  self.check('malformed_import_keeps_key',self.pub(0xb6)==old)
  # Strict parser rejects duplicate tags before destructive replacement.
  self.pin();bad=bytes.fromhex('4d4cb6007f4804922092205f4840')+bytes(64)
  _,sw=self.exchange(helper.apdu(0xdb,0x3f,0xff,bad,False));self.check('duplicate_import_tag_rejected',sw in (0x6a80,0x6700))
  self.check('duplicate_import_keeps_key',self.pub(0xb6)==old)
  # PIN length wrap regression: known current PIN plus 262 bytes of suffix.
  self.pin();_,sw=self.long(0x24,0,0x81,b'123456'+b'654321'+bytes(256));self.check('pin_length_wrap_rejected',sw==0x6700)
  self.pin(0x81);self.check('pin_unchanged_after_bad_change',True)
  self.select();self.pin();_,sw=self.exchange(bytes.fromhex('10db3fff034d8200'));self.check('chain_start',sw==0x9000)
  _,sw=self.exchange(bytes.fromhex('04db3fff0100'));self.check('chain_SM_switch_rejected',sw==0x6883)
  self.select();self.pin();_,sw=self.exchange(helper.apdu(0xdb,0x3f,0xff,bytes.fromhex('4d82ffffb6000000'),False));self.check('negative_BER_length_rejected',sw==0x6a80)
  self.test_imports()
  self.test_p256()
  self.test_other_curves()
  self.test_rsa()
  self.test_aes_metadata()
  self.test_kdf_and_pin()
  self.test_sm()
 def import25519(self,crt,secret,pub):
  body=bytes([crt,0])+bytes.fromhex('7f4804922099205f4840')+secret+pub
  blob=bytes([0x4d,len(body)])+body
  self.pin();return self.exchange(helper.apdu(0xdb,0x3f,0xff,blob,False))
 def test_imports(self):
  seed=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
  key=ed25519.Ed25519PrivateKey.from_private_bytes(seed);pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  _,sw=self.import25519(0xb6,seed,pub);self.check('ed25519_seed_import',sw==0x9000)
  self.pin(0x81);sig=self.need(helper.apdu(0x2a,0x9e,0x9a,b'\x72'))
  self.check('ed25519_import_exact_reference_signature',sig==key.sign(b'\x72'))
  wrong=ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  _,sw=self.import25519(0xb6,seed,wrong);self.check('mismatched_ed25519_pair_rejected',sw!=0x9000)
  _,sw=self.exchange(helper.apdu(0x47,0x81,0,b'\xb6\x00'));self.check('mismatched_key_not_usable',sw==0x6a88)
  _,sw=self.import25519(0xb6,seed,pub);self.check('recovery_after_failed_import',sw==0x9000)
  scalar=bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');key=x25519.X25519PrivateKey.from_private_bytes(scalar)
  pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  _,sw=self.import25519(0xb8,scalar[::-1],pub);print('X25519 import SW',hex(sw),flush=True);self.check('x25519_scalar_import',sw==0x9000)
  self.pin(0x82);bob=bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
  got,sw=helper.decipher(self.c,bob);self.check('x25519_RFC7748_KAT',sw==0x9000 and got.hex()=='4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')
 def test_p256(self):
  self.attr(0xc1,'132a8648ce3d030107');blob=self.gen(0xb6)
  point=dict(helper.tlv(dict(helper.tlv(blob))[0x7f49]))[0x86];pub=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),point)
  for i in range(8):
   h=os.urandom(32);self.pin(0x81);sig=self.need(helper.apdu(0x2a,0x9e,0x9a,h));self.check('P256_fixed_width_'+str(i),len(sig)==64)
   pub.verify(utils.encode_dss_signature(int.from_bytes(sig[:32],'big'),int.from_bytes(sig[32:],'big')),h,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
  self.check('P256_independent_verify_8',True)
 def test_other_curves(self):
  cases=[('P384','132b81040022',ec.SECP384R1(),48),('P521','132b81040023',ec.SECP521R1(),66),
         ('brainpoolP256','132b2403030208010107',ec.BrainpoolP256R1(),32),
         ('brainpoolP384','132b240303020801010b',ec.BrainpoolP384R1(),48),
         ('brainpoolP512','132b240303020801010d',ec.BrainpoolP512R1(),64)]
  for name,attr,curve,width in cases:
   self.attr(0xc1,attr);blob=self.gen(0xb6)
   point=dict(helper.tlv(dict(helper.tlv(blob))[0x7f49]))[0x86];pub=ec.EllipticCurvePublicKey.from_encoded_point(curve,point)
   h=os.urandom(32);self.pin(0x81);sig=self.need(helper.apdu(0x2a,0x9e,0x9a,h));self.check(name+'_fixed_width',len(sig)==2*width)
   pub.verify(utils.encode_dss_signature(int.from_bytes(sig[:width],'big'),int.from_bytes(sig[width:],'big')),h,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
   self.check(name+'_independent_verify',True)

 def test_rsa(self):
  self.attr(0xc1,'010800001103');blob=self.gen(0xb6);d=dict(helper.tlv(dict(helper.tlv(blob))[0x7f49]));pub=rsa.RSAPublicNumbers(int.from_bytes(d[0x82],'big'),int.from_bytes(d[0x81],'big')).public_key()
  h=os.urandom(32);di=bytes.fromhex('3031300d060960864801650304020105000420')+h;self.pin(0x81);sig=self.need(helper.apdu(0x2a,0x9e,0x9a,di));pub.verify(sig,h,padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()));self.check('RSA2048_independent_verify',True)
  self.attr(0xc2,'010800001103');blob=self.gen(0xb8);d=dict(helper.tlv(dict(helper.tlv(blob))[0x7f49]));dec=rsa.RSAPublicNumbers(int.from_bytes(d[0x82],'big'),int.from_bytes(d[0x81],'big')).public_key()
  plain=b'SmartPGP RSA independent decrypt test';ct=dec.encrypt(plain,padding.PKCS1v15());self.pin(0x82);got,sw=self.long(0x2a,0x80,0x86,b'\x00'+ct)
  self.check('RSA2048_independent_decrypt',sw==0x9000 and got==plain)
 def test_aes_metadata(self):
  self.put(0xd5,bytes(range(16)));self.pin(0x82);plain=bytes(range(32));enc=self.need(helper.apdu(0x2a,0x86,0x80,plain));self.check('AES_roundtrip',self.need(helper.apdu(0x2a,0x80,0x86,enc))==plain)
  from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
  reference=Cipher(algorithms.AES(bytes(range(16))),modes.CBC(bytes(16))).encryptor()
  self.check('AES_CBC_independent_ciphertext',enc==b'\x02'+reference.update(plain)+reference.finalize())
  self.pin();blob=bytes([0x42])*255;_,sw=self.long(0xda,0x01,0x04,blob);self.check('persistent_DO_atomic_255',sw==0x9000)
  self.check('persistent_DO_readback',self.need(helper.apdu(0xca,0x01,0x04))==blob)
  self.pin();blob=bytes([0x53])*255;_,sw=self.long(0xda,0x01,0x04,blob);self.check('persistent_DO_replace_atomic_255',sw==0x9000)
  self.check('persistent_DO_replace_readback',self.need(helper.apdu(0xca,0x01,0x04))==blob)
  self.select();self.pin();certificate=bytes((i%251 for i in range(1152)))
  _,sw=self.long(0xda,0x7f,0x21,certificate);self.check('certificate_max_1152_write',sw==0x9000)
  self.check('certificate_max_1152_readback',self.need(helper.apdu(0xca,0x7f,0x21))==certificate)
  self.pin();replacement=certificate[::-1];_,sw=self.long(0xda,0x7f,0x21,replacement);self.check('certificate_max_atomic_replace',sw==0x9000)
  self.check('certificate_replacement_readback',self.need(helper.apdu(0xca,0x7f,0x21))==replacement)
  self.pin(0x82);_,sw=self.long(0x2a,0x86,0x80,bytes(656));self.check('AES_output_capacity_checked',sw==0x6700)

 def test_kdf_and_pin(self):
  before=self.need(helper.apdu(0xca,0,0xf9));self.pin()
  _,sw=self.exchange(helper.apdu(0xda,0,0xf9,bytes.fromhex('810103820199'),False));self.check('malformed_KDF_rejected',sw==0x6a80)
  self.check('malformed_KDF_keeps_metadata',self.need(helper.apdu(0xca,0,0xf9))==before)
  self.select();status=self.need(helper.apdu(0xca,0,0xc4));initial=status[4]
  if initial!=3:raise RuntimeError('test requires fresh PW1 retry budget')
  _,sw=self.exchange(helper.apdu(0x20,0,0x81,b'999999',False));self.check('wrong_PIN_rejected',sw==0x6982)
  self.select();self.check('PIN_retry_survives_reselect',self.need(helper.apdu(0xca,0,0xc4))[4]==2)
  self.pin(0x81);self.check('correct_PIN_restores_retry_budget',self.need(helper.apdu(0xca,0,0xc4))[4]==3)

 def test_sm(self,existing=False):
  from cryptography.hazmat.primitives.cmac import CMAC
  from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
  def mac(k,msg):
   c=CMAC(algorithms.AES(k));c.update(msg);return c.finalize()
  def aes(k,msg,iv=None,decrypt=False):
   c=Cipher(algorithms.AES(k),modes.ECB() if iv is None else modes.CBC(iv))
   op=c.decryptor() if decrypt else c.encryptor();return op.update(msg)+op.finalize()
  blob=self.pub(0xa6) if existing else self.gen(0xa6)
  static=dict(helper.tlv(dict(helper.tlv(blob))[0x7f49]))[0x86]
  host=ec.generate_private_key(ec.SECP256R1());hp=host.public_key().public_bytes(Encoding.X962,PublicFormat.UncompressedPoint)
  prefix=bytes.fromhex('a60d9002110095013c800188810110')
  request=prefix+bytes.fromhex('5f4941')+hp
  response=self.need(helper.apdu(0x88,1,0,request));parts=dict(helper.tlv(response))
  ep=parts[0x5f49];receipt=parts[0x86]
  z=host.exchange(ec.ECDH(),ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),ep))+host.exchange(ec.ECDH(),ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),static))
  material=b''.join(hashlib.sha256(z+i.to_bytes(4,'big')+bytes.fromhex('3c8810')).digest() for i in (1,2))
  kr,ke,km,krm=[material[i:i+16] for i in range(0,64,16)]
  self.check('SCP11b_receipt_independent_CMAC',hmac.compare_digest(receipt,mac(kr,request+bytes.fromhex('5f4941')+ep)))
  chain=receipt;counter=0
  def command(ins,p1,p2,plain=b''):
   nonlocal counter,chain
   counter+=1
   encrypted=b''
   if plain:
    padded=plain+b'\x80'+bytes((-len(plain)-1)%16)
    encrypted=aes(ke,padded,aes(ke,counter.to_bytes(16,'big')))
   header=bytes([4,ins,p1,p2,len(encrypted)+8]);chain=mac(km,chain+header+encrypted)
   reply,sw=self.exchange(header+encrypted+chain[:8]+b'\x00')
   if sw!=0x9000:raise RuntimeError(f'SM command {ins:02x} SW={sw:04x}')
   ct,tag=reply[:-8],reply[-8:]
   if not hmac.compare_digest(mac(krm,chain+ct+sw.to_bytes(2,'big'))[:8],tag):raise RuntimeError('SM response MAC mismatch')
   if not ct:return b''
   iv=bytearray(counter.to_bytes(16,'big'));iv[0]=0x80
   padded=aes(ke,ct,aes(ke,bytes(iv)),True)
   stripped=padded.rstrip(b'\x00')
   if not stripped.endswith(b'\x80'):raise RuntimeError('SM response padding mismatch')
   return stripped[:-1]
  actual=command(0xca,0,0xc1);print('SM public attribute response',actual.hex(),flush=True)
  self.check('SCP11b_encrypted_GET_DATA',actual==bytes.fromhex('c106010800001103'))
  self.check('SCP11b_encrypted_VERIFY',command(0x20,0,0x83,b'12345678')==b'')
  _,sw=self.exchange(bytes.fromhex('04ca00c108')+bytes(8)+b'\x00');self.check('SCP11b_bad_MAC_rejected',sw==0x6982)
  _,sw=self.exchange(helper.apdu(0x20,0,0x83,b'12345678',False));self.check('NFC_plain_PIN_rejected_after_SM_provision',sw==0x6985)

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--reader',required=True);ap.add_argument('--allow-key-replacement',action='store_true');ap.add_argument('--report',type=Path,default=ROOT/'build/test-results/card-regression.json');ap.add_argument('--expect-aid');args=ap.parse_args()
 if not args.allow_key_replacement:ap.error('explicit --allow-key-replacement is required')
 c=Card(args.reader);s=Suite(c);report=args.report;report.parent.mkdir(parents=True,exist_ok=True);completed=False
 try:
  if args.expect_aid:
   s.select()
   aid=s.need(helper.apdu(0xca,0,0x4f)).hex().upper()
   if aid!=args.expect_aid.upper():raise RuntimeError('Unexpected card AID; no regression writes issued')
  s.run();completed=True
 finally:
  c.close();report.write_text(json.dumps({'reader':c.reader,'completed':completed,'expected_aid':args.expect_aid,'tested_cap_sha256':hashlib.sha256((ROOT/'dist/SmartPGPApplet.cap').read_bytes()).hexdigest(),'results':s.results},indent=2),encoding='utf-8')
if __name__=='__main__':main()
