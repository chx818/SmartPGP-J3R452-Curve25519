/*
  SmartPGP : JavaCard implementation of OpenPGP card v3 specification
  https://github.com/ANSSI-FR/SmartPGP
  Copyright (C) 2016 ANSSI

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

package fr.anssi.smartpgp;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import org.suut.javacard.pki.curve25519.Curve25519KeyAgreement;
import org.suut.javacard.pki.curve25519.Curve25519KeyBuilder;
import org.suut.javacard.pki.curve25519.Curve25519PublicKey;
import org.suut.javacard.pki.curve25519.Curve25519Signature;

public final class Common {
    protected final Cipher cipher_aes_cbc_nopad;
    protected final RandomData random;

    /* Lazy-loaded cryptographic engines to preserve JCOP 4.5 COR/System RAM */
    private Cipher cipher_rsa_pkcs1;
    private KeyAgreement ka_ec_dh;

    private Signature sign_ecdsa_sha;
    private Signature sign_ecdsa_sha_224;
    private Signature sign_ecdsa_sha_256;
    private Signature sign_ecdsa_sha_384;
    private Signature sign_ecdsa_sha_512;

    /* J3R452 Curve25519 hardware crypto */
    private Curve25519Signature curve25519_sig;
    private Curve25519KeyAgreement curve25519_ka;
    private Curve25519PublicKey curve25519_eph_pub;

    protected Common() {
        cipher_aes_cbc_nopad = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        RandomData rnd = null;
        try {
            rnd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        } catch (CryptoException e) {
            if(e.getReason() != CryptoException.NO_SUCH_ALGORITHM) { throw e; }
            rnd = RandomData.getInstance(RandomData.ALG_TRNG);
        }
        random = rnd;
    }

    public Cipher getCipherRsaPkcs1() {
        if(cipher_rsa_pkcs1 == null) {
            cipher_rsa_pkcs1 = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        }
        return cipher_rsa_pkcs1;
    }

    public KeyAgreement getKaEcDh() {
        if(ka_ec_dh == null) {
            ka_ec_dh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        }
        return ka_ec_dh;
    }

    public Signature getEcdsaSignature(final short hashLen) {
        switch(hashLen) {
        case MessageDigest.LENGTH_SHA:
            if(sign_ecdsa_sha == null) {
                sign_ecdsa_sha = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
            }
            return sign_ecdsa_sha;
        case MessageDigest.LENGTH_SHA_224:
            if(sign_ecdsa_sha_224 == null) {
                sign_ecdsa_sha_224 = Signature.getInstance(Signature.ALG_ECDSA_SHA_224, false);
            }
            return sign_ecdsa_sha_224;
        case MessageDigest.LENGTH_SHA_256:
            if(sign_ecdsa_sha_256 == null) {
                sign_ecdsa_sha_256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
            }
            return sign_ecdsa_sha_256;
        case MessageDigest.LENGTH_SHA_384:
            if(sign_ecdsa_sha_384 == null) {
                sign_ecdsa_sha_384 = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
            }
            return sign_ecdsa_sha_384;
        case MessageDigest.LENGTH_SHA_512:
            if(sign_ecdsa_sha_512 == null) {
                sign_ecdsa_sha_512 = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
            }
            return sign_ecdsa_sha_512;
        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return null;
        }
    }

    public Curve25519Signature getCurve25519Sig() {
        if(curve25519_sig == null) {
            curve25519_sig = new Curve25519Signature();
        }
        return curve25519_sig;
    }

    public Curve25519KeyAgreement getCurve25519Ka() {
        if(curve25519_ka == null) {
            curve25519_ka = new Curve25519KeyAgreement();
        }
        return curve25519_ka;
    }

    public Curve25519PublicKey getCurve25519EphPub() {
        if(curve25519_eph_pub == null) {
            curve25519_eph_pub = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(
                Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC,
                JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT
            );
        }
        return curve25519_eph_pub;
    }

    protected static final void beginTransaction(final boolean isRegistering) {
        if(!isRegistering) {
            JCSystem.beginTransaction();
        }
    }

    protected static final void commitTransaction(final boolean isRegistering) {
        if(!isRegistering) {
            JCSystem.commitTransaction();
        }
    }

    protected static final short aesKeyLength(final ECParams params) {
        if(params.isCurve25519 || params.nb_bits < (short)512) {
            return (short)16;
        } else {
            return (short)32;
        }
    }

    protected static final short writeLength(final byte[] buf, short off, final short len) {
        if(len > 0xff) {
            buf[off] = (byte)0x82;
            return Util.setShort(buf, (short)(off+1), len);
        }

        if(len > 0x7f) {
            buf[off++] = (byte)0x81;
            buf[off++] = (byte)(len & 0xff);
            return off;
        }

        buf[off++] = (byte)(len & 0x7f);
        return off;
    }

    protected static final short skipLength(final byte[] buf, final short off, final short len) {
        if((off < 0) || (len < 1) || (off > (short)(buf.length - len))) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return off;
        }

        if((buf[off] & (byte)0x80) == 0) {
            return (short)(off + 1);
        }

        switch(buf[off]) {
        case (byte)0x81:
            if(len < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return off;
            }
            return (short)(off + 2);

        case (byte)0x82:
            if(len < 3) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return off;
            }
            return (short)(off + 3);

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return off;
        }
    }

    protected static final short readLength(final byte[] buf, final short off, final short len) {
        if((off < 0) || (len < 1) || (off > (short)(buf.length - len))) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return (short)0;
        }

        if((buf[off] & (byte)0x80) == 0) {
            return Util.makeShort((byte)0, buf[off]);
        }

        switch(buf[off]) {
        case (byte)0x81:
            if(len < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return (short)0;
            }
            return Util.makeShort((byte)0, buf[(short)(off + 1)]);

        case (byte)0x82:
            if(len < 3) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return (short)0;
            }
            final short value = Util.getShort(buf, (short)(off + 1));
            if(value < 0) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            return value;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return (short)0;
        }
    }

    /** Remove ISO 7816-4 padding from exactly one final block. Fixed byte
     * access/loop count for equal public ciphertext lengths; not an SCA proof. */
    protected static short unpad80(final byte[] buf, final short len) {
        if(len < Constants.AES_BLOCK_SIZE || (len % Constants.AES_BLOCK_SIZE)!=0 || len>buf.length) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        short searching=1;
        short invalid=0;
        short result=0;
        for(short i=1;i<=Constants.AES_BLOCK_SIZE;++i) {
            short value=(short)(buf[(short)(len-i)] & 0xff);
            short zero=(short)(((short)(value-1) >> 8) & 1);
            short marker=(short)(((short)((short)(value ^ 0x80)-1) >> 8) & 1);
            short choose=(short)(searching & marker);
            invalid |= (short)(searching & (1 ^ zero) & (1 ^ marker));
            short mask=(short)-choose;
            result=(short)((result & ~mask) | ((len-i) & mask));
            searching &= (short)(1 ^ marker);
        }
        if((invalid | searching)!=0) { ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED); }
        return result;
    }

    /** Bound the whole old-credential/new-PIN command before checking OwnerPIN. */
    protected static short newPinLength(final short lc, final short oldLength,
                                        final short minimum, final short derivedLength) {
        short size=(short)(lc-oldLength);
        if(oldLength<0 || oldLength>127 || lc<oldLength || size>127 ||
           (derivedLength==0 ? size<minimum : size!=derivedLength)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return size;
    }

    protected static final short bitsToBytes(final short bits) {
        return (short)((bits / 8) + (short)(((bits % 8) == 0) ? 0 : 1));
    }

    protected static final void arrayLeftShift(final byte[] inBuf, short inOff,
                                               final byte[] outBuf, short outOff,
                                               final short len) {
        if(len > 0) {
            outBuf[outOff++] = (byte)(inBuf[inOff++] << 1);
            for(short i = 1; i < len; ++i) {
                outBuf[(short)(outOff - 1)] |= (byte)((inBuf[inOff] >>> 7) & 1);
                outBuf[outOff++] = (byte)(inBuf[inOff++] << 1);
            }
        }
    }

    protected static final void arrayXor(final byte[] inBuf1, short inOff1,
                                         final byte[] inBuf2, short inOff2,
                                         final byte[] outBuf, short outOff,
                                         final short len) {
        for(short i = 0; i < len; ++i) {
            outBuf[outOff++] = (byte)(inBuf1[inOff1++] ^ inBuf2[inOff2++]);
        }
    }

    protected static final short writeAlgorithmInformation(final ECCurves ec,
                                                           final byte key_tag, final boolean is_dec,
                                                           final byte[] buf, short off) {
        for(short i = 0; i < ec.curves.length; ++i) {
            final ECParams p = ec.curves[i];
            if(p.isCurve25519) {
                if(p.isEd25519 && is_dec) continue; /* Ed25519 is for SIG/AUT, not DEC */
                if(!p.isEd25519 && !is_dec) continue; /* X25519 is for DEC, not SIG/AUT */
                buf[off++] = key_tag;
                buf[off++] = (byte)(1 + p.oid.length + 1); /* len */
                if(is_dec) {
                    buf[off++] = (byte)0x12; /* ECDH (cv25519) */
                } else {
                    buf[off++] = (byte)0x16; /* EdDSA (Ed25519) */
                }
                off = Util.arrayCopyNonAtomic(p.oid, (short)0,
                                              buf, off,
                                              (short)p.oid.length);
                buf[off++] = (byte)0xff; /* with public key */
            } else {
                buf[off++] = key_tag;
                buf[off++] = (byte)(1 + p.oid.length + 1); /* len */
                if(is_dec) buf[off++] = (byte)0x12; /* ECDH */
                else buf[off++] = (byte)0x13; /* ECDSA */
                off = Util.arrayCopyNonAtomic(p.oid, (short)0,
                                              buf, off,
                                              (short)p.oid.length);
                buf[off++] = (byte)0xff; /* with public key */
            }
        }

        for(short m = 2; m <= 4; ++m) {
            for(byte form = Constants.RSA_IMPORT_SUPPORTS_FORMAT_1 ? 1 : 3; form <= 3; form += 2) {
                buf[off++] = key_tag;
                buf[off++] = (byte)6; /* len */
                buf[off++] = (byte)0x01; /* RSA */
                off = Util.setShort(buf, off, (short)(m * 1024)); /* modulus bit size */
                off = Util.setShort(buf, off, (short)0x11); /* 65537 = 17 bits public exponent size */
                buf[off++] = form;
            }
        }

        return off;
    }

    /* Compare without a Java-level early exit. This is not a physical SCA claim. */
    protected static final boolean equal(final byte[] a, final short ao,
                                         final byte[] b, final short bo, final short len) {
        byte diff = 0;
        for(short i = 0; i < len; ++i) { diff |= (byte)(a[(short)(ao+i)] ^ b[(short)(bo+i)]); }
        return diff == 0;
    }

    protected static final void requireSpace(final byte[] b, final short off, final short len) {
        if(off < 0 || len < 0 || off > (short)(b.length-len)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    /* Caller holds a transaction for persistent data; ordinary element writes
       participate in it. Also works during installation without a transaction. */
    protected static final short arrayFillAtomic(final byte[] b, final short off,
                                                 final short len, final byte value) {
        requireSpace(b,off,len);
        short end=(short)(off+len);
        for(short i=off;i<end;++i) { b[i]=value; }
        return end;
    }

    protected static final void requestDeletion() {
        if(JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
    }
}
