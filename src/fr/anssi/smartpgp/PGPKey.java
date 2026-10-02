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
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import org.suut.javacard.pki.curve25519.Curve25519KeyBuilder;
import org.suut.javacard.pki.curve25519.Curve25519PrivateKey;
import org.suut.javacard.pki.curve25519.Curve25519PublicKey;

public final class PGPKey {

    protected final Fingerprint fingerprint;

    protected final byte[] generation_date;

    protected final byte[] certificate;
    protected short certificate_length;

    protected final byte[] attributes;
    protected byte attributes_length;

    protected final boolean is_secure_messaging_key;

    private boolean has_been_generated;

    /* For RSA and standard Weierstrass EC */
    private KeyPair keys;

    /* For J3R452 hardware Curve25519 (Ed25519 / X25519) */
    private Curve25519PrivateKey c25519_priv;
    private Curve25519PublicKey c25519_pub;
    /* Pre-allocated transient buffers for key import parsing to avoid dynamic allocation */
    private final byte[] data_tag_val;
    private final short[] data_tag_len;

    /* CRIT-03: Persistent sentinel flag for fault-tolerant tear protection during keygen/import */
    private boolean key_operation_in_progress;

    /* MED-04: Pre-allocated transient buffer for securely zeroizing key slots before clearing */
    private final byte[] zero_key_buf;

    /* CRIT-01: RFC 7748 §6 / Errata 4730 small-subgroup order-8 point coordinates (little-endian) */
    private static final byte[] LOW_ORDER_ROOT1 = {
        (byte)0xEC, (byte)0xED, (byte)0x78, (byte)0xD6, (byte)0x79, (byte)0x56, (byte)0x22, (byte)0x7F,
        (byte)0x7C, (byte)0xE0, (byte)0x17, (byte)0xDE, (byte)0x63, (byte)0xFD, (byte)0x56, (byte)0xAD,
        (byte)0x57, (byte)0xAF, (byte)0x9E, (byte)0x9D, (byte)0xE3, (byte)0x6A, (byte)0x28, (byte)0x15,
        (byte)0x32, (byte)0x49, (byte)0x1F, (byte)0xEE, (byte)0x5F, (byte)0x56, (byte)0xB0, (byte)0x47
    };
    private static final byte[] LOW_ORDER_ROOT2 = {
        (byte)0x00, (byte)0x12, (byte)0x87, (byte)0x29, (byte)0x86, (byte)0x98, (byte)0xDD, (byte)0x80,
        (byte)0x83, (byte)0x1F, (byte)0xE8, (byte)0x21, (byte)0x9C, (byte)0x02, (byte)0xA9, (byte)0x52,
        (byte)0xA8, (byte)0x50, (byte)0x61, (byte)0x62, (byte)0x1C, (byte)0x95, (byte)0xE7, (byte)0xCA,
        (byte)0xCD, (byte)0xB6, (byte)0xE0, (byte)0x11, (byte)0xA0, (byte)0xA9, (byte)0x4F, (byte)0x38
    };

    protected PGPKey(final boolean for_secure_messaging) {

        is_secure_messaging_key = for_secure_messaging;

        if(is_secure_messaging_key) {
            fingerprint = null;
            generation_date = null;
        } else {
            fingerprint = new Fingerprint();
            generation_date = new byte[Constants.GENERATION_DATE_SIZE];
        }

        certificate = new byte[Constants.cardholderCertificateMaxLength()];
        certificate_length = 0;

        attributes = new byte[Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH];
        attributes_length = 0;

        data_tag_val = JCSystem.makeTransientByteArray((short)7, JCSystem.CLEAR_ON_DESELECT);
        data_tag_len = JCSystem.makeTransientShortArray((short)7, JCSystem.CLEAR_ON_DESELECT);
        zero_key_buf = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);

        reset(true);
    }

    private final void resetKeys(final boolean isRegistering) {
        key_operation_in_progress = false;

        if(keys != null) {
            keys.getPrivate().clearKey();
            keys.getPublic().clearKey();
            keys = null;
        }

        if(c25519_priv != null) {
            try {
                c25519_priv.setS(zero_key_buf, (short)0, (short)32);
            } catch (Exception e) {}
            c25519_priv.clearKey();
            c25519_priv = null;
        }

        if(c25519_pub != null) {
            try {
                c25519_pub.setW(zero_key_buf, (short)0, (short)32);
            } catch (Exception e) {}
            c25519_pub.clearKey();
            c25519_pub = null;
        }

        if(!isRegistering) {
            Common.requestDeletion();
        }

        if(certificate_length > 0) {
            Util.arrayFillNonAtomic(certificate, (short)0, (short)certificate.length, (byte)0);
            certificate_length = (short)0;
        }

        if(!is_secure_messaging_key) {
            fingerprint.reset(isRegistering);
            Util.arrayFillNonAtomic(generation_date, (short)0, Constants.GENERATION_DATE_SIZE, (byte)0);
        }

        has_been_generated = false;
    }

    protected final void reset(final boolean isRegistering) {
        resetKeys(isRegistering);

        Common.beginTransaction(isRegistering);
        if(attributes_length > 0) {
            Util.arrayFillNonAtomic(attributes, (short)0, attributes_length, (byte)0);
            attributes_length = (byte)0;
        }

        if(is_secure_messaging_key) {
            Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING, (short)0,
                                    attributes, (short)0,
                                    (short)Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length);
            attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length;
        } else {
            Util.arrayCopyNonAtomic(Constants.ALGORITHM_ATTRIBUTES_DEFAULT, (short)0,
                                    attributes, (short)0,
                                    (short)Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length);
            attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length;
        }
        Common.commitTransaction(isRegistering);
    }

    protected final boolean isInitialized() {
        if(key_operation_in_progress) {
            resetKeys(false);
            key_operation_in_progress = false;
            return false;
        }
        if((c25519_priv != null) || (c25519_pub != null)) {
            return (c25519_priv != null) && (c25519_pub != null) &&
                   c25519_priv.isInitialized() && c25519_pub.isInitialized();
        }
        return (keys != null) && keys.getPrivate().isInitialized() && keys.getPublic().isInitialized();
    }

    protected final byte keyInformation() {
        byte res = (byte)0x0;
        if(isInitialized()) {
            if(has_been_generated) {
                res = (byte)0x01;
            } else {
                res = (byte)0x02;
            }
        }
        return res;
    }

    protected final void setCertificate(final byte[] buf, final short off, final short len) {
        if((len < 0) ||
           (len > Constants.cardholderCertificateMaxLength())) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        JCSystem.beginTransaction();
        if(certificate_length > 0) {
            Util.arrayFillNonAtomic(certificate, (short)0, certificate_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(buf, off, certificate, (short)0, len);
        certificate_length = len;
        JCSystem.commitTransaction();
    }

    protected final void setGenerationDate(final byte[] buf, final short off, final short len) {
        if(len != Constants.GENERATION_DATE_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }
        Util.arrayCopy(buf, off, generation_date, (short)0, len);
    }

    protected final void setAttributes(final ECCurves ec,
                                       final byte[] buf, final short off, short len) {
        if((len < Constants.ALGORITHM_ATTRIBUTES_MIN_LENGTH) ||
           (len > Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            return;
        }

        switch(buf[off]) {
        case 0x01:
            if((len != 6) || is_secure_messaging_key) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            if((Util.getShort(buf, (short)(off + 1)) < 2048) ||
               (Util.getShort(buf, (short)(off + 3)) != 0x11) ||
               (buf[(short)(off + 5)] < 0) || (buf[(short)(off + 5)] > 3)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            break;

        case 0x12:
        case 0x13:
        case 0x16:
            if(len < 2) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            final boolean has_ff = (buf[(short)(off + len - 1)] == (byte)0xff);
            final short oid_len = has_ff ? (short)(len - 2) : (short)(len - 1);
            if(oid_len <= 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            final ECParams params = ec.findByOid(buf, (short)(off + 1), (byte)oid_len);
            if(params == null) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
            if(params.isCurve25519) {
                if(is_secure_messaging_key) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return;
                }
                if(params.isEd25519 && (buf[off] != (byte)0x16)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }
                if(!params.isEd25519 && (buf[off] != (byte)0x12)) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }
            } else {
                if(buf[off] == (byte)0x16) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }
                if((buf[off] != 0x12) && is_secure_messaging_key) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return;
                }
            }
            break;

        default:
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        resetKeys(false);

        JCSystem.beginTransaction();
        if(attributes_length > 0) {
            Util.arrayFillNonAtomic(attributes, (short)0, attributes_length, (byte)0);
        }
        Util.arrayCopyNonAtomic(buf, off, attributes, (short)0, len);
        if((buf[off] == 0x12 || buf[off] == 0x13 || buf[off] == 0x16) && (attributes[(short)(len - 1)] != (byte)0xff)) {
            if(len >= Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH) {
                JCSystem.abortTransaction();
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return;
            }
            attributes[len] = (byte)0xff;
            len++;
        }
        attributes_length = (byte)len;
        JCSystem.commitTransaction();
    }

    protected final boolean isRsa() {
        return (attributes[0] == 1);
    }

    protected final short rsaModulusBitSize() {
        return Util.getShort(attributes, (short)1);
    }

    protected final short rsaExponentBitSize() {
        return Util.getShort(attributes, (short)3);
    }

    protected final boolean isEc() {
        return ((attributes[0] == (byte)0x12) ||
                (attributes[0] == (byte)0x13) ||
                (attributes[0] == (byte)0x16));
    }

    protected final boolean isCurve25519(final ECCurves ec) {
        final ECParams params = ecParams(ec);
        if(params != null) {
            return params.isCurve25519;
        }
        return false;
    }

    protected final ECParams ecParams(final ECCurves ec) {
        final byte delta = (attributes[(short)(attributes_length - 1)] == (byte)0xff) ? (byte)1 : (byte)0;
        return ec.findByOid(attributes, (short)1, (byte)(attributes_length - 1 - delta));
    }

    private final KeyPair generateRSA() {
        PrivateKey priv = (PrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, rsaModulusBitSize(), false);
        RSAPublicKey pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, rsaModulusBitSize(), false);

        if((priv == null) || (pub == null)) {
            priv = null;
            pub = null;
            Common.requestDeletion();
            return null;
        }

        pub.setExponent(Constants.RSA_EXPONENT, (short)0, (byte)Constants.RSA_EXPONENT.length);

        return new KeyPair(pub, priv);
    }

    private final KeyPair generateEC(final ECCurves ec) {
        ECParams params = ecParams(ec);

        ECPrivateKey priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, params.nb_bits, false);
        ECPublicKey pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, params.nb_bits, false);

        if((priv == null) || (pub == null)) {
            params = null;
            priv = null;
            pub = null;
            Common.requestDeletion();
            return null;
        }

        params.setParams(priv);
        params.setParams(pub);

        return new KeyPair(pub, priv);
    }

    private final boolean generateCurve25519(final ECParams params) {
        final byte privType = params.isEd25519 ? Curve25519KeyBuilder.ALG_TYPE_EDDSA_PRIVATE
                                               : Curve25519KeyBuilder.ALG_TYPE_X25519_PRIVATE;
        final byte pubType  = params.isEd25519 ? Curve25519KeyBuilder.ALG_TYPE_EDDSA_PUBLIC
                                               : Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC;

        c25519_priv = (Curve25519PrivateKey)Curve25519KeyBuilder.buildKey(privType, JCSystem.MEMORY_TYPE_PERSISTENT);
        c25519_pub  = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(pubType, JCSystem.MEMORY_TYPE_PERSISTENT);

        if((c25519_priv == null) || (c25519_pub == null)) {
            c25519_priv = null;
            c25519_pub = null;
            Common.requestDeletion();
            return false;
        }

        try {
            Curve25519KeyBuilder.genKeyPair(c25519_priv, c25519_pub);
        } catch (CryptoException e) {
            resetKeys(false);
            return false;
        }
        return true;
    }

    protected final void generate(final ECCurves ec) {
        key_operation_in_progress = true;
        resetKeys(false);

        if(isRsa()) {
            keys = generateRSA();
        } else if(isCurve25519(ec)) {
            final ECParams params = ecParams(ec);
            if(!generateCurve25519(params)) {
                key_operation_in_progress = false;
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        } else if(isEc()) {
            keys = generateEC(ec);
        }

        if(!isCurve25519(ec)) {
            if((keys == null) || (keys.getPrivate() == null) || (keys.getPublic() == null)) {
                resetKeys(false);
                key_operation_in_progress = false;
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
            try {
                keys.genKeyPair();
            } catch (CryptoException e) {
                resetKeys(false);
                key_operation_in_progress = false;
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return;
            }
        }

        if(!isInitialized()) {
            resetKeys(false);
            key_operation_in_progress = false;
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        has_been_generated = true;
        key_operation_in_progress = false;
    }

    private final KeyPair importRSAKey(final byte[] buf,
                                       final short boff, final short len,
                                       final byte tag_count, final byte[] tag_val, final short[] tag_len) {

        final short attr_modulus_bit_size = rsaModulusBitSize();
        final short attr_modulus_byte_size = Common.bitsToBytes(attr_modulus_bit_size);

        final RSAPrivateCrtKey priv = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, attr_modulus_bit_size, false);
        final RSAPublicKey pub = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, attr_modulus_bit_size, false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        short off = boff;
        byte i = 0;
        while(i < tag_count) {

            if((short)((short)(off - boff) + tag_len[i]) > len) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return null;
            }

            switch(tag_val[i]) {
            case (byte)0x91:
                if(tag_len[i] != Common.bitsToBytes(rsaExponentBitSize())) {
                    return null;
                }
                pub.setExponent(buf, off, tag_len[i]);
                break;

            case (byte)0x92:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setP(buf, off, tag_len[i]);
                break;

            case (byte)0x93:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setQ(buf, off, tag_len[i]);
                break;

            case (byte)0x94:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setPQ(buf, off, tag_len[i]);
                break;

            case (byte)0x95:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setDP1(buf, off, tag_len[i]);
                break;

            case (byte)0x96:
                if(tag_len[i] != (short)(attr_modulus_byte_size / 2)) {
                    return null;
                }
                priv.setDQ1(buf, off, tag_len[i]);
                break;

            case (byte)0x97:
                if(tag_len[i] != attr_modulus_byte_size) {
                    return null;
                }
                pub.setModulus(buf, off, tag_len[i]);
                break;

            default:
                return null;
            }

            off += tag_len[i];
            ++i;
        }

        if(!priv.isInitialized() || !pub.isInitialized()) {
            return null;
        }

        return new KeyPair(pub, priv);
    }

    private final KeyPair importECKey(final ECCurves ec,
                                      final byte[] buf,
                                      final short boff, final short len,
                                      final byte tag_count, final byte[] tag_val, final short[] tag_len) {
        final ECParams params = ecParams(ec);

        final ECPrivateKey priv = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE,
                                                                    params.nb_bits,
                                                                    false);
        final ECPublicKey pub = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC,
                                                                 params.nb_bits,
                                                                 false);

        if((priv == null) || (pub == null)) {
            return null;
        }

        params.setParams(priv);
        params.setParams(pub);

        short off = boff;
        byte i = 0;
        while(i < tag_count) {

            if((short)((short)(off - boff) + tag_len[i]) > len) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return null;
            }

            switch(tag_val[i]) {
            case (byte)0x92:
                if(tag_len[i] > Common.bitsToBytes(params.nb_bits)) {
                    return null;
                }
                priv.setS(buf, off, tag_len[i]);
                break;

            case (byte)0x99:
                if(tag_len[i] > (short)(2 * Common.bitsToBytes(params.nb_bits) + 1)) {
                    return null;
                }
                if(((byte)(tag_len[i] - 1) & (byte)0x1) != 0) {
                    return null;
                }
                pub.setW(buf, off, tag_len[i]);
                break;

            default:
                return null;
            }

            off += tag_len[i];
            ++i;
        }

        if(!priv.isInitialized() || !pub.isInitialized()) {
            return null;
        }

        return new KeyPair(pub, priv);
    }

    private final void cleanCurve25519Keys() {
        if(c25519_priv != null) {
            try {
                /* MED-04: Overwrite private key slot in EEPROM before clearKey() */
                c25519_priv.setS(zero_key_buf, (short)0, (short)32);
            } catch (Exception e) {}
            c25519_priv.clearKey();
            c25519_priv = null;
        }
        if(c25519_pub != null) {
            try {
                c25519_pub.setW(zero_key_buf, (short)0, (short)32);
            } catch (Exception e) {}
            c25519_pub.clearKey();
            c25519_pub = null;
        }
        Common.requestDeletion();
    }

    private final boolean importCurve25519Key(final ECParams params,
                                              final byte[] buf,
                                              final short boff, final short len,
                                              final byte tag_count, final byte[] tag_val, final short[] tag_len) {
        final byte privType = params.isEd25519 ? Curve25519KeyBuilder.ALG_TYPE_EDDSA_PRIVATE
                                               : Curve25519KeyBuilder.ALG_TYPE_X25519_PRIVATE;
        final byte pubType  = params.isEd25519 ? Curve25519KeyBuilder.ALG_TYPE_EDDSA_PUBLIC
                                               : Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC;

        c25519_priv = (Curve25519PrivateKey)Curve25519KeyBuilder.buildKey(privType, JCSystem.MEMORY_TYPE_PERSISTENT);
        c25519_pub  = (Curve25519PublicKey)Curve25519KeyBuilder.buildKey(pubType, JCSystem.MEMORY_TYPE_PERSISTENT);

        if((c25519_priv == null) || (c25519_pub == null)) {
            cleanCurve25519Keys();
            return false;
        }

        short off = boff;
        byte i = 0;
        try {
            while(i < tag_count) {

                if((short)((short)(off - boff) + tag_len[i]) > len) {
                    cleanCurve25519Keys();
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return false;
                }

                switch(tag_val[i]) {
                case (byte)0x92:
                    if(tag_len[i] != 32) {
                        cleanCurve25519Keys();
                        return false;
                    }
                    /* Cryptographic Architecture (RFC 7748 §5 vs RFC 8032):
                     * - Ed25519: The private key is a 32-byte seed. Clamping must NOT be applied here,
                     *   as RFC 8032 requires clamping to occur internally on the expanded 64-byte scalar
                     *   derived from SHA-512(seed). Clamping the seed here would corrupt the derivation chain.
                     * - X25519: The private key is a direct scalar multiplier. RFC 7748 §5 strictly requires
                     *   scalar clamping (bits 0,1,2 cleared, bit 255 cleared, bit 254 set) to mitigate
                     *   small-subgroup and timing attacks. */
                    if(!params.isEd25519) {
                        buf[off] &= (byte)0xF8;
                        buf[(short)(off + 31)] &= (byte)0x7F;
                        buf[(short)(off + 31)] |= (byte)0x40;
                    }
                    c25519_priv.setS(buf, off, (short)32);
                    break;

                case (byte)0x99:
                    short pubOff = off;
                    short pubLen = tag_len[i];
                    if((pubLen == 33) && (buf[pubOff] == (byte)0x40)) {
                        pubOff++;
                        pubLen--;
                    }
                    if(pubLen != 32) {
                        cleanCurve25519Keys();
                        return false;
                    }
                    c25519_pub.setW(buf, pubOff, (short)32);
                    break;

                default:
                    cleanCurve25519Keys();
                    return false;
                }

                off += tag_len[i];
                ++i;
            }
        } catch (CryptoException e) {
            cleanCurve25519Keys();
            return false;
        }

        if(!c25519_priv.isInitialized() || !c25519_pub.isInitialized()) {
            cleanCurve25519Keys();
            return false;
        }

        return true;
    }

    protected final void importKey(final ECCurves ec,
                                   final byte[] buf, final short boff, final short len) {
        short off = boff;

        short template_len = 0;
        short template_off = 0;

        short data_len = 0;
        short data_off = 0;

        byte data_tag_count = 0;

        while((short)(len - (short)(off - boff)) > 2) {
            switch(Util.getShort(buf, off)) {

            case (short)0x7f48:
                off += 2;
                template_len = Common.readLength(buf, off, (short)(len - (short)(off - boff)));
                off = Common.skipLength(buf, off, (short)(len - (short)(off - boff)));
                template_off = off;

                if(template_len > (short)(len - (short)(off - boff))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }

                while((short)(template_len - (short)(off - template_off)) > 1) {
                    if((buf[off] < (byte)0x91) ||
                       (buf[off] > (byte)0x99)) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }

                    if(data_tag_count >= data_tag_val.length) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        return;
                    }

                    data_tag_val[data_tag_count] = buf[off];
                    ++off;

                    data_tag_len[data_tag_count] = Common.readLength(buf, off, (short)(template_len - (short)(off - template_off)));
                    off = Common.skipLength(buf, off, (short)(template_len - (short)(off - template_off)));

                    ++data_tag_count;
                }
                break;

            case (short)0x5f48:
                off += 2;
                data_len = Common.readLength(buf, off, (short)(len - (short)(off - boff)));
                off = Common.skipLength(buf, off, (short)(len - (short)(off - boff)));
                data_off = off;

                if(data_len > (short)(len - (short)(off - boff))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    return;
                }

                off += data_len;

                break;

            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            }
        }

        key_operation_in_progress = true;
        resetKeys(false);

        boolean success = false;
        if(isRsa()) {
            keys = importRSAKey(buf, data_off, data_len, data_tag_count, data_tag_val, data_tag_len);
            success = (keys != null);
        } else if(isCurve25519(ec)) {
            success = importCurve25519Key(ecParams(ec), buf, data_off, data_len, data_tag_count, data_tag_val, data_tag_len);
        } else if(isEc()) {
            keys = importECKey(ec, buf, data_off, data_len, data_tag_count, data_tag_val, data_tag_len);
            success = (keys != null);
        }

        /* Cryptographic Audit: Zeroize private key material in input buffer immediately */
        if(data_len > 0) {
            Util.arrayFillNonAtomic(buf, data_off, data_len, (byte)0);
        }

        /* Zeroize tag parsing buffers */
        Util.arrayFillNonAtomic(data_tag_val, (short)0, (short)data_tag_val.length, (byte)0);
        for(byte t = 0; t < (byte)data_tag_len.length; ++t) {
            data_tag_len[t] = (short)0;
        }

        if(!success || !isInitialized()) {
            resetKeys(false);
            key_operation_in_progress = false;
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            return;
        }

        key_operation_in_progress = false;
    }

    protected final short writePublicKeyDo(final byte[] buf, short off) {
        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        off = Util.setShort(buf, off, (short)0x7f49);

        if(isRsa()) {
            final RSAPublicKey rsapub = (RSAPublicKey)keys.getPublic();
            final short modulus_size = Common.bitsToBytes(rsaModulusBitSize());
            final short exponent_size = Common.bitsToBytes(rsaExponentBitSize());

            final short mlensize = (short)((modulus_size > (short)0xff) ? 3 : 2);

            final short flen =
                (short)(1 + mlensize + modulus_size +
                        1 + 1 + exponent_size);

            off = Common.writeLength(buf, off, flen);

            buf[off++] = (byte)0x81;
            off = Common.writeLength(buf, off, modulus_size);
            off += rsapub.getModulus(buf, off);

            buf[off++] = (byte)0x82;
            off = Common.writeLength(buf, off, exponent_size);
            off += rsapub.getExponent(buf, off);

            return off;

        } else if(c25519_pub != null) {
            /* Curve25519 public key is 32 bytes little-endian */
            final short size = 32;
            off = Common.writeLength(buf, off, (short)(1 + 1 + size));
            buf[off++] = (byte)0x86;
            off = Common.writeLength(buf, off, size);
            c25519_pub.getW(buf, off);
            return (short)(off + size);

        } else if(isEc()) {
            final ECPublicKey ecpub = (ECPublicKey)keys.getPublic();
            final short qsize = (short)(1 + 2 * (short)((ecpub.getSize() / 8) + (((ecpub.getSize() % 8) == 0) ? 0 : 1)));
            short rsize = (short)(1 + qsize);

            if(qsize > 0x7f) {
                rsize = (short)(rsize + 2);
            } else {
                rsize = (short)(rsize + 1);
            }

            off = Common.writeLength(buf, off, rsize);
            buf[off++] = (byte)0x86;
            off = Common.writeLength(buf, off, qsize);
            off += ecpub.getW(buf, off);

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return off;
    }

    protected final short sign(final Common common,
                               final ECCurves ec,
                               final byte[] buf, final short lc,
                               final boolean forAuth) {
        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        short off = 0;

        if(isRsa()) {
            final PrivateKey priv = keys.getPrivate();
            byte[] sha_header = null;

            if(!forAuth) {
                if(lc == (short)(2 + Constants.DSI_SHA256_HEADER[1])) {
                    sha_header = Constants.DSI_SHA256_HEADER;
                } else if(lc == (short)(2 + Constants.DSI_SHA384_HEADER[1])) {
                    sha_header = Constants.DSI_SHA384_HEADER;
                } else if(lc == (short)(2 + Constants.DSI_SHA512_HEADER[1])) {
                    sha_header = Constants.DSI_SHA512_HEADER;
                } else {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return 0;
                }

                if(Util.arrayCompare(buf, (short)0, sha_header, (short)0, (byte)sha_header.length) != 0) {
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    return 0;
                }
            }

            if(lc > (short)(((short)(Common.bitsToBytes(rsaModulusBitSize()) * 2)) / 5)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            final Cipher cipher = common.getCipherRsaPkcs1();
            cipher.init(priv, Cipher.MODE_ENCRYPT);

            off = cipher.doFinal(buf, (short)0, lc,
                                 buf, lc);

            return Util.arrayCopyNonAtomic(buf, lc,
                                           buf, (short)0,
                                           off);

        } else if(isCurve25519(ec)) {
            final ECParams params = ecParams(ec);
            if(!params.isEd25519) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            if((short)(lc + 64) > (short)buf.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            /* Ed25519 sign in hardware: writes 64-byte signature at buf[lc] */
            short sig_size = 0;
            try {
                sig_size = common.getCurve25519Sig().sign(c25519_priv, buf, (short)0, lc, buf, lc);
            } catch (CryptoException e) {
                Util.arrayFillNonAtomic(buf, (short)0, lc, (byte)0);
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            /* RFC 8032 §5.1.6: An Ed25519 signature is strictly 64 bytes (R || S) */
            if(sig_size != 64) {
                Util.arrayFillNonAtomic(buf, (short)0, (short)buf.length, (byte)0);
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
                return 0;
            }

            off = Util.arrayCopyNonAtomic(buf, lc, buf, (short)0, sig_size);

            /* Cryptographic Audit: Zeroize scratch buffer area */
            Util.arrayFillNonAtomic(buf, sig_size, lc, (byte)0);

            return off;

        } else if(isEc()) {
            final PrivateKey priv = keys.getPrivate();
            final Signature sig = common.getEcdsaSignature(lc);

            sig.init(priv, Signature.MODE_SIGN);

            final short sig_size = sig.signPreComputedHash(buf, (short)0, lc,
                                                           buf, lc);

            off = (short)(lc + 1);
            if((buf[off] & (byte)0x80) != (byte)0) {
                ++off;
            }
            ++off;

            if((buf[off++] != (byte)0x02)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((buf[off] & (byte)0x80) != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final short r_size = Util.makeShort((byte)0, buf[off++]);
            final short r_off = off;

            off += r_size;

            if((buf[off++] != (byte)0x02)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((buf[off] & (byte)0x80) != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final short s_size = Util.makeShort((byte)0, buf[off++]);
            final short s_off = off;

            off = (short)(lc + sig_size);

            if(r_size < s_size) {
                off = Util.arrayFillNonAtomic(buf, off, (short)(s_size - r_size), (byte)0);
            }

            off = Util.arrayCopyNonAtomic(buf, r_off,
                                          buf, off, r_size);

            if(s_size < r_size) {
                off = Util.arrayFillNonAtomic(buf, off, (short)(r_size - s_size), (byte)0);
            }

            off = Util.arrayCopyNonAtomic(buf, s_off,
                                          buf, off, s_size);

            off = Util.arrayCopyNonAtomic(buf, (short)(lc + sig_size),
                                          buf, (short)0,
                                          (short)(off - lc - sig_size));

            Util.arrayFillNonAtomic(buf, off, (short)(lc + sig_size - off), (byte)0);

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }

    protected final short decipher(final Common common, final ECCurves ec,
                                   final byte[] buf, final short lc) {

        if(!isInitialized()) {
            ISOException.throwIt(Constants.SW_REFERENCE_DATA_NOT_FOUND);
            return 0;
        }

        short off = 0;

        if(isRsa()) {
            final PrivateKey priv = keys.getPrivate();
            final short modulus_size = Common.bitsToBytes(rsaModulusBitSize());

            if(lc != (short)(modulus_size + 1)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(buf[0] != (byte)0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            final Cipher cipher = common.getCipherRsaPkcs1();
            cipher.init(priv, Cipher.MODE_DECRYPT);

            final short len = cipher.doFinal(buf, (short)1, (short)(lc - 1),
                                             buf, lc);

            off = Util.arrayCopyNonAtomic(buf, lc,
                                          buf, (short)0,
                                          len);

            Util.arrayFillNonAtomic(buf, lc, len, (byte)0);

            return off;

        } else if(isCurve25519(ec)) {
            final ECParams params = ecParams(ec);
            if(params.isEd25519) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            /* Parse Cipher DO: A6 -> 7F49 -> 86 */
            if(buf[off] != (byte)0xA6) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            ++off;

            short elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(Util.getShort(buf, off) != (short)0x7f49) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            off += 2;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(buf[off] != (byte)0x86) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            ++off;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if((elc == 33) && (buf[off] == (byte)0x40)) {
                off++;
                elc--;
            }
            if(elc != 32) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            /* RFC 7748 Small-Subgroup Attack Defense:
             * Reject known non-zero order-8 roots in addition to hardware rejection of 0, 1, p-1 */
            if((Util.arrayCompare(buf, off, LOW_ORDER_ROOT1, (short)0, (short)32) == 0) ||
               (Util.arrayCompare(buf, off, LOW_ORDER_ROOT2, (short)0, (short)32) == 0)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if((short)(lc + 32) > (short)buf.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            /* Load remote public key into transient key object */
            final Curve25519PublicKey eph = common.getCurve25519EphPub();
            eph.setW(buf, off, (short)32);

            /* Hardware X25519 key agreement */
            short secret_len = 0;
            try {
                secret_len = common.getCurve25519Ka().keyExchange(c25519_priv, eph, buf, lc);
            } catch (CryptoException e) {
                Util.arrayFillNonAtomic(buf, (short)0, lc, (byte)0);
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            } finally {
                /* Cryptographic Audit: Zeroize ephemeral public key object immediately */
                eph.clearKey();
            }

            /* RFC 7748 §6 & Lim-Lee Small Subgroup Attack Mitigation:
             * Validate that ECDH shared secret is not all-zero and exactly 32 bytes */
            if(secret_len != 32) {
                Util.arrayFillNonAtomic(buf, (short)0, (short)buf.length, (byte)0);
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            byte all_zero = 0;
            for(short z = lc; z < (short)(lc + 32); ++z) {
                all_zero |= buf[z];
            }
            if(all_zero == (byte)0) {
                Util.arrayFillNonAtomic(buf, (short)0, (short)buf.length, (byte)0);
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            /* Copy shared secret to response buffer */
            off = Util.arrayCopyNonAtomic(buf, lc, buf, (short)0, secret_len);

            /* Cryptographic Audit: Zeroize scratch buffer area */
            Util.arrayFillNonAtomic(buf, secret_len, lc, (byte)0);

            return off;

        } else if(isEc()) {
            final PrivateKey priv = keys.getPrivate();
            final ECParams params = ecParams(ec);
            short elc = 7;

            if(params.nb_bits >= (short)512) {
                elc = 10;
            }

            if(lc != (short)(elc + 1 + (short)(2 * Common.bitsToBytes(params.nb_bits)))) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }

            if(buf[off] != (byte)0xA6) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            ++off;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(Util.getShort(buf, off) != (short)0x7f49) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            off += 2;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            if(buf[off] != (byte)0x86) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return 0;
            }
            ++off;

            elc = Common.readLength(buf, off, (short)(lc - off));
            off = Common.skipLength(buf, off, (short)(lc - off));
            if(elc != (short)(lc - off)) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            final KeyAgreement ka = common.getKaEcDh();
            ka.init(priv);

            final short len  = ka.generateSecret(buf, off, (short)(lc - off),
                                                 buf, lc);

            off = Util.arrayCopyNonAtomic(buf, lc,
                                          buf, (short)0,
                                          len);

            Util.arrayFillNonAtomic(buf, lc, len, (byte)0);

            return off;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }

    protected final void initSignature(final Signature sign) {
        if(!isInitialized() || (keys == null)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }
        sign.init(keys.getPrivate(), Signature.MODE_SIGN);
    }

    protected final void initKeyAgreement(final KeyAgreement ka) {
        if(!isInitialized() || (keys == null)) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }
        ka.init(keys.getPrivate());
    }

}
