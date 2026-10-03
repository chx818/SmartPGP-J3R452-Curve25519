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

    protected byte[] certificate;
    private byte[] certificate_staging;
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
    private byte key_state;
    private byte key_state_inverse;
    private static final byte KEY_EMPTY = (byte)0x33;
    private static final byte KEY_UPDATING = (byte)0x5A;
    private static final byte KEY_VALID = (byte)0x66;

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
        certificate_staging = new byte[Constants.cardholderCertificateMaxLength()];
        certificate_length = 0;

        attributes = new byte[Constants.ALGORITHM_ATTRIBUTES_MAX_LENGTH];
        attributes_length = 0;

        data_tag_val = JCSystem.makeTransientByteArray((short)7, JCSystem.CLEAR_ON_DESELECT);
        data_tag_len = JCSystem.makeTransientShortArray((short)7, JCSystem.CLEAR_ON_DESELECT);

        reset(true);
    }

    private final void resetKeys(final boolean isRegistering) {
        setKeyState(KEY_UPDATING, isRegistering);

        if(keys != null) {
            keys.getPrivate().clearKey();
            keys.getPublic().clearKey();
            keys = null;
        }

        if(c25519_priv != null) {
            c25519_priv.clearKey();
            c25519_priv = null;
        }

        if(c25519_pub != null) {
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
        setKeyState(KEY_EMPTY, isRegistering);
    }

    protected final void reset(final boolean isRegistering) {
        resetKeys(isRegistering);

        if(isRegistering) {
            byte[] defaults=is_secure_messaging_key ? Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING : Constants.ALGORITHM_ATTRIBUTES_DEFAULT;
            Util.arrayCopyNonAtomic(defaults,(short)0,attributes,(short)0,(short)defaults.length);
            attributes_length=(byte)defaults.length;
            return;
        }
        Common.beginTransaction(false);
        if(attributes_length > 0) {
            Common.arrayFillAtomic(attributes, (short)0, attributes_length, (byte)0);
            attributes_length = (byte)0;
        }

        if(is_secure_messaging_key) {
            Util.arrayCopy(Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING, (short)0,
                                    attributes, (short)0,
                                    (short)Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length);
            attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_DEFAULT_SECURE_MESSAGING.length;
        } else {
            Util.arrayCopy(Constants.ALGORITHM_ATTRIBUTES_DEFAULT, (short)0,
                                    attributes, (short)0,
                                    (short)Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length);
            attributes_length = (byte)Constants.ALGORITHM_ATTRIBUTES_DEFAULT.length;
        }
        Common.commitTransaction(isRegistering);
    }

    private final void setKeyState(final byte state, final boolean registering) {
        Common.beginTransaction(registering);
        key_state = state;
        key_state_inverse = (byte)~state;
        Common.commitTransaction(registering);
    }

    protected final boolean isInitialized() {
        return key_state == KEY_VALID && key_state_inverse == (byte)~KEY_VALID && keyObjectsInitialized();
    }

    private final boolean keyObjectsInitialized() {
        if(c25519_priv != null || c25519_pub != null) {
            return c25519_priv != null && c25519_pub != null &&
                   c25519_priv.isInitialized() && c25519_pub.isInitialized();
        }
        return keys != null && keys.getPrivate().isInitialized() && keys.getPublic().isInitialized();
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

        // Stage outside the transaction; only references and length are committed.
        Util.arrayFillNonAtomic(certificate_staging,(short)0,(short)certificate_staging.length,(byte)0);
        Util.arrayCopyNonAtomic(buf,off,certificate_staging,(short)0,len);
        JCSystem.beginTransaction();
        byte[] old=certificate;
        certificate=certificate_staging;
        certificate_staging=old;
        certificate_length=len;
        JCSystem.commitTransaction();
        Util.arrayFillNonAtomic(certificate_staging,(short)0,(short)certificate_staging.length,(byte)0);
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
            if(((Util.getShort(buf, (short)(off + 1)) != 2048) &&
                (Util.getShort(buf, (short)(off + 1)) != 3072) &&
                (Util.getShort(buf, (short)(off + 1)) != 4096)) ||
               (Util.getShort(buf, (short)(off + 3)) != 0x11) ||
               (buf[(short)(off + 5)] != 3)) {
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
            Common.arrayFillAtomic(attributes, (short)0, attributes_length, (byte)0);
        }
        Util.arrayCopy(buf, off, attributes, (short)0, len);
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

    protected final void generate(final Common common, final ECCurves ec, final byte[] scratch) {
        resetKeys(false);
        setKeyState(KEY_UPDATING,false);
        boolean success=false;
        try {
            if(isRsa()) { keys=generateRSA(); }
            else if(isCurve25519(ec)) {
                if(!generateCurve25519(ecParams(ec))) { ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); }
            } else { keys=generateEC(ec); }
            if(!isCurve25519(ec)) {
                if(keys==null) { ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); }
                keys.genKeyPair();
            }
            if(!keyObjectsInitialized()) { ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); }
            validatePair(common,ec,scratch);
            has_been_generated=true;
            setKeyState(KEY_VALID,false);
            success=true;
        } finally {
            Util.arrayFillNonAtomic(scratch,(short)0,(short)scratch.length,(byte)0);
            if(!success) { resetKeys(false); }
        }
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

        keys = new KeyPair(pub, priv);
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

        keys = new KeyPair(pub, priv);
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
            c25519_priv.clearKey();
            c25519_priv = null;
        }
        if(c25519_pub != null) {
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
                    /* Ed25519 is a seed, never clamp it. Legacy OpenPGP cv25519
                       imports the scalar as a big-endian integer; JCOPX setS uses
                       the same integer order (unlike its public wire encoding). */
                    if(!params.isEd25519) {
                        buf[(short)(off+31)] &= (byte)0xf8;
                        buf[off] = (byte)((buf[off] & 0x7f) | 0x40);
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
                    if(!params.isEd25519) { normalizeX25519(buf,pubOff); }
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

    protected final void importKey(final Common common, final ECCurves ec,
                                   final byte[] buf, final short boff, final short len) {
        Common.requireSpace(buf, boff, len);
        short off = boff;
        short end = (short)(boff + len);
        byte count = 0;
        boolean updating = false;
        try {
            if((short)(end-off) < 3 || Util.getShort(buf,off) != (short)0x7f48) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            off += 2;
            short templateLen = Common.readLength(buf,off,(short)(end-off));
            off = Common.skipLength(buf,off,(short)(end-off));
            if(templateLen <= 0 || templateLen > (short)(end-off)) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            short templateEnd = (short)(off+templateLen);
            short total = 0;
            while(off < templateEnd) {
                if(count >= data_tag_val.length || (short)(templateEnd-off) < 2) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                byte tag = buf[off++];
                if((tag & 0xff) < 0x91 || (tag & 0xff) > 0x99) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                for(byte i=0;i<count;++i) { if(data_tag_val[i] == tag) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); } }
                short size = Common.readLength(buf,off,(short)(templateEnd-off));
                off = Common.skipLength(buf,off,(short)(templateEnd-off));
                if(size <= 0 || size > (short)(len-total)) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                total += size;
                data_tag_val[count] = tag;
                data_tag_len[count++] = size;
            }
            if((short)(end-off)<3 || Util.getShort(buf,off)!=(short)0x5f48) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            off += 2;
            short dataLen = Common.readLength(buf,off,(short)(end-off));
            off = Common.skipLength(buf,off,(short)(end-off));
            if(dataLen != total || dataLen != (short)(end-off)) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            if(isRsa()) {
                if(count != 7) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                for(byte i=0;i<7;++i) {
                    if(data_tag_val[i] != (byte)(0x91+i)) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                    short expected = i==0 ? Common.bitsToBytes(rsaExponentBitSize()) :
                        (i==6 ? Common.bitsToBytes(rsaModulusBitSize()) : (short)(Common.bitsToBytes(rsaModulusBitSize())/2));
                    if(data_tag_len[i]!=expected) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                }
            } else {
                if(count!=2 || data_tag_val[0]!=(byte)0x92 || data_tag_val[1]!=(byte)0x99) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                ECParams params=ecParams(ec);
                short width=Common.bitsToBytes(params.nb_bits);
                if(data_tag_len[0] <= 0 || data_tag_len[0]>width ||
                   (params.isCurve25519 && data_tag_len[0]!=32) ||
                   (params.isCurve25519 ? (data_tag_len[1]!=32 && data_tag_len[1]!=33) : data_tag_len[1]!=(short)(1+2*width))) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }
            }
            resetKeys(false);
            setKeyState(KEY_UPDATING,false);
            updating = true;
            boolean ok;
            if(isRsa()) { ok=importRSAKey(buf,off,dataLen,count,data_tag_val,data_tag_len)!=null; }
            else if(isCurve25519(ec)) { ok=importCurve25519Key(ecParams(ec),buf,off,dataLen,count,data_tag_val,data_tag_len); }
            else { ok=importECKey(ec,buf,off,dataLen,count,data_tag_val,data_tag_len)!=null; }
            if(!ok || !keyObjectsInitialized()) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            Util.arrayFillNonAtomic(buf,(short)0,(short)buf.length,(byte)0);
            validatePair(common,ec,buf);
            has_been_generated=false;
            setKeyState(KEY_VALID,false);
            updating=false;
        } finally {
            Util.arrayFillNonAtomic(buf,(short)0,(short)buf.length,(byte)0);
            Util.arrayFillNonAtomic(data_tag_val,(short)0,(short)data_tag_val.length,(byte)0);
            for(byte i=0;i<data_tag_len.length;++i) { data_tag_len[i]=0; }
            if(updating) { resetKeys(false); }
        }
    }

    /* Pairwise test before activation. Uses only public outputs and transient scratch. */
    private final void validatePair(final Common common, final ECCurves ec, final byte[] buf) {
        boolean ok = false;
        try {
            common.random.generateData(buf,(short)0,(short)32);
            if(isCurve25519(ec)) {
                if(ecParams(ec).isEd25519) {
                    short n=common.getCurve25519Sig().sign(c25519_priv,buf,(short)0,(short)32,buf,(short)32);
                    ok=n==64 && common.getCurve25519Sig().verify(c25519_pub,buf,(short)0,(short)32,buf,(short)32,n);
                } else {
                    Curve25519PublicKey eph=common.getCurve25519EphPub();
                    try {
                        Util.arrayFillNonAtomic(buf,(short)0,(short)32,(byte)0); buf[0]=9;
                        eph.setW(buf,(short)0,(short)32);
                        short n=common.getCurve25519Ka().keyExchange(c25519_priv,eph,buf,(short)32);
                        short m=c25519_pub.getW(buf,(short)64);
                        ok=n==32 && m==32 && Common.equal(buf,(short)32,buf,(short)64,(short)32);
                    } finally { eph.clearKey(); }
                }
            } else if(isRsa()) {
                Cipher c=common.getCipherRsaPkcs1();
                c.init(keys.getPrivate(),Cipher.MODE_ENCRYPT);
                short n=c.doFinal(buf,(short)0,(short)32,buf,(short)32);
                c.init(keys.getPublic(),Cipher.MODE_DECRYPT);
                short m=c.doFinal(buf,(short)32,n,buf,(short)(32+n));
                ok=m==32 && Common.equal(buf,(short)0,buf,(short)(32+n),(short)32);
            } else {
                Signature sig=common.getEcdsaSignature((short)32);
                sig.init(keys.getPrivate(),Signature.MODE_SIGN);
                short n=sig.signPreComputedHash(buf,(short)0,(short)32,buf,(short)32);
                sig.init(keys.getPublic(),Signature.MODE_VERIFY);
                ok=sig.verifyPreComputedHash(buf,(short)0,(short)32,buf,(short)32,n);
            }
            if(!ok) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
        } finally { Util.arrayFillNonAtomic(buf,(short)0,(short)buf.length,(byte)0); }
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

            Common.requireSpace(buf,lc,(short)(Common.bitsToBytes(rsaModulusBitSize())+lc));
            off = cipher.doFinal(buf, (short)0, lc,
                                 buf, lc);

            short sigLen = off;
            Common.requireSpace(buf,(short)(lc+sigLen),lc);
            cipher.init(keys.getPublic(),Cipher.MODE_DECRYPT);
            short recovered=cipher.doFinal(buf,lc,sigLen,buf,(short)(lc+sigLen));
            if(recovered!=lc || !Common.equal(buf,(short)0,buf,(short)(lc+sigLen),lc)) { ISOException.throwIt(ISO7816.SW_UNKNOWN); }
            Util.arrayCopyNonAtomic(buf,lc,buf,(short)0,sigLen);
            Util.arrayFillNonAtomic(buf,sigLen,(short)(buf.length-sigLen),(byte)0);
            return sigLen;

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
                Util.arrayFillNonAtomic(buf, (short)0, (short)buf.length, (byte)0);
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            }

            /* RFC 8032 搂5.1.6: An Ed25519 signature is strictly 64 bytes (R || S) */
            if(sig_size != 64 || !common.getCurve25519Sig().verify(c25519_pub,buf,(short)0,lc,buf,lc,sig_size)) {
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

            sig.init(keys.getPublic(), Signature.MODE_VERIFY);
            if(!sig.verifyPreComputedHash(buf,(short)0,lc,buf,lc,sig_size)) {
                ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
            final short width = Common.bitsToBytes(ecParams(ec).nb_bits);
            final short rawOff = (short)(lc + sig_size);
            Common.requireSpace(buf,rawOff,(short)(2*width));
            off = lc;
            if(buf[off++] != 0x30) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            short sequenceLen = Common.readLength(buf,off,(short)(rawOff-off));
            off = Common.skipLength(buf,off,(short)(rawOff-off));
            if(sequenceLen != (short)(rawOff-off)) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            for(byte component=0;component<2;++component) {
                if((short)(rawOff-off)<2 || buf[off++]!=2) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                short size=(short)(buf[off++] & 0xff);
                if(size<=0 || size>(short)(rawOff-off) || buf[off]<0) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                if(size>1 && buf[off]==0) { ++off; --size; }
                if(size>width) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                short dst=(short)(rawOff+component*width);
                Util.arrayFillNonAtomic(buf,dst,width,(byte)0);
                Util.arrayCopyNonAtomic(buf,off,buf,(short)(dst+width-size),size);
                off+=size;
            }
            if(off!=rawOff) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            short result=(short)(2*width);
            Util.arrayCopyNonAtomic(buf,rawOff,buf,(short)0,result);
            Util.arrayFillNonAtomic(buf,result,(short)(buf.length-result),(byte)0);
            return result;
        }

        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0;
    }

    /* RFC 7748 decodeUCoordinate: public input only, mask bit 255 and reduce mod p.
       After masking, the only noncanonical values are p through p+18. */
    private static void normalizeX25519(final byte[] buf, final short off) {
        buf[(short)(off+31)] &= (byte)0x7f;
        boolean high = buf[(short)(off+31)] == (byte)0x7f;
        for(short i=1;i<31;++i) { high &= buf[(short)(off+i)] == (byte)0xff; }
        if(high && (short)(buf[off] & 0xff) >= (short)0xed) {
            byte low=(byte)((buf[off] & 0xff)-0xed);
            Util.arrayFillNonAtomic(buf,off,(short)32,(byte)0);
            buf[off]=low;
        }
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

            Common.requireSpace(buf,lc,modulus_size);
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

            if((short)(lc + 32) > (short)buf.length) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                return 0;
            }

            /* Load remote public key into transient key object */
            final Curve25519PublicKey eph = common.getCurve25519EphPub();

            /* Hardware X25519 key agreement */
            short secret_len = 0;
            try {
                normalizeX25519(buf,off);
                eph.setW(buf, off, (short)32);
                secret_len = common.getCurve25519Ka().keyExchange(c25519_priv, eph, buf, lc);
            } catch (CryptoException e) {
                Util.arrayFillNonAtomic(buf, (short)0, (short)buf.length, (byte)0);
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return 0;
            } finally {
                /* Cryptographic Audit: Zeroize ephemeral public key object immediately */
                eph.clearKey();
            }

            /* RFC 7748 搂6 & Lim-Lee Small Subgroup Attack Mitigation:
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
