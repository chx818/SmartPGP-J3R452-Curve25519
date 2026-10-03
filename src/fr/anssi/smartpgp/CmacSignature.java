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

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Signature;

/** Native CMAC only: do not expose K1/K2 or CBC intermediate state to Java.
 * Lack of ALG_AES_CMAC_128 support fails session initialization, with no software
 * downgrade. Physical protection of the native service remains platform-specific.
 */
public final class CmacSignature {
    private CmacKey key;
    private Signature engine;
    private final byte[] result;
    private final byte[] short_input;

    protected CmacSignature() {
        result=JCSystem.makeTransientByteArray((short)16,JCSystem.CLEAR_ON_DESELECT);
        short_input=JCSystem.makeTransientByteArray((short)2,JCSystem.CLEAR_ON_DESELECT);
    }
    private void eraseScratch() {
        Util.arrayFillNonAtomic(result,(short)0,(short)result.length,(byte)0);
        Util.arrayFillNonAtomic(short_input,(short)0,(short)short_input.length,(byte)0);
    }
    protected final void clear() {
        try { if(key!=null) { key.clearKey(); } }
        finally { key=null; eraseScratch(); }
    }
    protected final boolean isInitialized() { return key!=null && key.isInitialized(); }
    protected final void init(final CmacKey next) {
        if(next==null || !next.isInitialized()) { CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY); }
        key=next;
        eraseScratch();
        if(engine==null) { engine=Signature.getInstance(Signature.ALG_AES_CMAC_128,false); }
        engine.init(key.key,Signature.MODE_SIGN);
    }
    protected final void update(final byte[] buf,final short off,final short len) {
        if(!isInitialized()) { CryptoException.throwIt(CryptoException.INVALID_INIT); }
        if(len<0) { CryptoException.throwIt(CryptoException.ILLEGAL_USE); }
        if(len>0) { engine.update(buf,off,len); }
    }
    protected final void updateByte(final byte value) {
        short_input[0]=value;
        try { update(short_input,(short)0,(short)1); }
        finally { Util.arrayFillNonAtomic(short_input,(short)0,(short)2,(byte)0); }
    }
    protected final void updateShort(final short value) {
        Util.setShort(short_input,(short)0,value);
        try { update(short_input,(short)0,(short)2); }
        finally { Util.arrayFillNonAtomic(short_input,(short)0,(short)2,(byte)0); }
    }
    protected final short sign(final byte[] buf,final short off,final short len,
                               final byte[] out,final short outOff,final short outLen) {
        if(!isInitialized()) { CryptoException.throwIt(CryptoException.INVALID_INIT); }
        if(len<0 || outLen<0 || outLen>16) { CryptoException.throwIt(CryptoException.ILLEGAL_VALUE); }
        try {
            // Some native implementations reject null even when the message is empty.
            short size=engine.sign(len==0 ? short_input : buf,len==0 ? (short)0 : off,len,result,(short)0);
            if(size!=16) { CryptoException.throwIt(CryptoException.ILLEGAL_USE); }
            Util.arrayCopyNonAtomic(result,(short)0,out,outOff,outLen);
            // Reset accumulation explicitly before reusing this object.
            engine.init(key.key,Signature.MODE_SIGN);
            return outLen;
        } finally { eraseScratch(); }
    }
}
