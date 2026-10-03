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

/** Bounded receiver for plaintext PUT DATA DB. Small imports retain the existing
 * parser. Large RSA format-3 imports reuse the normal work buffer one component
 * at a time. No APDU/global buffer reference or private component is persistent.
 */
final class RsaImportStream {
    private static final byte MODE=0, USED=1, EXPECTED=2, RECEIVED=3, SLOT=4,
        COMPONENT=5, TOUCHED=6, OUTER_END=7, STATE_SIZE=8;
    private static final short PREFIX=1, BUFFERED=2, HEADER=3, DATA=4, COMPLETE=5;
    private static final short MAX_COMMAND=1900, MAX_HEADER=64;
    private final short[] state;

    RsaImportStream() {
        state=JCSystem.makeTransientShortArray(STATE_SIZE,JCSystem.CLEAR_ON_DESELECT);
    }

    boolean active() { return state[MODE]!=0; }
    boolean streamed() { return state[MODE]>=HEADER; }
    short bufferedLength() { return state[USED]; }

    void begin() {
        if(active()) { ISOException.throwIt(Constants.SW_CHAINING_ERROR); }
        state[MODE]=PREFIX;
    }

    void clear(final PGPKey[] keys) {
        try {
            if(state[TOUCHED]!=0) { keys[state[SLOT]].abortStreamImport(); }
        } finally {
            for(byte i=0;i<STATE_SIZE;++i) { state[i]=0; }
        }
    }

    /* Return the end of a complete BER length; 0 means more bytes needed. */
    private short lengthEnd(final byte[] b, final short off, final short available) {
        if(off>=available) { return 0; }
        short lead=(short)(b[off]&0xff);
        short count=lead<128 ? (short)1 : (lead==129 ? (short)2 : (lead==130 ? (short)3 : (short)0));
        if(count==0) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
        if(count>(short)(available-off)) { return 0; }
        if(count==3 && b[(short)(off+1)]<0) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
        return (short)(off+count);
    }

    private short lengthValue(final byte[] b, final short off, final short end) {
        if(end==(short)(off+1)) { return (short)(b[off]&0xff); }
        if(end==(short)(off+2)) { return (short)(b[(short)(off+1)]&0xff); }
        return Util.getShort(b,(short)(off+1));
    }

    private short componentLength(final PGPKey key, final short component) {
        if(component==0) { return 3; }
        short width=Common.bitsToBytes(key.rsaModulusBitSize());
        return component==6 ? width : (short)(width/2);
    }

    private void tryHeader(final byte[] b, final PGPKey[] keys) {
        short used=state[USED];
        short off=state[OUTER_END];
        if((short)(used-off)<2) { return; }
        short slot;
        switch(b[off++]) {
        case (byte)0xb6: slot=Persistent.PGP_KEYS_OFFSET_SIG; break;
        case (byte)0xb8: slot=Persistent.PGP_KEYS_OFFSET_DEC; break;
        case (byte)0xa4: slot=Persistent.PGP_KEYS_OFFSET_AUT; break;
        default: ISOException.throwIt(ISO7816.SW_WRONG_DATA); return;
        }
        byte crtLength=b[off++];
        if(crtLength==3) {
            if((short)(used-off)<3) { return; }
            if(b[off++]!=(byte)0x84 || b[off++]!=1 || b[off++]!=(byte)(slot+1)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        } else if(crtLength!=0) { ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); }
        PGPKey key=keys[slot];
        if(!key.isRsa() || (key.rsaModulusBitSize()!=3072 && key.rsaModulusBitSize()!=4096)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        if((short)(used-off)<2) { return; }
        if(Util.getShort(b,off)!=(short)0x7f48) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
        off+=2;
        short end=lengthEnd(b,off,used);
        if(end==0) { return; }
        short templateLength=lengthValue(b,off,end);
        off=end;
        if(templateLength<=0 || templateLength>28) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
        short templateEnd=(short)(off+templateLength);
        if(templateEnd>used) { return; }
        short total=0;
        for(short component=0;component<7;++component) {
            if((short)(templateEnd-off)<2 || b[off++]!=(byte)(0x91+component)) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
            end=lengthEnd(b,off,templateEnd);
            if(end==0) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            short size=lengthValue(b,off,end);
            if(size!=componentLength(key,component)) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
            total+=size;
            off=end;
        }
        if(off!=templateEnd) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
        if((short)(used-off)<2) { return; }
        if(Util.getShort(b,off)!=(short)0x5f48) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
        off+=2;
        end=lengthEnd(b,off,used);
        if(end==0) { return; }
        short declared=lengthValue(b,off,end);
        if(declared!=total || state[EXPECTED]!=(short)(end+total) || end!=used) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        /* All metadata is checked before destroying an old key. */
        state[SLOT]=slot;
        state[TOUCHED]=1;
        key.beginStreamImport();
        Util.arrayFillNonAtomic(b,(short)0,used,(byte)0);
        state[USED]=0;
        state[COMPONENT]=0;
        state[MODE]=DATA;
    }

    void accept(final byte[] in, short off, short len, final byte[] work, final PGPKey[] keys) {
        if(!active()) { ISOException.throwIt(Constants.SW_CHAINING_ERROR); }
        while(len>0) {
            if(state[RECEIVED]>=MAX_COMMAND || (state[EXPECTED]>0 && state[RECEIVED]>=state[EXPECTED])) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            byte value=in[off++]; --len;
            ++state[RECEIVED];
            short used=state[USED];
            if(state[MODE]==COMPLETE || used>=(short)work.length) { ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); }
            work[used++]=value;
            state[USED]=used;
            if(state[MODE]==PREFIX) {
                if(work[0]!=(byte)0x4d) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                short end=lengthEnd(work,(short)1,used);
                if(end==0) { continue; }
                short size=lengthValue(work,(short)1,end);
                if(size<0 || size>(short)(MAX_COMMAND-end)) { ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); }
                state[EXPECTED]=(short)(end+size);
                state[OUTER_END]=end;
                state[MODE]=state[EXPECTED]>(short)work.length ? HEADER : BUFFERED;
            } else if(state[MODE]==HEADER) {
                if(used>MAX_HEADER) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
                tryHeader(work,keys);
            } else if(state[MODE]==DATA) {
                PGPKey key=keys[state[SLOT]];
                if(used==componentLength(key,state[COMPONENT])) {
                    key.setStreamComponent(state[COMPONENT],work,used);
                    Util.arrayFillNonAtomic(work,(short)0,used,(byte)0);
                    state[USED]=0;
                    if(++state[COMPONENT]==7) { state[MODE]=COMPLETE; }
                }
            }
        }
    }

    void requireFinalLength() {
        if(state[EXPECTED]==0 || state[RECEIVED]!=state[EXPECTED] ||
           (state[MODE]!=BUFFERED && state[MODE]!=COMPLETE)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
    }

    short finish(final Common common, final ECCurves ec, final byte[] work, final PGPKey[] keys) {
        requireFinalLength();
        if(state[MODE]!=COMPLETE) { ISOException.throwIt(ISO7816.SW_WRONG_DATA); }
        short slot=state[SLOT];
        keys[slot].finishStreamImport(common,ec,work);
        state[TOUCHED]=0;
        clear(keys);
        return slot;
    }
}
