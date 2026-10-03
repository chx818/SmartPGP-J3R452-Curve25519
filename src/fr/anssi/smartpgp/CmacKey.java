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

import javacard.security.AESKey;
import javacard.security.KeyBuilder;

/** Native AES key container. No application-level CMAC subkey arrays. */
public final class CmacKey {
    protected final AESKey key;

    protected CmacKey(final short aesKeyLength) {
        key=(AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                        (short)(aesKeyLength*8),false);
    }
    protected final boolean isInitialized() { return key.isInitialized(); }
    protected final void clearKey() { key.clearKey(); }
    protected final short getSize() { return key.getSize(); }
    protected final void setKey(final byte[] buf,final short off) { key.setKey(buf,off); }
}
