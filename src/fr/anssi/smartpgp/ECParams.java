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

import javacard.framework.Util;
import javacard.security.ECKey;

public final class ECParams {

    protected final short nb_bits;
    protected final byte[] oid;
    protected final byte[] field, a, b, g, r;
    protected final short k;
    protected final boolean isCurve25519;
    protected final boolean isEd25519;

    /**
     * Constructor for standard Weierstrass curves (secp / brainpool)
     */
    protected ECParams(final short nb_bits,
                       final byte[] oid,
                       final byte[] field, /* p */
                       final byte[] a,
                       final byte[] b,
                       final byte[] g,
                       final byte[] r, /* n */
                       final short k) /* h */ {
        this.nb_bits = nb_bits;
        this.oid = oid;
        this.field = field;
        this.a = a;
        this.b = b;
        this.g = g;
        this.r = r;
        this.k = k;
        this.isCurve25519 = false;
        this.isEd25519 = false;
    }

    /**
     * Constructor for Curve25519 curves (Ed25519 or X25519)
     */
    protected ECParams(final byte[] oid, final boolean isEd25519) {
        this.nb_bits = (short)256;
        this.oid = oid;
        this.field = null;
        this.a = null;
        this.b = null;
        this.g = null;
        this.r = null;
        this.k = (short)0;
        this.isCurve25519 = true;
        this.isEd25519 = isEd25519;
    }

    protected final boolean matchOid(final byte[] buf, final short off, final short len) {
        return (len == (short)oid.length) && (Util.arrayCompare(buf, off, oid, (short)0, len) == 0);
    }

    protected final void setParams(final ECKey key) {
        if(!isCurve25519) {
            key.setFieldFP(field, (short)0, (short)field.length);
            key.setA(a, (short)0, (short)a.length);
            key.setB(b, (short)0, (short)b.length);
            key.setG(g, (short)0, (short)g.length);
            key.setR(r, (short)0, (short)r.length);
            key.setK(k);
        }
    }
}
