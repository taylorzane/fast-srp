(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory(require('crypto'), require('scryptsy')) :
	typeof define === 'function' && define.amd ? define(['crypto', 'scryptsy'], factory) :
	(global.fastSRP = factory(global.crypt_,global.scrypt));
}(this, (function (crypt_,scrypt) { 'use strict';

crypt_ = crypt_ && crypt_.hasOwnProperty('default') ? crypt_['default'] : crypt_;
scrypt = scrypt && scrypt.hasOwnProperty('default') ? scrypt['default'] : scrypt;

var ScryptHash = function() {
    return {
        _digest: null,
        update(data) {
            if (!this._digest) {
                if (Buffer.isBuffer(data)) {
                    this._digest = data;
                } else {
                    this._digest = new Buffer(data.normalize('NFKC'), 'utf8');
                }
            } else {
                if (Buffer.isBuffer(data)) {
                    this._digest = Buffer.concat([this._digest, data]);
                } else {
                    this._digest = Buffer.concat([this._digest, new Buffer(data.normalize('NFKC'), 'utf8')]);
                }
            }

            return this
        },
        digest(encoding) {
            var salt = new Buffer(crypt.randomBytes(32), 'utf8');

            // TODO: Allow this to be customizable
            // FIXME: Update the salt to something longer
            return scrypt(this._digest, new Buffer('NaCl'), 32768, 8, 1, 32)
        }
    }
};

var crypt = {};
if (typeof window == 'undefined') {
    crypt = {
        createHash(hash) {
            if (hash === 'scrypt') {
                return new ScryptHash
            } else {
                return crypt_.createHash(hash)
            }
        },
        randomBytes: crypt_.randomBytes
    };
} else {
    crypt = {
        createHash() {
            return new ScryptHash
        },
        // TODO: Update this to use the polyfill from crypto-browserify
        randomBytes(size, callback) {
            var values = window.crypto.getRandomValues(new Uint8Array(size));

            if (callback && typeof callback === 'function') {
                callback(null, values);
            } else {
                return values
            }
        }
    };
}

var crypto = crypt

/*
 * Basic JavaScript BN library - subset useful for RSA encryption.
 *
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */

/*
 *
 * Copyright (c) 2015 Zarmack Tanen
 * Fixed .toString(16) to be compatible with node >0.12.7 because hexWrite()
 *       only accepts %2=0 strings
 *
 *
 * Added Node.js Buffers support
 * 2014 rzcoder
 */

// Bits per digit
var dbits;

// (public) Constructor
function BigInteger(a, b) {
    if (a != null) {
        if ("number" == typeof a) {
            this.fromNumber(a, b);
        } else if (Buffer.isBuffer(a)) {
            this.fromBuffer(a);
        } else if (b == null && "string" != typeof a) {
            this.fromByteArray(a);
        } else {
            this.fromString(a, b);
        }
    }
}

// return new, unset BigInteger
function nbi() {
    return new BigInteger(null);
}

// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i, x, w, j, c, n) {
    var xl = x & 0x3fff, xh = x >> 14;
    while (--n >= 0) {
        var l = this[i] & 0x3fff;
        var h = this[i++] >> 14;
        var m = xh * l + h * xl;
        l = xl * l + ((m & 0x3fff) << 14) + w[j] + c;
        c = (l >> 28) + (m >> 14) + xh * h;
        w[j++] = l & 0xfffffff;
    }
    return c;
}

// We need to select the fastest one that works in this environment.
//if (j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
//	BigInteger.prototype.am = am2;
//	dbits = 30;
//} else if (j_lm && (navigator.appName != "Netscape")) {
//	BigInteger.prototype.am = am1;
//	dbits = 26;
//} else { // Mozilla/Netscape seems to prefer am3
//	BigInteger.prototype.am = am3;
//	dbits = 28;
//}

// For node.js, we pick am3 with max dbits to 28.
BigInteger.prototype.am = am3;
dbits = 28;

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1 << dbits) - 1);
BigInteger.prototype.DV = (1 << dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr;
var vv;
rr = "0".charCodeAt(0);
for (vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for (vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) {
    return BI_RM.charAt(n);
}
function intAt(s, i) {
    var c = BI_RC[s.charCodeAt(i)];
    return (c == null) ? -1 : c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
    for (var i = this.t - 1; i >= 0; --i) r[i] = this[i];
    r.t = this.t;
    r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
    this.t = 1;
    this.s = (x < 0) ? -1 : 0;
    if (x > 0) this[0] = x;
    else if (x < -1) this[0] = x + DV;
    else this.t = 0;
}

// return bigint initialized to value
function nbv(i) {
    var r = nbi();
    r.fromInt(i);
    return r;
}

// (protected) set from string and radix
function bnpFromString(data, radix, unsigned) {
    var k;
    switch (radix) {
        case 2:
            k = 1;
            break;
        case 4:
            k = 2;
            break;
        case 8:
            k = 3;
            break;
        case 16:
            k = 4;
            break;
        case 32:
            k = 5;
            break;
        case 256:
            k = 8;
            break;
        default:
            this.fromRadix(data, radix);
            return;
    }

    this.t = 0;
    this.s = 0;

    var i = data.length;
    var mi = false;
    var sh = 0;

    while (--i >= 0) {
        var x = (k == 8) ? data[i] & 0xff : intAt(data, i);
        if (x < 0) {
            if (data.charAt(i) == "-") mi = true;
            continue;
        }
        mi = false;
        if (sh === 0)
            this[this.t++] = x;
        else if (sh + k > this.DB) {
            this[this.t - 1] |= (x & ((1 << (this.DB - sh)) - 1)) << sh;
            this[this.t++] = (x >> (this.DB - sh));
        }
        else
            this[this.t - 1] |= x << sh;
        sh += k;
        if (sh >= this.DB) sh -= this.DB;
    }
    if ((!unsigned) && k == 8 && (data[0] & 0x80) != 0) {
        this.s = -1;
        if (sh > 0) this[this.t - 1] |= ((1 << (this.DB - sh)) - 1) << sh;
    }
    this.clamp();
    if (mi) BigInteger.ZERO.subTo(this, this);
}

function bnpFromByteArray(a, unsigned) {
    this.fromString(a, 256, unsigned);
}

function bnpFromBuffer(a) {
    this.fromString(a, 256, true);
}

// (protected) clamp off excess high words
function bnpClamp() {
    var c = this.s & this.DM;
    while (this.t > 0 && this[this.t - 1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
    if (this.s < 0) return "-" + this.negate().toString(b);
    var k;
    if (b == 16) k = 4;
    else if (b == 8) k = 3;
    else if (b == 2) k = 1;
    else if (b == 32) k = 5;
    else if (b == 4) k = 2;
    else return this.toRadix(b);
    var km = (1 << k) - 1, d, m = false, r = "", i = this.t;
    var p = this.DB - (i * this.DB) % k;
    if (i-- > 0) {
        if (p < this.DB && (d = this[i] >> p) > 0) {
            m = true;
            r = int2char(d);
        }
        while (i >= 0) {
            if (p < k) {
                d = (this[i] & ((1 << p) - 1)) << (k - p);
                d |= this[--i] >> (p += this.DB - k);
            }
            else {
                d = (this[i] >> (p -= k)) & km;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
            }
            if (d > 0) m = true;
            if (m) r += int2char(d);
        }
    }
    //! Fix to be compatible with node >0.12.7 Buffer.js
    if(b == 16 && r.length % 2 != 0)
	     r = "0" + r;
    return m ? r : "0";
}

// (public) -this
function bnNegate() {
    var r = nbi();
    BigInteger.ZERO.subTo(this, r);
    return r;
}

// (public) |this|
function bnAbs() {
    return (this.s < 0) ? this.negate() : this;
}

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
    var r = this.s - a.s;
    if (r != 0) return r;
    var i = this.t;
    r = i - a.t;
    if (r != 0) return (this.s < 0) ? -r : r;
    while (--i >= 0) if ((r = this[i] - a[i]) != 0) return r;
    return 0;
}

function bnEqual(a) {
  return (this.compareTo(a) == 0) ? true: false;
}

function bnGreater(a) {
  return (this.compareTo(a) > 0) ? true : false;
}

function bnGreaterOrEqual(a) {
  return (this.compareTo(a) >= 0) ? true : false;
}

function bnLesser(a) {
  return (this.compareTo(a) < 0) ? true : false;
}

function bnLesserOrEqual(a) {
  return (this.compareTo(a) <= 0) ? true : false;
}

// returns bit length of the integer x
function nbits(x) {
    var r = 1, t;
    if ((t = x >>> 16) != 0) {
        x = t;
        r += 16;
    }
    if ((t = x >> 8) != 0) {
        x = t;
        r += 8;
    }
    if ((t = x >> 4) != 0) {
        x = t;
        r += 4;
    }
    if ((t = x >> 2) != 0) {
        x = t;
        r += 2;
    }
    if ((t = x >> 1) != 0) {
        x = t;
        r += 1;
    }
    return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
    if (this.t <= 0) return 0;
    return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ (this.s & this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n, r) {
    var i;
    for (i = this.t - 1; i >= 0; --i) r[i + n] = this[i];
    for (i = n - 1; i >= 0; --i) r[i] = 0;
    r.t = this.t + n;
    r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n, r) {
    for (var i = n; i < this.t; ++i) r[i - n] = this[i];
    r.t = Math.max(this.t - n, 0);
    r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n, r) {
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << cbs) - 1;
    var ds = Math.floor(n / this.DB), c = (this.s << bs) & this.DM, i;
    for (i = this.t - 1; i >= 0; --i) {
        r[i + ds + 1] = (this[i] >> cbs) | c;
        c = (this[i] & bm) << bs;
    }
    for (i = ds - 1; i >= 0; --i) r[i] = 0;
    r[ds] = c;
    r.t = this.t + ds + 1;
    r.s = this.s;
    r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n, r) {
    r.s = this.s;
    var ds = Math.floor(n / this.DB);
    if (ds >= this.t) {
        r.t = 0;
        return;
    }
    var bs = n % this.DB;
    var cbs = this.DB - bs;
    var bm = (1 << bs) - 1;
    r[0] = this[ds] >> bs;
    for (var i = ds + 1; i < this.t; ++i) {
        r[i - ds - 1] |= (this[i] & bm) << cbs;
        r[i - ds] = this[i] >> bs;
    }
    if (bs > 0) r[this.t - ds - 1] |= (this.s & bm) << cbs;
    r.t = this.t - ds;
    r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a, r) {
    var i = 0, c = 0, m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] - a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c -= a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    }
    else {
        c += this.s;
        while (i < a.t) {
            c -= a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c -= a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c < -1) r[i++] = this.DV + c;
    else if (c > 0) r[i++] = c;
    r.t = i;
    r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a, r) {
    var x = this.abs(), y = a.abs();
    var i = x.t;
    r.t = i + y.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < y.t; ++i) r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
    r.s = 0;
    r.clamp();
    if (this.s != a.s) BigInteger.ZERO.subTo(r, r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
    var x = this.abs();
    var i = r.t = 2 * x.t;
    while (--i >= 0) r[i] = 0;
    for (i = 0; i < x.t - 1; ++i) {
        var c = x.am(i, x[i], r, 2 * i, 0, 1);
        if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
            r[i + x.t] -= x.DV;
            r[i + x.t + 1] = 1;
        }
    }
    if (r.t > 0) r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
    r.s = 0;
    r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m, q, r) {
    var pm = m.abs();
    if (pm.t <= 0) return;
    var pt = this.abs();
    if (pt.t < pm.t) {
        if (q != null) q.fromInt(0);
        if (r != null) this.copyTo(r);
        return;
    }
    if (r == null) r = nbi();
    var y = nbi(), ts = this.s, ms = m.s;
    var nsh = this.DB - nbits(pm[pm.t - 1]);	// normalize modulus
    if (nsh > 0) {
        pm.lShiftTo(nsh, y);
        pt.lShiftTo(nsh, r);
    }
    else {
        pm.copyTo(y);
        pt.copyTo(r);
    }
    var ys = y.t;
    var y0 = y[ys - 1];
    if (y0 === 0) return;
    var yt = y0 * (1 << this.F1) + ((ys > 1) ? y[ys - 2] >> this.F2 : 0);
    var d1 = this.FV / yt, d2 = (1 << this.F1) / yt, e = 1 << this.F2;
    var i = r.t, j = i - ys, t = (q == null) ? nbi() : q;
    y.dlShiftTo(j, t);
    if (r.compareTo(t) >= 0) {
        r[r.t++] = 1;
        r.subTo(t, r);
    }
    BigInteger.ONE.dlShiftTo(ys, t);
    t.subTo(y, y);	// "negative" y so we can replace sub with am later
    while (y.t < ys) y[y.t++] = 0;
    while (--j >= 0) {
        // Estimate quotient digit
        var qd = (r[--i] == y0) ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
        if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {	// Try it out
            y.dlShiftTo(j, t);
            r.subTo(t, r);
            while (r[i] < --qd) r.subTo(t, r);
        }
    }
    if (q != null) {
        r.drShiftTo(ys, q);
        if (ts != ms) BigInteger.ZERO.subTo(q, q);
    }
    r.t = ys;
    r.clamp();
    if (nsh > 0) r.rShiftTo(nsh, r);	// Denormalize remainder
    if (ts < 0) BigInteger.ZERO.subTo(r, r);
}

// (public) this mod a
function bnMod(a) {
    var r = nbi();
    this.abs().divRemTo(a, null, r);
    if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r, r);
    return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) {
    this.m = m;
}
function cConvert(x) {
    if (x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
    else return x;
}
function cRevert(x) {
    return x;
}
function cReduce(x) {
    x.divRemTo(this.m, null, x);
}
function cMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}
function cSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
    if (this.t < 1) return 0;
    var x = this[0];
    if ((x & 1) === 0) return 0;
    var y = x & 3;		// y == 1/x mod 2^2
    y = (y * (2 - (x & 0xf) * y)) & 0xf;	// y == 1/x mod 2^4
    y = (y * (2 - (x & 0xff) * y)) & 0xff;	// y == 1/x mod 2^8
    y = (y * (2 - (((x & 0xffff) * y) & 0xffff))) & 0xffff;	// y == 1/x mod 2^16
    // last step - calculate inverse mod DV directly;
    // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
    y = (y * (2 - x * y % this.DV)) % this.DV;		// y == 1/x mod 2^dbits
    // we really want the negative inverse, and -DV < y < DV
    return (y > 0) ? this.DV - y : -y;
}

// Montgomery reduction
function Montgomery(m) {
    this.m = m;
    this.mp = m.invDigit();
    this.mpl = this.mp & 0x7fff;
    this.mph = this.mp >> 15;
    this.um = (1 << (m.DB - 15)) - 1;
    this.mt2 = 2 * m.t;
}

// xR mod m
function montConvert(x) {
    var r = nbi();
    x.abs().dlShiftTo(this.m.t, r);
    r.divRemTo(this.m, null, r);
    if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r, r);
    return r;
}

// x/R mod m
function montRevert(x) {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
    while (x.t <= this.mt2)	// pad x so am has enough room later
        x[x.t++] = 0;
    for (var i = 0; i < this.m.t; ++i) {
        // faster way of calculating u0 = x[i]*mp mod DV
        var j = x[i] & 0x7fff;
        var u0 = (j * this.mpl + (((j * this.mph + (x[i] >> 15) * this.mpl) & this.um) << 15)) & x.DM;
        // use am to combine the multiply-shift-add into one call
        j = i + this.m.t;
        x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
        // propagate carry
        while (x[j] >= x.DV) {
            x[j] -= x.DV;
            x[++j]++;
        }
    }
    x.clamp();
    x.drShiftTo(this.m.t, x);
    if (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

// r = "xy/R mod m"; x,y != r
function montMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() {
    return ((this.t > 0) ? (this[0] & 1) : this.s) === 0;
}

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e, z) {
    if (e > 0xffffffff || e < 1) return BigInteger.ONE;
    var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e) - 1;
    g.copyTo(r);
    while (--i >= 0) {
        z.sqrTo(r, r2);
        if ((e & (1 << i)) > 0) z.mulTo(r2, g, r);
        else {
            var t = r;
            r = r2;
            r2 = t;
        }
    }
    return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e, m) {
    var z;
    if (e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
    return this.exp(e, z);
}

// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

//(public)
function bnClone() {
    var r = nbi();
    this.copyTo(r);
    return r;
}

//(public) return value as integer
function bnIntValue() {
    if (this.s < 0) {
        if (this.t == 1) return this[0] - this.DV;
        else if (this.t === 0) return -1;
    }
    else if (this.t == 1) return this[0];
    else if (this.t === 0) return 0;
// assumes 16 < DB < 32
    return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
}

//(public) return value as byte
function bnByteValue() {
    return (this.t == 0) ? this.s : (this[0] << 24) >> 24;
}

//(public) return value as short (assumes DB>=16)
function bnShortValue() {
    return (this.t == 0) ? this.s : (this[0] << 16) >> 16;
}

//(protected) return x s.t. r^x < DV
function bnpChunkSize(r) {
    return Math.floor(Math.LN2 * this.DB / Math.log(r));
}

//(public) 0 if this === 0, 1 if this > 0
function bnSigNum() {
    if (this.s < 0) return -1;
    else if (this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
    else return 1;
}

//(protected) convert to radix string
function bnpToRadix(b) {
    if (b == null) b = 10;
    if (this.signum() === 0 || b < 2 || b > 36) return "0";
    var cs = this.chunkSize(b);
    var a = Math.pow(b, cs);
    var d = nbv(a), y = nbi(), z = nbi(), r = "";
    this.divRemTo(d, y, z);
    while (y.signum() > 0) {
        r = (a + z.intValue()).toString(b).substr(1) + r;
        y.divRemTo(d, y, z);
    }
    return z.intValue().toString(b) + r;
}

//(protected) convert from radix string
function bnpFromRadix(s, b) {
    this.fromInt(0);
    if (b == null) b = 10;
    var cs = this.chunkSize(b);
    var d = Math.pow(b, cs), mi = false, j = 0, w = 0;
    for (var i = 0; i < s.length; ++i) {
        var x = intAt(s, i);
        if (x < 0) {
            if (s.charAt(i) == "-" && this.signum() === 0) mi = true;
            continue;
        }
        w = b * w + x;
        if (++j >= cs) {
            this.dMultiply(d);
            this.dAddOffset(w, 0);
            j = 0;
            w = 0;
        }
    }
    if (j > 0) {
        this.dMultiply(Math.pow(b, j));
        this.dAddOffset(w, 0);
    }
    if (mi) BigInteger.ZERO.subTo(this, this);
}

//(protected) alternate constructor
function bnpFromNumber(a, b) {
    if ("number" == typeof b) {
        // new BigInteger(int,int,RNG)
        if (a < 2) this.fromInt(1);
        else {
            this.fromNumber(a);
            if (!this.testBit(a - 1))	// force MSB set
                this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
            if (this.isEven()) this.dAddOffset(1, 0); // force odd
            while (!this.isProbablePrime(b)) {
                this.dAddOffset(2, 0);
                if (this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
            }
        }
    } else {
        // new BigInteger(int,RNG)
        var x = crypto.randomBytes((a >> 3) + 1);
        var t = a & 7;

        if (t > 0)
            x[0] &= ((1 << t) - 1);
        else
            x[0] = 0;

        this.fromByteArray(x);
    }
}

//(public) convert to bigendian byte array
function bnToByteArray() {
    var i = this.t, r = new Array();
    r[0] = this.s;
    var p = this.DB - (i * this.DB) % 8, d, k = 0;
    if (i-- > 0) {
        if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p)
            r[k++] = d | (this.s << (this.DB - p));
        while (i >= 0) {
            if (p < 8) {
                d = (this[i] & ((1 << p) - 1)) << (8 - p);
                d |= this[--i] >> (p += this.DB - 8);
            }
            else {
                d = (this[i] >> (p -= 8)) & 0xff;
                if (p <= 0) {
                    p += this.DB;
                    --i;
                }
            }
            if ((d & 0x80) != 0) d |= -256;
            if (k === 0 && (this.s & 0x80) != (d & 0x80)) ++k;
            if (k > 0 || d != this.s) r[k++] = d;
        }
    }
    return r;
}

/**
 * return Buffer object
 * @param trim {boolean} slice buffer if first element == 0
 * @returns {Buffer}
 */
function bnToBuffer(trimOrSize) {
    var res = new Buffer(this.toByteArray());
    if (trimOrSize === true && res[0] === 0) {
        res = res.slice(1);
    } else if (typeof trimOrSize == 'number') {
        if (res.length > trimOrSize) {
            for (var i = 0; i < res.length - trimOrSize; i++) {
                if (res[i] !== 0) {
                    return null;
                }
            }
            return res.slice(res.length - trimOrSize);
        } else if (res.length < trimOrSize) {
            var padded = new Buffer(trimOrSize);
            padded.fill(0, 0, trimOrSize - res.length);
            res.copy(padded, trimOrSize - res.length);
            return padded;
        }
    }
    return res;
}

function bnEquals(a) {
    return (this.compareTo(a) == 0);
}
function bnMin(a) {
    return (this.compareTo(a) < 0) ? this : a;
}
function bnMax(a) {
    return (this.compareTo(a) > 0) ? this : a;
}

//(protected) r = this op a (bitwise)
function bnpBitwiseTo(a, op, r) {
    var i, f, m = Math.min(a.t, this.t);
    for (i = 0; i < m; ++i) r[i] = op(this[i], a[i]);
    if (a.t < this.t) {
        f = a.s & this.DM;
        for (i = m; i < this.t; ++i) r[i] = op(this[i], f);
        r.t = this.t;
    }
    else {
        f = this.s & this.DM;
        for (i = m; i < a.t; ++i) r[i] = op(f, a[i]);
        r.t = a.t;
    }
    r.s = op(this.s, a.s);
    r.clamp();
}

//(public) this & a
function op_and(x, y) {
    return x & y;
}
function bnAnd(a) {
    var r = nbi();
    this.bitwiseTo(a, op_and, r);
    return r;
}

//(public) this | a
function op_or(x, y) {
    return x | y;
}
function bnOr(a) {
    var r = nbi();
    this.bitwiseTo(a, op_or, r);
    return r;
}

//(public) this ^ a
function op_xor(x, y) {
    return x ^ y;
}
function bnXor(a) {
    var r = nbi();
    this.bitwiseTo(a, op_xor, r);
    return r;
}

//(public) this & ~a
function op_andnot(x, y) {
    return x & ~y;
}
function bnAndNot(a) {
    var r = nbi();
    this.bitwiseTo(a, op_andnot, r);
    return r;
}

//(public) ~this
function bnNot() {
    var r = nbi();
    for (var i = 0; i < this.t; ++i) r[i] = this.DM & ~this[i];
    r.t = this.t;
    r.s = ~this.s;
    return r;
}

//(public) this << n
function bnShiftLeft(n) {
    var r = nbi();
    if (n < 0) this.rShiftTo(-n, r); else this.lShiftTo(n, r);
    return r;
}

//(public) this >> n
function bnShiftRight(n) {
    var r = nbi();
    if (n < 0) this.lShiftTo(-n, r); else this.rShiftTo(n, r);
    return r;
}

//return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
    if (x === 0) return -1;
    var r = 0;
    if ((x & 0xffff) === 0) {
        x >>= 16;
        r += 16;
    }
    if ((x & 0xff) === 0) {
        x >>= 8;
        r += 8;
    }
    if ((x & 0xf) === 0) {
        x >>= 4;
        r += 4;
    }
    if ((x & 3) === 0) {
        x >>= 2;
        r += 2;
    }
    if ((x & 1) === 0) ++r;
    return r;
}

//(public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
    for (var i = 0; i < this.t; ++i)
        if (this[i] != 0) return i * this.DB + lbit(this[i]);
    if (this.s < 0) return this.t * this.DB;
    return -1;
}

//return number of 1 bits in x
function cbit(x) {
    var r = 0;
    while (x != 0) {
        x &= x - 1;
        ++r;
    }
    return r;
}

//(public) return number of set bits
function bnBitCount() {
    var r = 0, x = this.s & this.DM;
    for (var i = 0; i < this.t; ++i) r += cbit(this[i] ^ x);
    return r;
}

//(public) true iff nth bit is set
function bnTestBit(n) {
    var j = Math.floor(n / this.DB);
    if (j >= this.t) return (this.s != 0);
    return ((this[j] & (1 << (n % this.DB))) != 0);
}

//(protected) this op (1<<n)
function bnpChangeBit(n, op) {
    var r = BigInteger.ONE.shiftLeft(n);
    this.bitwiseTo(r, op, r);
    return r;
}

//(public) this | (1<<n)
function bnSetBit(n) {
    return this.changeBit(n, op_or);
}

//(public) this & ~(1<<n)
function bnClearBit(n) {
    return this.changeBit(n, op_andnot);
}

//(public) this ^ (1<<n)
function bnFlipBit(n) {
    return this.changeBit(n, op_xor);
}

//(protected) r = this + a
function bnpAddTo(a, r) {
    var i = 0, c = 0, m = Math.min(a.t, this.t);
    while (i < m) {
        c += this[i] + a[i];
        r[i++] = c & this.DM;
        c >>= this.DB;
    }
    if (a.t < this.t) {
        c += a.s;
        while (i < this.t) {
            c += this[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += this.s;
    }
    else {
        c += this.s;
        while (i < a.t) {
            c += a[i];
            r[i++] = c & this.DM;
            c >>= this.DB;
        }
        c += a.s;
    }
    r.s = (c < 0) ? -1 : 0;
    if (c > 0) r[i++] = c;
    else if (c < -1) r[i++] = this.DV + c;
    r.t = i;
    r.clamp();
}

//(public) this + a
function bnAdd(a) {
    var r = nbi();
    this.addTo(a, r);
    return r;
}

//(public) this - a
function bnSubtract(a) {
    var r = nbi();
    this.subTo(a, r);
    return r;
}

//(public) this * a
function bnMultiply(a) {
    var r = nbi();
    this.multiplyTo(a, r);
    return r;
}

// (public) this^2
function bnSquare() {
    var r = nbi();
    this.squareTo(r);
    return r;
}

//(public) this / a
function bnDivide(a) {
    var r = nbi();
    this.divRemTo(a, r, null);
    return r;
}

//(public) this % a
function bnRemainder(a) {
    var r = nbi();
    this.divRemTo(a, null, r);
    return r;
}

//(public) [this/a,this%a]
function bnDivideAndRemainder(a) {
    var q = nbi(), r = nbi();
    this.divRemTo(a, q, r);
    return new Array(q, r);
}

//(protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
    this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
}

//(protected) this += n << w words, this >= 0
function bnpDAddOffset(n, w) {
    if (n === 0) return;
    while (this.t <= w) this[this.t++] = 0;
    this[w] += n;
    while (this[w] >= this.DV) {
        this[w] -= this.DV;
        if (++w >= this.t) this[this.t++] = 0;
        ++this[w];
    }
}

//A "null" reducer
function NullExp() {
}
function nNop(x) {
    return x;
}
function nMulTo(x, y, r) {
    x.multiplyTo(y, r);
}
function nSqrTo(x, r) {
    x.squareTo(r);
}

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

//(public) this^e
function bnPow(e) {
    return this.exp(e, new NullExp());
}

//(protected) r = lower n words of "this * a", a.t <= n
//"this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a, n, r) {
    var i = Math.min(this.t + a.t, n);
    r.s = 0; // assumes a,this >= 0
    r.t = i;
    while (i > 0) r[--i] = 0;
    var j;
    for (j = r.t - this.t; i < j; ++i) r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
    for (j = Math.min(a.t, n); i < j; ++i) this.am(0, a[i], r, i, 0, n - i);
    r.clamp();
}

//(protected) r = "this * a" without lower n words, n > 0
//"this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a, n, r) {
    --n;
    var i = r.t = this.t + a.t - n;
    r.s = 0; // assumes a,this >= 0
    while (--i >= 0) r[i] = 0;
    for (i = Math.max(n - this.t, 0); i < a.t; ++i)
        r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
    r.clamp();
    r.drShiftTo(1, r);
}

//Barrett modular reduction
function Barrett(m) {
// setup Barrett
    this.r2 = nbi();
    this.q3 = nbi();
    BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
    this.mu = this.r2.divide(m);
    this.m = m;
}

function barrettConvert(x) {
    if (x.s < 0 || x.t > 2 * this.m.t) return x.mod(this.m);
    else if (x.compareTo(this.m) < 0) return x;
    else {
        var r = nbi();
        x.copyTo(r);
        this.reduce(r);
        return r;
    }
}

function barrettRevert(x) {
    return x;
}

//x = x mod m (HAC 14.42)
function barrettReduce(x) {
    x.drShiftTo(this.m.t - 1, this.r2);
    if (x.t > this.m.t + 1) {
        x.t = this.m.t + 1;
        x.clamp();
    }
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
    while (x.compareTo(this.r2) < 0) x.dAddOffset(1, this.m.t + 1);
    x.subTo(this.r2, x);
    while (x.compareTo(this.m) >= 0) x.subTo(this.m, x);
}

//r = x^2 mod m; x != r
function barrettSqrTo(x, r) {
    x.squareTo(r);
    this.reduce(r);
}

//r = x*y mod m; x,y != r
function barrettMulTo(x, y, r) {
    x.multiplyTo(y, r);
    this.reduce(r);
}

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

//(public) this^e % m (HAC 14.85)
function bnModPow(e, m) {
    var i = e.bitLength(), k, r = nbv(1), z;
    if (i <= 0) return r;
    else if (i < 18) k = 1;
    else if (i < 48) k = 3;
    else if (i < 144) k = 4;
    else if (i < 768) k = 5;
    else k = 6;
    if (i < 8)
        z = new Classic(m);
    else if (m.isEven())
        z = new Barrett(m);
    else
        z = new Montgomery(m);

// precomputation
    var g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
    g[1] = z.convert(this);
    if (k > 1) {
        var g2 = nbi();
        z.sqrTo(g[1], g2);
        while (n <= km) {
            g[n] = nbi();
            z.mulTo(g2, g[n - 2], g[n]);
            n += 2;
        }
    }

    var j = e.t - 1, w, is1 = true, r2 = nbi(), t;
    i = nbits(e[j]) - 1;
    while (j >= 0) {
        if (i >= k1) w = (e[j] >> (i - k1)) & km;
        else {
            w = (e[j] & ((1 << (i + 1)) - 1)) << (k1 - i);
            if (j > 0) w |= e[j - 1] >> (this.DB + i - k1);
        }

        n = k;
        while ((w & 1) === 0) {
            w >>= 1;
            --n;
        }
        if ((i -= n) < 0) {
            i += this.DB;
            --j;
        }
        if (is1) {	// ret == 1, don't bother squaring or multiplying it
            g[w].copyTo(r);
            is1 = false;
        }
        else {
            while (n > 1) {
                z.sqrTo(r, r2);
                z.sqrTo(r2, r);
                n -= 2;
            }
            if (n > 0) z.sqrTo(r, r2); else {
                t = r;
                r = r2;
                r2 = t;
            }
            z.mulTo(r2, g[w], r);
        }

        while (j >= 0 && (e[j] & (1 << i)) === 0) {
            z.sqrTo(r, r2);
            t = r;
            r = r2;
            r2 = t;
            if (--i < 0) {
                i = this.DB - 1;
                --j;
            }
        }
    }
    return z.revert(r);
}

//(public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
    var x = (this.s < 0) ? this.negate() : this.clone();
    var y = (a.s < 0) ? a.negate() : a.clone();
    if (x.compareTo(y) < 0) {
        var t = x;
        x = y;
        y = t;
    }
    var i = x.getLowestSetBit(), g = y.getLowestSetBit();
    if (g < 0) return x;
    if (i < g) g = i;
    if (g > 0) {
        x.rShiftTo(g, x);
        y.rShiftTo(g, y);
    }
    while (x.signum() > 0) {
        if ((i = x.getLowestSetBit()) > 0) x.rShiftTo(i, x);
        if ((i = y.getLowestSetBit()) > 0) y.rShiftTo(i, y);
        if (x.compareTo(y) >= 0) {
            x.subTo(y, x);
            x.rShiftTo(1, x);
        }
        else {
            y.subTo(x, y);
            y.rShiftTo(1, y);
        }
    }
    if (g > 0) y.lShiftTo(g, y);
    return y;
}

//(protected) this % n, n < 2^26
function bnpModInt(n) {
    if (n <= 0) return 0;
    var d = this.DV % n, r = (this.s < 0) ? n - 1 : 0;
    if (this.t > 0)
        if (d === 0) r = this[0] % n;
        else for (var i = this.t - 1; i >= 0; --i) r = (d * r + this[i]) % n;
    return r;
}

//(public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
    var ac = m.isEven();
    if ((this.isEven() && ac) || m.signum() === 0) return BigInteger.ZERO;
    var u = m.clone(), v = this.clone();
    var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
    while (u.signum() != 0) {
        while (u.isEven()) {
            u.rShiftTo(1, u);
            if (ac) {
                if (!a.isEven() || !b.isEven()) {
                    a.addTo(this, a);
                    b.subTo(m, b);
                }
                a.rShiftTo(1, a);
            }
            else if (!b.isEven()) b.subTo(m, b);
            b.rShiftTo(1, b);
        }
        while (v.isEven()) {
            v.rShiftTo(1, v);
            if (ac) {
                if (!c.isEven() || !d.isEven()) {
                    c.addTo(this, c);
                    d.subTo(m, d);
                }
                c.rShiftTo(1, c);
            }
            else if (!d.isEven()) d.subTo(m, d);
            d.rShiftTo(1, d);
        }
        if (u.compareTo(v) >= 0) {
            u.subTo(v, u);
            if (ac) a.subTo(c, a);
            b.subTo(d, b);
        }
        else {
            v.subTo(u, v);
            if (ac) c.subTo(a, c);
            d.subTo(b, d);
        }
    }
    if (v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
    if (d.compareTo(m) >= 0) return d.subtract(m);
    if (d.signum() < 0) d.addTo(m, d); else return d;
    if (d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997];
var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];

//(public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
    var i, x = this.abs();
    if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
        for (i = 0; i < lowprimes.length; ++i)
            if (x[0] == lowprimes[i]) return true;
        return false;
    }
    if (x.isEven()) return false;
    i = 1;
    while (i < lowprimes.length) {
        var m = lowprimes[i], j = i + 1;
        while (j < lowprimes.length && m < lplim) m *= lowprimes[j++];
        m = x.modInt(m);
        while (i < j) if (m % lowprimes[i++] === 0) return false;
    }
    return x.millerRabin(t);
}

//(protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
    var n1 = this.subtract(BigInteger.ONE);
    var k = n1.getLowestSetBit();
    if (k <= 0) return false;
    var r = n1.shiftRight(k);
    t = (t + 1) >> 1;
    if (t > lowprimes.length) t = lowprimes.length;
    var a = nbi();
    for (var i = 0; i < t; ++i) {
        //Pick bases at random, instead of starting at 2
        a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
        var y = a.modPow(r, this);
        if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
            var j = 1;
            while (j++ < k && y.compareTo(n1) != 0) {
                y = y.modPowInt(2, this);
                if (y.compareTo(BigInteger.ONE) === 0) return false;
            }
            if (y.compareTo(n1) != 0) return false;
        }
    }
    return true;
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.fromByteArray = bnpFromByteArray;
BigInteger.prototype.fromBuffer = bnpFromBuffer;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;


// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.toBuffer = bnToBuffer;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.eq = bnEqual;
BigInteger.prototype.gt = bnGreater;
BigInteger.prototype.gte = bnGreaterOrEqual;
BigInteger.prototype.lt = bnLesser;
BigInteger.prototype.lte = bnLesserOrEqual;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
BigInteger.int2char = int2char;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

/*
 * SRP Group Parameters
 * http://tools.ietf.org/html/rfc5054#appendix-A
 *
 * The 1024-, 1536-, and 2048-bit groups are taken from software
 * developed by Tom Wu and Eugene Jhong for the Stanford SRP
 * distribution, and subsequently proven to be prime.  The larger primes
 * are taken from [MODP], but generators have been calculated that are
 * primitive roots of N, unlike the generators in [MODP].
 *
 * The 1024-bit and 1536-bit groups MUST be supported.
 */

// since these are meant to be used internally, all values are numbers. If
// you want to add parameter sets, you'll need to convert them to bignums.

function hex(s) {
    return new BigInteger(s.split(/\s/).join(''), 16);
}

var params = {

  1024: {
    N_length_bits: 1024,
    N: hex(' EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C'
           +'9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4'
           +'8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29'
           +'7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A'
           +'FD5138FE 8376435B 9FC61D2F C0EB06E3'),
    g: hex('02'),
    hash: 'sha1'},

  1536: {
    N_length_bits: 1536,
    N: hex(' 9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961'
           +'4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843'
           +'80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B'
           +'E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5'
           +'6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A'
           +'F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E'
           +'8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB'),
    g: hex('02'),
    hash: 'sha1'},

  2048: {
    N_length_bits: 2048,
    N: hex(' AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294'
           +'3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D'
           +'CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB'
           +'D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74'
           +'7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A'
           +'436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D'
           +'5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73'
           +'03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6'
           +'94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F'
           +'9E4AFF73'),
    g: hex('02'),
    hash: 'sha256'},

  3072: {
    N_length_bits: 3072,
    N: hex(' FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08'
           +'8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B'
           +'302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9'
           +'A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6'
           +'49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8'
           +'FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D'
           +'670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C'
           +'180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718'
           +'3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D'
           +'04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D'
           +'B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226'
           +'1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C'
           +'BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC'
           +'E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF'),
    g: hex('05'),
    hash: 'sha256'},

  4096: {
    N_length_bits: 4096,
    N: hex(' FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08'
           +'8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B'
           +'302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9'
           +'A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6'
           +'49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8'
           +'FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D'
           +'670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C'
           +'180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718'
           +'3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D'
           +'04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D'
           +'B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226'
           +'1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C'
           +'BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC'
           +'E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26'
           +'99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB'
           +'04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2'
           +'233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127'
           +'D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199'
           +'FFFFFFFF FFFFFFFF'),
    g: hex('05'),
    hash: 'sha256'},

  6244: {
    N_length_bits: 6244,
    N: hex(' FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08'
           +'8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B'
           +'302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9'
           +'A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6'
           +'49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8'
           +'FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D'
           +'670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C'
           +'180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718'
           +'3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D'
           +'04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D'
           +'B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226'
           +'1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C'
           +'BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC'
           +'E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26'
           +'99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB'
           +'04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2'
           +'233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127'
           +'D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492'
           +'36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406'
           +'AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918'
           +'DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151'
           +'2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03'
           +'F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F'
           +'BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA'
           +'CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B'
           +'B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632'
           +'387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E'
           +'6DCC4024 FFFFFFFF FFFFFFFF'),
    g: hex('05'),
    hash: 'sha256'},

  8192: {
    N_length_bits: 8192,
    N: hex(' FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08'
           +'8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B'
           +'302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9'
           +'A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6'
           +'49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8'
           +'FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D'
           +'670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C'
           +'180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718'
           +'3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D'
           +'04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D'
           +'B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226'
           +'1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C'
           +'BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC'
           +'E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26'
           +'99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB'
           +'04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2'
           +'233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127'
           +'D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492'
           +'36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406'
           +'AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918'
           +'DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151'
           +'2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03'
           +'F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F'
           +'BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA'
           +'CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B'
           +'B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632'
           +'387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E'
           +'6DBE1159 74A3926F 12FEE5E4 38777CB6 A932DF8C D8BEC4D0 73B931BA'
           +'3BC832B6 8D9DD300 741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C'
           +'5AE4F568 3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9'
           +'22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B 4BCBC886'
           +'2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A 062B3CF5 B3A278A6'
           +'6D2A13F8 3F44F82D DF310EE0 74AB6A36 4597E899 A0255DC1 64F31CC5'
           +'0846851D F9AB4819 5DED7EA1 B1D510BD 7EE74D73 FAF36BC3 1ECFA268'
           +'359046F4 EB879F92 4009438B 481C6CD7 889A002E D5EE382B C9190DA6'
           +'FC026E47 9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71'
           +'60C980DD 98EDD3DF FFFFFFFF FFFFFFFF'),
    g: hex('13'),
    hash: 'sha256'},
    scrypt_8192: {
      N_length_bits: 8192,
      N: hex(' FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08'
             +'8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B'
             +'302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9'
             +'A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6'
             +'49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8'
             +'FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D'
             +'670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C'
             +'180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718'
             +'3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D'
             +'04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D'
             +'B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226'
             +'1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C'
             +'BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC'
             +'E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26'
             +'99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB'
             +'04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2'
             +'233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127'
             +'D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492'
             +'36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406'
             +'AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918'
             +'DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151'
             +'2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03'
             +'F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F'
             +'BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA'
             +'CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B'
             +'B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632'
             +'387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E'
             +'6DBE1159 74A3926F 12FEE5E4 38777CB6 A932DF8C D8BEC4D0 73B931BA'
             +'3BC832B6 8D9DD300 741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C'
             +'5AE4F568 3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9'
             +'22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B 4BCBC886'
             +'2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A 062B3CF5 B3A278A6'
             +'6D2A13F8 3F44F82D DF310EE0 74AB6A36 4597E899 A0255DC1 64F31CC5'
             +'0846851D F9AB4819 5DED7EA1 B1D510BD 7EE74D73 FAF36BC3 1ECFA268'
             +'359046F4 EB879F92 4009438B 481C6CD7 889A002E D5EE382B C9190DA6'
             +'FC026E47 9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71'
             +'60C980DD 98EDD3DF FFFFFFFF FFFFFFFF'),
      g: hex('13'),
      hash: 'scrypt'}
};

var zero = new BigInteger(0);

function assert_(val, msg) {
  if (!val)
    throw new Error(msg||"assertion");
}

/*
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * params:
 *         n (buffer)       Number to pad
 *         len (int)        length of the resulting Buffer
 *
 * returns: buffer
 */
function padTo(n, len) {
  assertIsBuffer(n, "n");
  var padding = len - n.length;
  assert_(padding > -1, "Negative padding.  Very uncomfortable.");
  var result = new Buffer(len);
  result.fill(0, 0, padding);
  n.copy(result, padding);
  assert_(result.length === len, 'AssertionError');
  return result;
}

function padToN(number, params$$1) {
  assertIsBigInteger(number);
  var n = number.toString(16).length % 2 != 0 ? "0" + number.toString(16) : number.toString(16);
  return padTo(new Buffer(n, 'hex'), params$$1.N_length_bits / 8);
}

function assertIsBuffer(arg, argname) {
  argname = argname || "arg";
  assert_(Buffer.isBuffer(arg), "Type error: "+argname+" must be a buffer");
}

function assertIsNBuffer(arg, params$$1, argname) {
  argname = argname || "arg";
  assert_(Buffer.isBuffer(arg), "Type error: "+argname+" must be a buffer");
  if (arg.length != params$$1.N_length_bits/8)
    assert_(false, argname+" was "+arg.length+", expected "+(params$$1.N_length_bits/8));
}

function assertIsBigInteger(arg) {
  assert_(arg.constructor.name === 'BigInteger', "Type error: " + arg.argname + " must be a BigInteger");
}

/*
 * compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 *
 * params:
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: x (bignum)      user secret
 */
function getx(params$$1, salt, I, P) {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");
  var hashIP = crypto.createHash(params$$1.hash)
    .update(Buffer.concat([I, new Buffer(':'), P]))
    .digest();
  var hashX = crypto.createHash(params$$1.hash)
    .update(salt)
    .update(hashIP)
    .digest();
  return(new BigInteger(hashX));
}

/*
 * The verifier is calculated as described in Section 3 of [SRP-RFC].
 * We give the algorithm here for convenience.
 *
 * The verifier (v) is computed based on the salt (s), user name (I),
 * password (P), and group parameters (N, g).
 *
 *         x = H(s | H(I | ":" | P))
 *         v = g^x % N
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt
 *         I (buffer)       user identity
 *         P (buffer)       user password
 *
 * returns: buffer
 */
function computeVerifier(params$$1, salt, I, P) {
  assertIsBuffer(salt, "salt (salt)");
  assertIsBuffer(I, "identity (I)");
  assertIsBuffer(P, "password (P)");
  var v_num = params$$1.g.modPow(getx(params$$1, salt, I, P), params$$1.N);
  return padToN(v_num, params$$1);
}

/*
 * calculate the SRP-6 multiplier
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *
 * returns: bignum
 */
function getk(params$$1) {
  var k_buf = crypto
    .createHash(params$$1.hash)
    .update(padToN(params$$1.N, params$$1))
    .update(padToN(params$$1.g, params$$1))
    .digest();
  return(new BigInteger(k_buf));
}

/*
 * Generate a random key
 *
 * params:
 *         bytes (int)      length of key (default=32)
 *         callback (func)  function to call with err,key
 *
 * returns: nothing, but runs callback with a Buffer
 */
function genKey(bytes, callback) {
  // bytes is optional
  if (arguments.length < 2) {
    callback = bytes;
    bytes = 32;
  }
  if (typeof callback !== 'function') {
    throw("Callback required");
  }
  crypto.randomBytes(bytes, function(err, buf) {
    if (err) return callback (err);
    return callback(null, buf);
  });
}

/*
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = H(N | PAD(g)).
 *
 * Note: as the tests imply, the entire expression is mod N.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored)
 *         b (bignum)       server secret exponent
 *
 * returns: B (buffer)      the server public message
 */
function getB(params$$1, k, v, b) {
  assertIsBigInteger(v);
  assertIsBigInteger(k);
  assertIsBigInteger(b);
  var N = params$$1.N;
  var r = k.multiply(v).add(params$$1.g.modPow(b, N)).mod(N);
  return padToN(r, params$$1);
}

/*
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         a (bignum)       client secret exponent
 *
 * returns A (bignum)       the client public message
 */
function getA(params$$1, a_num) {
  assertIsBigInteger(a_num);
  if (Math.ceil(a_num.toString(16).length / 2) < 32) {
    console.warn("getA: client key length", a_num.bitLength(), "is less than the recommended 256 bits");
  }
  return padToN(params$$1.g.modPow(a_num, params$$1.N), params$$1);
}

/*
 * getu() hashes the two public messages together, to obtain a scrambling
 * parameter "u" which cannot be predicted by either party ahead of time.
 * This makes it safe to use the message ordering defined in the SRP-6a
 * paper, in which the server reveals their "B" value before the client
 * commits to their "A" value.
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         A (Buffer)       client ephemeral public key
 *         B (Buffer)       server ephemeral public key
 *
 * returns: u (bignum)      shared scrambling parameter
 */
function getu(params$$1, A, B) {
  assertIsNBuffer(A, params$$1, "A");
  assertIsNBuffer(B, params$$1, "B");
  var u_buf = crypto.createHash(params$$1.hash)
    .update(A).update(B)
    .digest();
  return(new BigInteger(u_buf));
}

/*
 * The TLS premaster secret as calculated by the client
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         salt (buffer)    salt (read from server)
 *         I (buffer)       user identity (read from user)
 *         P (buffer)       user password (read from user)
 *         a (bignum)       ephemeral private key (generated for session)
 *         B (bignum)       server ephemeral public key (read from server)
 *
 * returns: buffer
 */

function client_getS(params$$1, k_num, x_num, a_num, B_num, u_num) {
  assertIsBigInteger(k_num);
  assertIsBigInteger(x_num);
  assertIsBigInteger(a_num);
  assertIsBigInteger(B_num);
  assertIsBigInteger(u_num);
  if (zero.gte(B_num) || params$$1.N.lte(B_num))
    throw new Error("invalid server-supplied 'B', must be 1..N-1");
  var S_num = B_num.subtract(k_num.multiply(params$$1.g.modPow(x_num, params$$1.N))).modPow(a_num.add(u_num.multiply(x_num)), params$$1.N).mod(params$$1.N);

  return padToN(S_num, params$$1);
}

/*
 * The TLS premastersecret as calculated by the server
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         v (bignum)       verifier (stored on server)
 *         A (bignum)       ephemeral client public key (read from client)
 *         b (bignum)       server ephemeral private key (generated for session)
 *
 * returns: bignum
 */

function server_getS(params$$1, v_num, A_num, b_num, u_num) {
  assertIsBigInteger(v_num);
  assertIsBigInteger(A_num);
  assertIsBigInteger(b_num);
  assertIsBigInteger(u_num);

  if (zero.gte(A_num) || params$$1.N.lte(A_num))
    throw new Error("invalid client-supplied 'A', must be 1..N-1");
  var S_num = A_num.multiply(v_num.modPow(u_num, params$$1.N)).modPow(b_num, params$$1.N).mod(params$$1.N);
  return padToN(S_num, params$$1);
}

/*
 * Compute the shared session key K from S
 *
 * params:
 *         params (obj)     group parameters, with .N, .g, .hash
 *         S (buffer)       Session key
 *
 * returns: buffer
 */
function getK(params$$1, S_buf) {
  assertIsNBuffer(S_buf, params$$1, "S");
  return crypto.createHash(params$$1.hash)
      .update(S_buf)
      .digest();
}

function getM1(params$$1, A_buf, B_buf, S_buf) {
  assertIsNBuffer(A_buf, params$$1, "A");
  assertIsNBuffer(B_buf, params$$1, "B");
  assertIsNBuffer(S_buf, params$$1, "S");
  return crypto.createHash(params$$1.hash)
    .update(A_buf).update(B_buf).update(S_buf)
    .digest();
}

function getM2(params$$1, A_buf, M_buf, K_buf) {
  assertIsNBuffer(A_buf, params$$1, "A");
  assertIsBuffer(M_buf, "M");
  assertIsBuffer(K_buf, "K");
  return crypto.createHash(params$$1.hash)
    .update(A_buf).update(M_buf).update(K_buf)
    .digest();
}

function equal(buf1, buf2) {
  // constant-time comparison. A drop in the ocean compared to our
  // non-constant-time modexp operations, but still good practice.
  var mismatch = buf1.length - buf2.length;
  if (mismatch) {
    return false;
  }
  for (var i = 0; i < buf1.length; i++) {
    mismatch |= buf1[i] ^ buf2[i];
  }
  return mismatch === 0;
}

function Client(params$$1, salt_buf, identity_buf, password_buf, secret1_buf) {
  if (!(this instanceof Client)) {
    return new Client(params$$1, salt_buf, identity_buf, password_buf, secret1_buf);
  }
  assertIsBuffer(salt_buf, "salt (salt)");
  assertIsBuffer(identity_buf, "identity (I)");
  assertIsBuffer(password_buf, "password (P)");
  assertIsBuffer(secret1_buf, "secret1");
  this._private = { params: params$$1,
                    k_num: getk(params$$1),
                    x_num: getx(params$$1, salt_buf, identity_buf, password_buf),
                    a_num: new BigInteger(secret1_buf) };
  this._private.A_buf = getA(params$$1, this._private.a_num);
}

Client.prototype = {
  computeA: function computeA() {
    return this._private.A_buf;
  },
  setB: function setB(B_buf) {
    var p = this._private;
    var B_num = new BigInteger(B_buf);
    var u_num = getu(p.params, p.A_buf, B_buf);
    var S_buf_x = client_getS(p.params, p.k_num, p.x_num, p.a_num, B_num, u_num);
    p.K_buf = getK(p.params, S_buf_x);
    p.M1_buf = getM1(p.params, p.A_buf, B_buf, S_buf_x);
    p.M2_buf = getM2(p.params, p.A_buf, p.M1_buf, p.K_buf);
    p.u_num = u_num; // only for tests
    p.S_buf = S_buf_x; // only for tests
  },
  computeM1: function computeM1() {
    if (this._private.M1_buf === undefined)
      throw new Error("incomplete protocol");
    return this._private.M1_buf;
  },
  checkM2: function checkM2(serverM2_buf) {
    if (!equal(this._private.M2_buf, serverM2_buf))
      throw new Error("server is not authentic");
  },
  computeK: function computeK() {
    if (this._private.K_buf === undefined)
      throw new Error("incomplete protocol");
    return this._private.K_buf;
  }
};

function Server(params$$1, verifier_buf, secret2_buf) {
  if (!(this instanceof Server))  {
    return new Server(params$$1, verifier_buf, secret2_buf);
  }
  assertIsBuffer(verifier_buf, "verifier");
  assertIsBuffer(secret2_buf, "secret2");
  this._private = { params: params$$1,
                    k_num: getk(params$$1),
                    b_num: new BigInteger(secret2_buf),
                    v_num: new BigInteger(verifier_buf) };

  this._private.B_buf = getB(params$$1, this._private.k_num,
                             this._private.v_num, this._private.b_num);
}

Server.prototype = {
  computeB: function computeB() {
    return this._private.B_buf;
  },
  setA: function setA(A_buf) {
    var p = this._private;
    var A_num = new BigInteger(A_buf);
    var u_num = getu(p.params, A_buf, p.B_buf);
    var S_buf = server_getS(p.params, p.v_num, A_num, p.b_num, u_num);
    p.K_buf = getK(p.params, S_buf);
    p.M1_buf = getM1(p.params, A_buf, p.B_buf, S_buf);
    p.M2_buf = getM2(p.params, A_buf, p.M1_buf, p.K_buf);
    p.u_num = u_num; // only for tests
    p.S_buf = S_buf; // only for tests
  },
  checkM1: function checkM1(clientM1_buf) {
    if (this._private.M1_buf === undefined)
      throw new Error("incomplete protocol");
    if (!equal(this._private.M1_buf, clientM1_buf))
      throw new Error("client did not use the same password");
    return this._private.M2_buf;
  },
  computeK: function computeK() {
    if (this._private.K_buf === undefined)
      throw new Error("incomplete protocol");
    return this._private.K_buf;
  }
};

var srp = {
  params, //: require('./params'),
  genKey, //: genKey,
  computeVerifier, //: computeVerifier,
  Client, //: Client,
  Server, //: Server
  BigInteger
};

return srp;

})));
