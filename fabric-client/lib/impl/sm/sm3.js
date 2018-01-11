var hexcase = 0;
var chrsz = 8;
var T = [0x79cc4519, 0x7a879d8a];
var IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc,
    0x163138aa, 0xe38dee4d, 0xb0fb0e4e];

/* fill the block */
function AlignSHA1(str) {

    var nblk = ((str.length + 8) >> 6) + 1, blks = new Array(nblk * 16);

    for (var i = 0; i < nblk * 16; i++)
        blks[i] = 0;

    if (typeof str === 'string') {
        for (i = 0; i < str.length; i++) {
            blks[i >> 2] |= str.charCodeAt(i) << (24 - (i & 3) * 8);
        }
    } else {
        for (i = 0; i < str.length; i++) {
            blks[i >> 2] |= str[i] << (24 - (i & 3) * 8);
        }
    }

    blks[i >> 2] |= 0x80 << (24 - (i & 3) * 8);

    blks[nblk * 16 - 1] = str.length * 8;

    return blks;

}

/* the funciton of FF in sm3 */
function FF(X, Y, Z, j) {
    if (j >= 0 && j <= 15) {
        return X ^ Y ^ Z;
    }
    if (j >= 16 && j <= 63) {
        return (X & Y) | (X & Z) | (Y & Z);
    }
}

/* the funciton of GG in sm3 */
function GG(X, Y, Z, j) {
    if (j >= 0 && j <= 15) {
        return X ^ Y ^ Z;
    }
    if (j >= 16 && j <= 63) {
        return (X & Y) | (~X & Z);
    }
}

function P0(x) {
    return x ^ rol(x, 9) ^ rol(x, 17);
}

function P1(y) {
    return y ^ rol(y, 15) ^ rol(y, 23);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally to
 * work around bugs in some JS interpreters.
 */
function safe_add(x, y) {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt) {
    return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert an 8-bit or 16-bit string to an array of big-endian words In 8-bit
 * function, characters >255 have their hi-byte silently ignored.
 */
function str2binb(str) {
    var bin = Array();
    var mask = (1 << chrsz) - 1;
    for (var i = 0; i < str.length * chrsz; i += chrsz)
        bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i % 32);
    return bin;
}

/*
 * Convert an array of big-endian words to a string
 */
function binb2str(bin) {
    var str = "";
    var mask = (1 << chrsz) - 1;
    for (var i = 0; i < bin.length * 32; i += chrsz)
        str += String.fromCharCode((bin[i >> 5] >>> (32 - chrsz - i % 32))
            & mask);
    return str;
}

/*
 * Convert an array of big-endian words to a hex string.
 */
function binb2hex(binarray) {
    var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
    var str = "";
    for (var i = 0; i < binarray.length * 4; i++) {
        str += hex_tab
                .charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF)
            + hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8)) & 0xF);
    }
    return str;
}

/*
 * message expand in sm3
 */
function msgEXP(binarray) {
    var re = Array();
    var re1 = Array();
    var re2 = Array();
    for (var i = 0; i < 16; i++)
        re1[i] = binarray[i];
    for (var i = 16; i < 68; i++)
        re1[i] = P1(re1[i - 16] ^ re1[i - 9] ^ rol(re1[i - 3], 15))
            ^ rol(re1[i - 13], 7) ^ re1[i - 6];
    for (var i = 0; i < 64; i++)
        re2[i] = re1[i] ^ re1[i + 4];
    for (var i = 0; i < 68; i++)
        re[i] = re1[i];
    for (var i = 0; i < 64; i++)
        re[i + 68] = re2[i];
    return re;
}

/*
 * T transform
 */
function T_tran(j) {
    if (j >= 0 && j <= 15)
        return T[0];
    if (j >= 16 && j <= 63)
        return T[1];
}

/*
 * compress function in sm3
 */
function CF(Vbinarray, MSGbinarray) {
    var W = Array();
    var W1 = Array();
    var Bbinarray = Array();
    Bbinarray = msgEXP(MSGbinarray);
    for (var i = 0; i < 68; i++)
        W[i] = Bbinarray[i];
    for (var i = 0; i < 64; i++)
        W1[i] = Bbinarray[i + 68];
    var A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;
    A = Vbinarray[0];
    B = Vbinarray[1];
    C = Vbinarray[2];
    D = Vbinarray[3];
    E = Vbinarray[4];
    F = Vbinarray[5];
    G = Vbinarray[6];
    H = Vbinarray[7];
    for (var i = 0; i < 64; i++) {
        SS1 = rol(safe_add(safe_add(rol(A, 12), E), rol(T_tran(i), i)), 7);
        SS2 = SS1 ^ rol(A, 12);
        TT1 = safe_add(safe_add(safe_add(FF(A, B, C, i), D), SS2), W1[i]);
        TT2 = safe_add(safe_add(safe_add(GG(E, F, G, i), H), SS1), W[i]);
        D = C;
        C = rol(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rol(F, 19);
        F = E;
        E = P0(TT2);
    }
    var IVtmp = Array();
    IVtmp[0] = A ^ Vbinarray[0];
    IVtmp[1] = B ^ Vbinarray[1];
    IVtmp[2] = C ^ Vbinarray[2];
    IVtmp[3] = D ^ Vbinarray[3];
    IVtmp[4] = E ^ Vbinarray[4];
    IVtmp[5] = F ^ Vbinarray[5];
    IVtmp[6] = G ^ Vbinarray[6];
    IVtmp[7] = H ^ Vbinarray[7];
    return IVtmp;
}

module.exports.hash = function (str) {
    var data = AlignSHA1(str);
    var IVtmp = Array();
    IVtmp = IV;
    for (var i = 0; i < data.length / 16; i++) {
        var msg = Array();
        for (var j = 0; j < 16; j++)
            msg[j] = data[i * 16 + j];
        IVtmp = CF(IVtmp, msg);
    }
    var data3 = binb2hex(IVtmp);
    return data3;
}

