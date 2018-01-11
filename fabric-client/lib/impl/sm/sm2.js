var sjcl = require('./ecc.js');
var _utils = require('elliptic/lib/elliptic/utils.js');
var Signature = require('elliptic/lib/elliptic/ec/signature.js');

//the length of signature
const SIG_LEN = 64;

class SM2 {

    constructor() {
        this.type = 'SM2';
        this.keylen = 256;
        this.prvKeyHex = null;
        this.pubKeyHex = null;
        this.isPrivate = false;
    };

    static newInstance(isPrivate) {
        if (typeof isPrivate !== 'boolean' || isPrivate == null) {
            throw new Error("SM2 key needs to know whether is private or public");
        }
        var sm2 = new SM2();
        sm2.isPrivate = isPrivate;
        var key = _keyGen();
        //private key needs to store both private and public key
        if (isPrivate) {
            sm2.setPrivateKeyHex(key.prvKey);
            sm2.setPublicKeyHex('04' + key.pubKey.pkx + key.pubKey.pky);
        } else {
            sm2.setPublicKeyHex('04' + key.pubKey.pkx + key.pubKey.pky);
        }
        return sm2;
    }

    //输入均为byte数组
    sign(hash) {
        if (typeof hash === 'undefined' || hash == null || this.prvKeyHex == null) {
            throw new Error("the input of hash for sign function can't be empty");
        }
        var ecurve = sjcl.ecc.curves.sm2_256_1;
        var e = add0x(hash);
        var k = sjcl.bn.random(ecurve.r, 0);
        var kG = ecurve.G.mult(k);
        var str = kG.toBits();
        var len = sjcl.bitArray.bitLength(str);
        var x = sjcl.bitArray.bitSlice(str, 0, len / 2);
        var x1 = sjcl.bn.fromBits(x);

        var bigE = new sjcl.bn(e);
        var bigR = (bigE.add(x1)).mod(ecurve.r);

        if (bigR.equals(new sjcl.bn("0x00")) || ecurve.r.equals(bigR.add(k))) {
            throw new Error("function sign error");
        }

        var dA = new sjcl.bn(add0x(this.prvKeyHex));
        var dA1 = (dA.add(new sjcl.bn("0x01"))).inverseMod(ecurve.r);

        var tmp1 = (bigR.mul(dA)).mod(ecurve.r);
        var tmp2 = (k.sub(tmp1)).mod(ecurve.r);
        var bigS = (dA1.mul(tmp2)).mod(ecurve.r);
        if (bigS.equals(new sjcl.bn("0x00"))) {
            throw new Error("function sign error");
        }
        var signature = _signature(bigR.toString(), bigS.toString());
        return signature;
    };

    verify(hash, sig) {
        var pubKeyHexXY = this.getPublicKeyXYHex();
        if (!pubKeyHexXY.pkx || !pubKeyHexXY.pky) {
            throw new Error("the public key has no x or y atrribute");
        }
        if (!sig.r || !sig.s) {
            throw new Error("the signature doesn't have r or s atrribute");
        }
        var ecurve = sjcl.ecc.curves.sm2_256_1;
        var e = add0x(hash);
        var r = new sjcl.bn(add0x(sig.r));
        var s = new sjcl.bn(add0x(sig.s));
        var t = (r.add(s)).mod(ecurve.r);

        var pkeyx = new sjcl.bn(add0x(pubKeyHexXY.pkx));
        var pkeyy = new sjcl.bn(add0x(pubKeyHexXY.pky));

        var pkey = new sjcl.ecc.point(ecurve, new ecurve.field(pkeyx),
            new ecurve.field(pkeyy));

        var tmp = ecurve.G.mult2(s, t, pkey);

        var str = tmp.toBits();
        var len = sjcl.bitArray.bitLength(str);
        var x = sjcl.bitArray.bitSlice(str, 0, len / 2);
        var x1 = sjcl.bn.fromBits(x);

        var R = (x1.add(new sjcl.bn(e))).mod(ecurve.r);
        if (R.equals(r))
            return true;
        else
            return false;
    };

    setPrivateKeyByte(i) {
        this.prvKeyByte = i;
        this.prvKeyHex = Bytes2hexStr(i);
        this.isPrivate = true;
    };

    setPublicKeyByte(i) {
        this.pubKeyByte = i;
        this.pubKeyHex = '04' + Bytes2hexStr(i.pkx) + Bytes2hexStr(i.pky);
    };

    setPrivateKeyHex(i) {
        this.prvKeyHex = i;
        this.prvKeyByte = hexStr2Bytes(i);
        this.isPrivate = true;
    };

    setPublicKeyHex(i) {
        this.pubKeyHex = i;
        this.pubKeyByte = this._getPublicKeyByte();
    };

    setPublicKeyXYHex(pkx, pky) {
        this.setPublicKeyHex('04' + pkx + pky);
    }

    getPublicKeyXYHex() {
        return {pkx: Bytes2hexStr(this.pubKeyByte.pkx), pky: Bytes2hexStr(this.pubKeyByte.pky)};
    };

    _getPublicKeyByte() {
        var k = this.pubKeyHex;
        if (k.substr(0, 2) !== "04") {
            throw new Error("this method supports uncompressed format(04) only");
        }
        var j = this.keylen / 4;
        if (k.length !== 2 + j * 2) {
            throw new Error("malformed public key hex length");
        }
        var i = {};
        i.pkx = hexStr2Bytes(k.substr(2, j));
        i.pky = hexStr2Bytes(k.substr(2 + j));
        return i;
    };
};
module.exports.SM2 = SM2;

module.exports.key_obj_gen = function () {
    var k = {};
    var h = SM2.newInstance(true);
    k.prvKeyObj = h;
    h = SM2.newInstance(false);
    k.pubKeyObj = h;
    return k
};

_SMKey = function (pkx, pky, sk) {
    sk = sub0x(sk);
    if (sk.length > SIG_LEN) {
        throw new Error("the length of private key is out of bounds");
    }
    return {pubKey: _pubKey(pkx, pky), prvKey: addZero(sk)};
};

_pubKey = function (pkx, pky) {
    pkx = sub0x(pkx);
    pky = sub0x(pky);
    if (pkx.length > SIG_LEN || pky.length > SIG_LEN) {
        throw new Error("the length of public key is out of bounds");
    }
    return {pkx: addZero(pkx), pky: addZero(pky)};
};

_signature = function (r, s) {
    r = sub0x(r);
    s = sub0x(s);
    if (r.length > SIG_LEN || s.length > SIG_LEN) {
        throw new Error("the length of output of sign function is out of bounds");
    }
    return {r: addZero(r), s: addZero(s)};
};

_keyGen = function () {
    var ecurve = sjcl.ecc.curves.sm2_256_1;
    var k = sjcl.bn.random(ecurve.r, 0);
    var kG = ecurve.G.mult(k);
    var str = kG.toBits();
    var len = sjcl.bitArray.bitLength(str);
    var x = sjcl.bitArray.bitSlice(str, 0, len / 2);
    var y = sjcl.bitArray.bitSlice(str, len / 2);
    var xx = sjcl.bn.fromBits(x);
    var yy = sjcl.bn.fromBits(y);
    var key = _SMKey(xx.toString(), yy.toString(), k.toString());
    return key;
};

function add0x(str) {
    return '0x' + str;
};

function sub0x(str) {
    if (typeof  str !== 'string' || str == null) {
        throw new Error("sub0x error,the form of param is wrong");
    }
    return str.substring(2);
};

function addZero(str) {
    for (var i = 0; i < SIG_LEN - str.length; i++) {
        str = '0' + str;
    }
    return str;
};

//parse DER strings of signature
module.exports.parseDER = function (data, enc) {
    data = _utils.toArray(data, enc);
    var p = new Position();
    if (data[p.place++] !== 0x30) {
        return;
    }
    var len = getLength(data, p);
    if (data[p.place++] !== 0x02) {
        return;
    }
    var rlen = getLength(data, p);
    var r = data.slice(p.place, rlen + p.place);
    p.place += rlen;
    if (data[p.place++] !== 0x02) {
        return;
    }
    var slen = getLength(data, p);
    var s = data.slice(p.place, slen + p.place);
    if (r[0] === 0 && (r[1] & 0x80)) {
        r = r.slice(1);
    }
    if (s[0] === 0 && (s[1] & 0x80)) {
        s = s.slice(1);
    }

    return {r: Bytes2hexStr(r), s: Bytes2hexStr(s)};
};

function Position() {
    this.place = 0;
}

function getLength(buf, p) {
    var initial = buf[p.place++];
    if (!(initial & 0x80)) {
        return initial;
    }
    var octetLen = initial & 0xf;
    var val = 0;
    for (var i = 0, off = p.place; i < octetLen; i++, off++) {
        val <<= 8;
        val |= buf[off];
    }
    p.place = off;
    return val;
}

function hexStr2Bytes(str) {
    if (typeof str !== 'string' || str == null) {
        throw new Error('the input must be string and not empty');
    }
    var len = str.length;
    if (len % 2 != 0) {
        throw new Error("the length of input string can only be even number");
    }
    var hexA = new Array();
    for (var pos = 0; pos < len; pos += 2) {
        var s = str.substr(pos, 2);
        var v = parseInt(s, 16);
        hexA.push(v);
    }
    return hexA;
};

function Bytes2hexStr(arr) {
    var str = "";
    for (var i = 0; i < arr.length; i++) {
        var tmp = arr[i].toString(16);
        if (tmp.length == 1) {
            tmp = "0" + tmp;
        }
        str += tmp;
    }
    return str;
}

exports.Bytes2hexStr = Bytes2hexStr;
exports.hexStr2Bytes = hexStr2Bytes;