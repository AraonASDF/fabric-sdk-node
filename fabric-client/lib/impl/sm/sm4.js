var hexcase = 0;
var chrsz = 8;
var sbox = [ 0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14,
		0xc2, 0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04,
		0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50,
		0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac,
		0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94,
		0xfa, 0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17,
		0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81,
		0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d,
		0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c,
		0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27,
		0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a,
		0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15,
		0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32,
		0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca,
		0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37,
		0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b,
		0x51, 0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c,
		0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b,
		0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97,
		0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6,
		0x84, 0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f,
		0x3e, 0xd7, 0xcb, 0x39, 0x48 ];

var FK = [ 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC ];
var CK = [ 0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85,
		0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d,
		0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5,
		0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d,
		0x848b9299, 0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25,
		0x2c333a41, 0x484f565d, 0x646b7279 ];
var key = [ 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 ];

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function rol(num, cnt) {
	return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * sm4 encrypt T
 */
T = function(data) {
	var out = sbox[data >>> 24] << 24 ^ sbox[data >> 16 & 255] << 16
			^ sbox[data >> 8 & 255] << 8 ^ sbox[data & 255];
	var T_out = out ^ rol(out, 2) ^ rol(out, 10) ^ rol(out, 18) ^ rol(out, 24);
	return T_out;
};
/*
 * sm4 key_exp
 */
T1 = function(data) {
	var out = sbox[data >>> 24] << 24 ^ sbox[data >> 16 & 255] << 16
			^ sbox[data >> 8 & 255] << 8 ^ sbox[data & 255];
	var T_out = out ^ rol(out, 13) ^ rol(out, 23);
	return T_out;
};

key_exp = function(key) {
	var keyexp = Array();
	var rk = Array();
	keyexp[0] = key[0] ^ FK[0];
	keyexp[1] = key[1] ^ FK[1];
	keyexp[2] = key[2] ^ FK[2];
	keyexp[3] = key[3] ^ FK[3];
	for (var i = 0; i < 32; i++) {
		var data = keyexp[i + 1] ^ keyexp[i + 2] ^ keyexp[i + 3] ^ CK[i];
		rk[i] = keyexp[i] ^ T1(data);
		keyexp[i + 4] = rk[i];
	}
	return rk;
};
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
	for (var i = 0; i < bin.length * 32; i += chrsz) {
		str += String.fromCharCode((bin[i >> 5] >>> (32 - chrsz - i % 32))
				& mask);
	}

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
};
crypt_one_round = function(rk, msg) {
	var re = Array();
	var msg_tmp = str2binb(msg);
	var xr = Array();
	xr[0] = msg_tmp[0];
	xr[1] = msg_tmp[1];
	xr[2] = msg_tmp[2];
	xr[3] = msg_tmp[3];
	for (var i = 0; i < 32; i++) {
		var data = xr[i + 1] ^ xr[i + 2] ^ xr[i + 3] ^ rk[i];
		xr[i + 4] = xr[i] ^ T(data);
	}
	re[0] = xr[35];
	re[1] = xr[34];
	re[2] = xr[33];
	re[3] = xr[32];
	return binb2str(re);
};
/*
 * 
 */
swap = function(rk) {
	var tmp = Array();
	for (var i = 0; i < 32; i++)
		tmp[i] = rk[31 - i];
	return tmp;
};
/*
 * 1 encrypt 0 decrypt
 */
module.exports.sm4_crypt_ecb = function(key, msg, mode) {
	var key_tmp = str2binb(key);
	var rk = key_exp(key_tmp);
	var cipher = "";
	if (mode == 0) {
		rk = swap(rk);
	}
	for (var i = 0; i < msg.length / 16; i++) {
		var tmpmsg = msg.substring(i * 16, i * 16 + 16);
		cipher += crypt_one_round(rk, tmpmsg);
	}
	return cipher;
};

yihuo = function(in1, in2) {
	var in11 = str2binb(in1);

	var out = Array();
	for (var i = 0; i < 4; i++) {
		out[i] = in11[i] ^ in2[i];
	}
	var re = binb2str(out);
	return re;
};

module.exports.sm4_crypt_cbc = function(key, msg, mode, iv) {
	var key_tmp = str2binb(key);
	var rk = key_exp(key_tmp);
	var cipher = "";
	var IV_tmp = iv;
	if (mode == 1) {
		for (var i = 0; i < msg.length / 16; i++) {
			var tmpmsg = msg.substring(i * 16, i * 16 + 16);
			var out = yihuo(tmpmsg, IV_tmp);
			out = crypt_one_round(rk, out);
			cipher += out;
			IV_tmp=str2binb(out);
		}
		return cipher;
	}
	if (mode == 0) {
		rk = swap(rk);
		for (var i = 0; i < msg.length / 16; i++) {
			var tmpmsg = msg.substring(i * 16, i * 16 + 16);
			var out = crypt_one_round(rk, tmpmsg);
			cipher += yihuo(out,IV_tmp);
			IV_tmp = str2binb(tmpmsg);
		}
		return cipher;
	}
};



main = function() {
	var key1 = "abcdefghabcdefgh";
	var msg = "abcdefghabcdegggabcdefghabcdefghabcdefghabcdegggabcdefghabcdefgh";

	var IV = [ 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 ];


	var cipher = sm4_crypt_ecb(key1, msg, 1);
	console.log("cipher:" + cipher);
	var msg1 = sm4_crypt_ecb(key1, cipher, 0);
	console.log("msg:" + msg1);

	var cipher11 = sm4_crypt_cbc(key1, msg, 1,IV);
	console.log("cipher:" + cipher11);
	var msg11 = sm4_crypt_cbc(key1, cipher11, 0,IV);
	console.log("msg:" + msg11);
};
main();