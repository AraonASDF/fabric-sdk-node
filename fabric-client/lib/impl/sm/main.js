var sm2Util = require('./sm2.js')
var sm3 = require('./sm3.js')


main = function () {

    var sm2 = sm2Util.SM2.newInstance(true);
    var test1 = 'hello';
    var hash = sm3.hash(test1);
    var sig = sm2.sign(hash);
    var re = sm2.verify(hash, sig);
    console.log(sig, hash, re);

    var signr = "47f0eabe02ac91f6f23fbdb80d8131a9a470fbc586a348afc82e79178532bf14";
    var signs = "6890ca6c4c11be71ad50844555b7c70c3cca13b322d4625f42997ae7587b70c9";
    var pkx = "8db23da159e4a360024138cabb800f87806cf8f13fe7521daff5fcd39d5841f6";
    var pky = "e301ddfb14e775bb4ca9b6cd0810cf987a80299a40abf08314a73d9017abe16d";
    var sk = "198f854c9b8eefdbbfac22e663ac03370ddcf0f5e3b8cc78e20bf88b4ede2fb2";
    var hash1 = "BECBBFAAE6548B8BF0CFCAD5A27183CD1BE6093B1CCECCC303D9C61D0A645268";

    sig = {r: signr, s: signs};
    sm2 = new sm2Util.SM2();
    sm2.setPublicKeyXYHex(pkx, pky);
    sm2.setPrivateKeyHex(sk);
    var hash2 = sm3.hash('Hello World!');
    re = sm2.verify(hash2, sig);
    console.log("re = " + re);


    // var SM2Key = new sm2Util.SM2();
    // var prvKeyHex = '3f44a3990591bb2b5e077075789b5bd65cad14cd90bde8faac7b820a2a2f8418';
    // var pubKeyXHex = 'ad37b5fa2b9a198d17cccd9c39b98b83a04287ff476dea4282a168c471a4dcc4';
    // var pubKeyYHex = '96abe19c2b8ad199c4df349f66840764019f677aa62274dde57d14e652600f9d';
    //
    // var sigR = '1542bd61a406745cb4f1310ec54e93cb6fcef55d5833057de840f340d912706e';
    // var sigS = '96feea05b46c9c2488b79a0190a00da49ed765604ae2f0d241fdbc692d4316ae';
    // var sig = {r: sm2Util.hexStr2Bytes(sigR), s: sm2Util.hexStr2Bytes(sigS)};
    //
    // SM2Key.setPublicKeyHex('04' + pubKeyXHex + pubKeyYHex);
    // SM2Key.setPrivateKeyHex(prvKeyHex);
    // console.log(SM2Key.pubKeyByte.pkx,sm2Util.hexStr2Bytes(pubKeyXHex));
    // console.log(SM2Key.pubKeyByte.pky,sm2Util.hexStr2Bytes(pubKeyYHex));
    // console.log(SM2Key.pubKeyByte);
    // let result = sm2Util.verify(hash, SM2Key.pubKeyByte, sig);
    // console.log("======================"+result);
    // var sig = sm2Util.sign(hash, SM2Key.prvKeyByte);
    // console.log(sm2Util.Bytes2hexStr(sig.r), sm2Util.Bytes2hexStr(sig.s));

};
main();