'use strict';

// requires
var api = require('../api.js');

var crypto = require('crypto');
var elliptic = require('elliptic');
var jsrsa = require('jsrsasign_SM');
var KEYUTIL = jsrsa.KEYUTIL;
var util = require('util');
var BN = require('bn.js');
var Signature = require('elliptic/lib/elliptic/ec/signature.js');

var utils = require('../utils');
var SMKey = require('./sm/key.js');

var SM2Util = require('./sm/sm2.js');
var SM3 = require('./sm/sm3.js');
var logger = utils.getLogger('crypto_sm2');

/**
 * The {@link module:api.CryptoSuite} implementation for ECDSA, and AES algorithms using software key generation.
 * This class implements a software-based key generation (as opposed to Hardware Security Module based key management)
 *
 * @class
 * @extends module:api.CryptoSuite
 */
var CryptoSuite_SM2 = class extends api.CryptoSuite {

    /**
     * constructor
     *
     * default hash algorithm sm3, keySize 256
     */
    constructor(opts) {
        logger.debug('SM2 constructor');
        super();

        this._hashAlgo = 'SM3';
        this._keySize = 256;
        this._cryptoKeyStore = null;
        this._hashFunction = SM3.hash;
        // this._hashFunctionKeyDerivation = hashPrimitives.hash_sha3_256;
        this._hashOutputSize = this._keySize / 8;

    }

    /**
     * Set the cryptoKeyStore.
     *
     * When the application needs to use a key store other than the default,
     * it should use the {@link Client} newCryptoKeyStore to create an instance and
     * use this function to set the instance on the CryptoSuite.
     *
     * @param {CryptoKeyStore} cryptoKeyStore The cryptoKeyStore.
     */
    setCryptoKeyStore(cryptoKeyStore) {
        this._cryptoKeyStore = cryptoKeyStore;
    }


    generateKey(opts) {
        var pair = SM2Util.key_obj_gen();

        if (typeof opts !== 'undefined' && typeof opts.ephemeral !== 'undefined' && opts.ephemeral === true) {
            // logger.debug('generateKey, ephemeral true, Promise resolved');
            return Promise.resolve(new SMKey(pair.prvKeyObj));
        } else {
            if (!this._cryptoKeyStore) {
                throw new Error('generateKey opts.ephemeral is false, which requires CryptoKeyStore to be set.');
            }
            // unless "opts.ephemeral" is explicitly set to "true", default to saving the key
            var key = new SMKey(pair.prvKeyObj);

            var self = this;
            return new Promise((resolve, reject) => {
                self._cryptoKeyStore._getKeyStore()
                    .then((store) => {
                        logger.debug('generateKey, store.setValue');
                        return store.putKey(key)
                            .then(() => {
                                return resolve(key);
                            }).catch((err) => {
                                reject(err);
                            });
                    });

            });
        }
    }

    /**
     * To be implemented
     */
    deriveKey(key, opts) {
        throw new Error('Not implemented yet');
    }

    importKey(raw, opts) {
        // logger.debug('importKey - start');
        var store_key = true; //default
        if (typeof opts !== 'undefined' && typeof opts.ephemeral !== 'undefined' && opts.ephemeral === true) {
            store_key = false;
        }
        if (!!store_key && !this._cryptoKeyStore) {
            throw new Error('importKey opts.ephemeral is false, which requires CryptoKeyStore to be set.');
        }

        var self = this;
        // attempt to import the raw content, assuming it's one of the following:
        // X.509v1/v3 PEM certificate (RSA/DSA/ECC)
        // PKCS#8 PEM RSA/DSA/ECC public key
        // PKCS#5 plain PEM DSA/RSA private key
        // PKCS#8 plain PEM RSA/ECDSA private key
        // TODO: add support for the following passcode-protected PEM formats
        // - PKCS#5 encrypted PEM RSA/DSA private
        // - PKCS#8 encrypted PEM RSA/ECDSA private key
        var pemString = Buffer.from(raw).toString();
        pemString = makeRealPem(pemString);
        var key = null;
        var theKey = null;
        var error = null;
        try {
            key = KEYUTIL.getKey(pemString);
        } catch (err) {
            error = new Error('Failed to parse key from PEM: ' + err);
        }

        if (key && key.type && key.type === 'SM2') {
            theKey = new SMKey(key);
            logger.debug('importKey - have the key %j', theKey);
        }
        else {
            error = new Error('Does not understand PEM contents other than SMKey private keys and certificates');
        }

        if (!store_key) {
            if (error) {
                logger.error('importKey - %s', error);
                throw error;
            }
            return theKey;
        }
        else {
            if (error) {
                logger.error('importKey - %j', error);
                return Promise.reject(error);
            }
            return new Promise((resolve, reject) => {
                return self._cryptoKeyStore._getKeyStore()
                    .then((store) => {
                        return store.putKey(theKey);
                    }).then(() => {
                        return resolve(theKey);
                    }).catch((err) => {
                        reject(err);
                    });

            });
        }
    }

    getKey(ski) {
        var self = this;
        var store;

        if (!self._cryptoKeyStore) {
            throw new Error('getKey requires CryptoKeyStore to be set.');
        }
        return new Promise((resolve, reject) => {
            self._cryptoKeyStore._getKeyStore()
                .then((st) => {
                    store = st;
                    return store.getKey(ski);
                }).then((key) => {
                if (SMKey.isInstance(key))
                    return resolve(key);
                else
                    throw  new Error('getKey failed, it is not SMKey.');
            }).catch((err) => {
                reject(err);
            });

        });
    }

    hash(msg, opts) {
        return this._hashFunction(msg);
    }

    sign(key, digest, opts) {
        if (typeof key === 'undefined' || key === null) {
            throw new Error('A valid key is required to sign');
        }

        if(!key.isPrivate()){
            throw new Error('sign must use private key');
        }

        if (typeof digest === 'undefined' || digest === null) {
            throw new Error('A valid message is required to sign');
        }
        var signature = key._key.sign(digest.toString('hex'));
        var signatureByte = {r: SM2Util.hexStr2Bytes(signature.r), s: SM2Util.hexStr2Bytes(signature.s)};
        var sig = new Signature(signatureByte);
        return sig.toDER();
    }


    verify(key, signature, digest) {
        if (typeof key === 'undefined' || key === null) {
            throw new Error('A valid key is required to verify');
        }

        if (typeof signature === 'undefined' || signature === null) {
            throw new Error('A valid signature is required to verify');
        }

        if (typeof digest === 'undefined' || digest === null) {
            throw new Error('A valid message is required to verify');
        }
        signature = SM2Util.parseDER(signature, 'hex');
        // note that the signature is generated on the hash of the message, not the message itself
        return key._key.verify(SM3.hash(digest), signature);
    }


    /**
     * To be implemented.
     */
    encrypt(key, plaintext, opts) {
        throw new Error('Not implemented yet');
    }

    /**
     * To be implemented.
     */
    decrypt(key, cipherText, opts) {
        throw new Error('Not implemented yet');
    }
};

// [Angelo De Caro] ECDSA signatures do not have unique representation and this can facilitate
// replay attacks and more. In order to have a unique representation,
// this change-set forses BCCSP to generate and accept only signatures
// with low-S.
// Bitcoin has also addressed this issue with the following BIP:
// https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
// Before merging this change-set, we need to ensure that client-sdks
// generates signatures properly in order to avoid massive rejection
// of transactions.

// map for easy lookup of the "N/2" value per elliptic curve
const halfOrdersForCurve = {
    'secp256r1': elliptic.curves['p256'].n.shrn(1),
    'secp384r1': elliptic.curves['p384'].n.shrn(1)
};

function _preventMalleability(sig, curveParams) {
    var halfOrder = halfOrdersForCurve[curveParams.name];
    if (!halfOrder) {
        throw new Error('Can not find the half order needed to calculate "s" value for immalleable signatures. Unsupported curve name: ' + curve);
    }

    // in order to guarantee 's' falls in the lower range of the order, as explained in the above link,
    // first see if 's' is larger than half of the order, if so, it needs to be specially treated
    if (sig.s.cmp(halfOrder) == 1) { // module 'bn.js', file lib/bn.js, method cmp()
        // convert from BigInteger used by jsrsasign Key objects and bn.js used by elliptic Signature objects
        var bigNum = new BN(curveParams.n.toString(16), 16);
        sig.s = bigNum.sub(sig.s);
    }

    return sig;
}

function _checkMalleability(sig, curveParams) {
    var halfOrder = halfOrdersForCurve[curveParams.name];
    if (!halfOrder) {
        throw new Error('Can not find the half order needed to calculate "s" value for immalleable signatures. Unsupported curve name: ' + curve);
    }

    // first need to unmarshall the signature bytes into the object with r and s values
    var sigObject = new Signature(sig, 'hex');
    if (!sigObject.r || !sigObject.s) {
        throw new Error('Failed to load the signature object from the bytes.');
    }

    // in order to guarantee 's' falls in the lower range of the order, as explained in the above link,
    // first see if 's' is larger than half of the order, if so, it is considered invalid in this context
    if (sigObject.s.cmp(halfOrder) == 1) { // module 'bn.js', file lib/bn.js, method cmp()
        return false;
    }

    return true;
}

// Utilitly method to make sure the start and end markers are correct
function makeRealPem(pem) {
    var result = null;
    if (typeof pem == 'string') {
        result = pem.replace(/-----BEGIN -----/, '-----BEGIN CERTIFICATE-----');
        result = result.replace(/-----END -----/, '-----END CERTIFICATE-----');
        result = result.replace(/-----([^-]+) ECDSA ([^-]+)-----([^-]*)-----([^-]+) ECDSA ([^-]+)-----/, '-----$1 EC $2-----$3-----$4 EC $5-----');
    }
    return result;
}


/*
 * Convert a PEM encoded certificate to DER format
 * @param {string) pem PEM encoded public or private key
 * @returns {string} hex Hex-encoded DER bytes
 * @throws Will throw an error if the conversation fails
 */
function pemToDER(pem) {

    //PEM format is essentially a nicely formatted base64 representation of DER encoding
    //So we need to strip "BEGIN" / "END" header/footer and string line breaks
    //Then we simply base64 decode it and convert to hex string
    var contents = pem.toString().trim().split(/\r?\n/);
    //check for BEGIN and END tags
    if (!(contents[0].match(/\-\-\-\-\-\s*BEGIN ?([^-]+)?\-\-\-\-\-/) &&
            contents[contents.length - 1].match(/\-\-\-\-\-\s*END ?([^-]+)?\-\-\-\-\-/))) {
        throw new Error('Input parameter does not appear to be PEM-encoded.');
    }
    ;
    contents.shift(); //remove BEGIN
    contents.pop(); //remove END
    //base64 decode and encode as hex string
    var hex = Buffer.from(contents.join(''), 'base64').toString('hex');
    return hex;
}


module.exports = CryptoSuite_SM2;
