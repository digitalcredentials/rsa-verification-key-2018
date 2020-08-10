/*!
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
import * as env from './env.js';
import * as forge from 'node-forge';
const {
  md: {sha256},
  pki: {getPublicKeyFingerprint, publicKeyFromPem},
  util: {binary: {base58, raw}}
} = forge;
import {LDVerifierKeyPair} from 'crypto-ld';

const SUITE_ID = 'RsaVerificationKey2018';

/**
 * @constant
 * @type {number}
 * @default
 */
const DEFAULT_RSA_KEY_BITS = 2048;

/**
 * @constant
 * @type {number}
 * @default
 */
const DEFAULT_RSA_EXPONENT = 0x10001;

export class RsaVerificationKey2018 extends LDVerifierKeyPair {
  /* eslint-disable max-len */
  /**
   * An implementation of
   * [RSA encryption]{@link https://simple.wikipedia.org/wiki/RSA_algorithm}
   * for
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}.
   * @example
   * > const options = {
   *    privateKeyPem: 'testPrivateKey',
   *    publicKeyPem: 'testPublicKey'
   *  };
   * > const RSAKey = new RsaVerificationKey2018(options);
   * @param {object} options - Options hashmap.
   * @param {string} options.publicKeyPem - Public Key for Signatures.
   * @param {string} options.privateKeyPem - Your Confidential key for signing.
   */
  /* eslint-enable */
  constructor(options = {}) {
    super(options);
    this.type = SUITE_ID;
    this.privateKeyPem = options.privateKeyPem;
    this.publicKeyPem = options.publicKeyPem;
    this.validateKeyParams(); // validate keyBits and exponent
    if(this.controller && this.publicKeyPem && !this.id) {
      this.id = `${this.controller}#${this.fingerprint()}`;
    }
  }

  /**
   * Generates an RSA KeyPair using the RSA Defaults.
   * @example
   * > const keyPair = await RsaVerificationKey2018.generate();
   * > keyPair
   * RsaVerificationKey2018 { ...
   * @param {object} [options={}] - See LDKeyPair
   * docstring for full list.
   *
   * @returns {Promise<RsaVerificationKey2018>} Generates an RSA key pair.
   */
  static async generate(options = {}) {
    // forge will use a native implementation in nodejs >= 10.12.0
    // and a purejs implementation in browser and nodejs < 10.12.0
    return new Promise((resolve, reject) => {
      forge.pki.rsa.generateKeyPair({
        bits: DEFAULT_RSA_KEY_BITS,
        e: DEFAULT_RSA_EXPONENT,
        workers: -1
      }, (err, keyPair) => {
        if(err) {
          return reject(err);
        }
        resolve(new RsaVerificationKey2018({
          publicKeyPem: forge.pki.publicKeyToPem(keyPair.publicKey),
          privateKeyPem: forge.pki.privateKeyToPem(keyPair.privateKey),
          ...options
        }));
      });
    });
  }

  /**
   * Creates a RSA Key Pair from an existing private key.
   * @example
   * > const options = {
   *    privateKeyPem: 'testkeypem'
   *  };
   * > const key = await RsaVerificationKey2018.from(options);
   * @param {object} options - Options hashmap.
   * @param {object} [options.publicKeyPem] - A public key.
   * @param {string} [options.privateKeyPem] - An RSA Private key.
   *
   * @returns {Promise<RsaVerificationKey2018>} An RSA Key Pair.
   */
  static async from(options) {
    return new RsaVerificationKey2018({
      publicKeyPem: options.publicKeyPem,
      privateKeyPem: options.privateKeyPem,
      ...options
    });
  }
  /**
   * Validates this key.
   * @example
   * > RsaVerificationKey2018.validateKeyParams();
   * undefined
   *
   * @returns {undefined} If it does not throw then the key is valid.
   * @throws Invalid RSA keyBit length
   * @throws Invalid RSA exponent
   */
  validateKeyParams() {
    if(this.publicKeyPem) {
      const publicKey = forge.pki.publicKeyFromPem(this.publicKeyPem);
      const keyBits = publicKey.n.bitLength();
      if(keyBits !== DEFAULT_RSA_KEY_BITS) {
        throw new Error(`Invalid RSA keyBit length ${JSON.stringify(keyBits)}` +
          ` required value is ${DEFAULT_RSA_KEY_BITS}`);
      }
      if(publicKey.e.toString(10) !== '65537') {
        throw new Error(
          `Invalid RSA exponent ${JSON.stringify(publicKey.e.toString(10))}` +
          ' required value is 65537}');
      }
    }

    if(this.privateKeyPem) {
      const privateKey = forge.pki.privateKeyFromPem(this.privateKeyPem);
      const keyBits = privateKey.n.bitLength();
      if(keyBits !== DEFAULT_RSA_KEY_BITS) {
        throw new Error(`Invalid RSA keyBit length ${JSON.stringify(keyBits)}` +
          ` required value is ${DEFAULT_RSA_KEY_BITS}`);
      }
      if(privateKey.e.toString(10) !== '65537') {
        throw new Error(
          `Invalid RSA exponent ${JSON.stringify(privateKey.e.toString(10))}` +
          ' required value is 65537}');
      }
    }
  }

  /**
   * Adds this KeyPair's publicKeyPem to a public node.
   * @param {object} key - A Node with out a publicKeyPem set.
   */
  addPublicKey({key}) {
    key.publicKeyPem = this.publicKeyPem;
    return key;
  }
  /**
   * Adds this KeyPair's privateKeyPem to a public node.
   *
   * @param {object} key - A Node with out a publicKeyPem set.
   */
  async addPrivateKey({key}) {
    key.privateKeyPem = this.privateKeyPem;
    return key;
  }

  /**
   * Generates and returns a multiformats
   * encoded RSA public key fingerprint (for use with cryptonyms, for example).
   * @example
   * > RsaVerificationKey2018.fingerprint();
   * 3423dfdsf3432sdfdsds
   *
   * @returns {string} An RSA fingerprint.
   */
  fingerprint() {
    const buffer = forge.util.createBuffer();

    // use SubjectPublicKeyInfo fingerprint
    const fingerprintBuffer = forge.pki.getPublicKeyFingerprint(
      forge.pki.publicKeyFromPem(this.publicKeyPem),
      {md: sha256.create()});
    // RSA cryptonyms are multiformats encoded values, specifically they are:
    // (multicodec RSA SPKI-based public key 0x5d + sha2-256 0x12 +
    // 32 byte value 0x20)
    buffer.putBytes(forge.util.hexToBytes('5d1220'));
    buffer.putBytes(fingerprintBuffer.bytes());

    // prefix with `z` to indicate multi-base base58btc encoding
    return `z${base58.encode(buffer)}`;
  }

  /*
   * Tests whether the fingerprint
   * was generated from a given key pair.
   * @example
   * > RsaVerificationKey2018.verifyFingerprint({fingerprint});
   * {valid: true}
   * @param {string} fingerprint - An RSA fingerprint for a key.
   *
   * @returns {boolean} True if the fingerprint is verified.
   */
  verifyFingerprint({fingerprint}) {
    // fingerprint should have `z` prefix indicating
    // that it's multi-base encoded
    if(!(typeof fingerprint === 'string' && fingerprint[0] === 'z')) {
      return {
        error: new Error('`fingerprint` must be a multibase encoded string.'),
        valid: false
      };
    }
    // base58.decode returns Buffer(nodejs) or Uint8Array
    const fingerprintBuffer = base58.decode(fingerprint.slice(1));
    // keyFingerprintBuffer is a forge ByteStringBuffer
    const keyFingerprintBuffer = getPublicKeyFingerprint(
      publicKeyFromPem(this.publicKeyPem), {md: sha256.create()});

    // validate the first three multicodec bytes 0x5d1220
    const valid = fingerprintBuffer.slice(0, 3).toString('hex') === '5d1220' &&
      keyFingerprintBuffer.toHex() ===
      fingerprintBuffer.slice(3).toString('hex');
    if(!valid) {
      return {
        error: new Error('The fingerprint does not match the public key.'),
        valid: false
      };
    }

    return {valid};
  }

  /* eslint-disable max-len */
  /**
   * Returns a signer object with an async sign function for use by
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}
   * to sign content in a signature.
   * @example
   * > const signer = RsaVerificationKey2018.signer();
   * > signer.sign({data});
   *
   * @returns {{sign: Function}} An RSA Signer Function for a single key.
   * for a single Private Key.
   */
  /* eslint-enable */
  signer() {
    return rsaSignerFactory(this);
  }

  /* eslint-disable max-len */
  /**
   * Returns a verifier object with an async
   * function verify for use with
   * [jsonld-signatures]{@link https://github.com/digitalbazaar/jsonld-signatures}.
   * @example
   * > const verifier = RsaVerificationKey2018.verifier();
   * > const valid = await verifier.verify({data, signature});
   *
   * @returns {{verify: Function}} An RSA Verifier Function for a single key.
   */
  /* eslint-enable */
  verifier() {
    return rsaVerifierFactory(this);
  }
}

RsaVerificationKey2018.suite = SUITE_ID;

/**
 * @ignore
 * Returns an object with an async sign function.
 * The sign function is bound to the KeyPair
 * and then returned by the KeyPair's signer method.
 * @example
 * > const factory = rsaSignerFactory(RsaVerificationKey2018);
 * > const bytes = await factory.sign({data});
 * @param {RsaVerificationKey2018} key - They key this factory will verify for.
 *
 * @returns {{sign: Function}} An RSA Verifier Function for a single key.
 */
function rsaSignerFactory(key) {
  if(!key.privateKeyPem) {
    return {
      async sign() {
        throw new Error('No private key to sign with.');
      }
    };
  }

  // Note: Per rfc7518, the digest algorithm for PS256 is SHA-256,
  // https://tools.ietf.org/html/rfc7518

  // sign data using RSASSA-PSS where PSS uses a SHA-256 hash,
  // a SHA-256 based masking function MGF1, and a 32 byte salt to match
  // the hash size
  if(env.nodejs) {
    // node.js 8+
    const crypto = require('crypto');
    if('RSA_PKCS1_PSS_PADDING' in crypto.constants) {
      return {
        async sign({data}) {
          const signer = crypto.createSign('RSA-SHA256');
          signer.update(Buffer.from(data.buffer, data.byteOffset, data.length));
          const buffer = signer.sign({
            key: key.privateKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
          });
          return new Uint8Array(
            buffer.buffer, buffer.byteOffset, buffer.length);
        }
      };
    }
  }

  // browser or other environment (including node 6.x)
  const privateKey = forge.pki.privateKeyFromPem(key.privateKeyPem);
  return {
    async sign({data}) {
      const pss = createPss();
      const md = sha256.create();
      md.update(raw.encode(data), 'binary');
      const binaryString = privateKey.sign(md, pss);
      return raw.decode(binaryString);
    }
  };
}

/**
 * @ignore
 * Returns an object with an async verify function.
 * The verify function is bound to the KeyPair
 * and then returned by the KeyPair's verifier method.
 * @example
 * > const verifier = rsaVerifierFactory(RsaVerificationKey2018);
 * > verifier.verify({data, signature});
 * false
 * @param {RsaVerificationKey2018} key - An RsaVerificationKey2018.
 *
 * @returns {Function} An RSA Verifier for the key pair passed in.
 */
function rsaVerifierFactory(key) {
  if(env.nodejs) {
    // node.js 8+
    const crypto = require('crypto');
    if('RSA_PKCS1_PSS_PADDING' in crypto.constants) {
      return {
        async verify({data, signature}) {
          const verifier = crypto.createVerify('RSA-SHA256');
          verifier.update(
            Buffer.from(data.buffer, data.byteOffset, data.length));
          return verifier.verify({
            key: key.publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
          }, Buffer.from(
            signature.buffer, signature.byteOffset, signature.length));
        }
      };
    }
  }

  // browser or other environment (including node 6.x)
  const publicKey = publicKeyFromPem(key.publicKeyPem);
  return {
    async verify({data, signature}) {
      const pss = createPss();
      const md = sha256.create();
      md.update(raw.encode(data), 'binary');
      try {
        return publicKey.verify(
          md.digest().bytes(),
          raw.encode(signature),
          pss);
      } catch(e) {
        // simply return false, do return information about malformed signature
        return false;
      }
    }
  };
}

/**
 * @ignore
 * creates an RSA PSS used in signatures.
 * @example
 * > const pss = createPss();
 *
 * @returns {PSS} A PSS object.
 * @see [PSS]{@link ./index.md#PSS}
 */
function createPss() {
  const md = sha256.create();
  return forge.pss.create({
    md,
    mgf: forge.mgf.mgf1.create(sha256.create()),
    saltLength: md.digestLength
  });
}
