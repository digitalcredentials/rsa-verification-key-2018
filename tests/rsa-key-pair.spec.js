/*!
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
const {
  md: {sha256},
  pki: {getPublicKeyFingerprint, publicKeyFromPem}
} = require('node-forge');
const multibase = require('multibase');
const multicodec = require('multicodec');
const multihashes = require('multihashes');
chai.should();

const {expect} = chai;

const RSAKeyPair = require('..');

describe('RSAKeyPair', () => {
  describe('export', () => {
    it('should export id, type and key material', async () => {
      const keyPair = await RSAKeyPair.generate();
      keyPair.id = '#test-id';
      const exported = await keyPair.export({publicKey: true, privateKey: true});

      expect(exported.id).to.equal('#test-id');
      expect(exported.type).to.equal('RsaVerificationKey2018');
      expect(exported).to.have.property('publicKeyPem');
      expect(exported).to.have.property('privateKeyPem');
    });
  });

  describe('fingerprint', () => {
    it('should create an RSA key fingerprint', async () => {
      const keyPair = await RSAKeyPair.generate();
      const fingerprint = keyPair.fingerprint();
      fingerprint.should.be.a('string');
      fingerprint.startsWith('z').should.be.true;
    });
    // FIXME: https://github.com/digitalbazaar/crypto-ld/issues/43
    it.skip('should be properly multicodec encoded', async () => {
      const keyPair = await RSAKeyPair.generate();
      const fingerprint = keyPair.fingerprint();
      const mcPubkeyBytes = multibase.decode(fingerprint);

      // FIXME: multicodec doesn't know about 0x5d encoding yet
      let error;
      let mcType;
      try {
        mcType = multicodec.getCodec(mcPubkeyBytes);
      } catch(e) {
        error = e;
      }
      expect(mcType).to.be.undefined;
      error.message.should.equal('Code `0x5d` not found');

      const multihashBytes = multicodec.rmPrefix(mcPubkeyBytes);
      mcType = multicodec.getCodec(multihashBytes);
      mcType.should.equal('sha2-256');
      // send hash, including prefix to multihashes.decode
      const hashHex = multihashes.decode(multihashBytes)
        .digest.toString('hex');
      // compute the fingerprint directly from the keyPair
      const fingerprintHex = getPublicKeyFingerprint(
        publicKeyFromPem(keyPair.publicKeyPem), {md: sha256.create()})
        .toHex();
      hashHex.should.equal(fingerprintHex);
    });
  });

  describe('verify fingerprint', () => {
    it('should verify a valid fingerprint', async () => {
      const keyPair = await RSAKeyPair.generate();
      const fingerprint = keyPair.fingerprint();
      const result = keyPair.verifyFingerprint(fingerprint);
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.true;
    });
    it('should reject an improperly encoded fingerprint', async () => {
      const keyPair = await RSAKeyPair.generate();
      const fingerprint = keyPair.fingerprint();
      const result = keyPair.verifyFingerprint(fingerprint.slice(1));
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.equal(
        '`fingerprint` must be a multibase encoded string.');
    });
    it('should reject an invalid fingerprint', async () => {
      const keyPair = await RSAKeyPair.generate();
      const fingerprint = keyPair.fingerprint();
      // reverse the valid fingerprint
      const t = fingerprint.slice(1).split('').reverse().join('');
      const badFingerprint = fingerprint[0] + t;
      const result = keyPair.verifyFingerprint(badFingerprint);
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.equal(
        'The fingerprint does not match the public key.');
    });
    it('should reject a numeric fingerprint', async () => {
      const keyPair = await RSAKeyPair.generate();
      const result = keyPair.verifyFingerprint(123);
      expect(result).to.exist;
      result.should.be.an('object');
      expect(result.valid).to.exist;
      result.valid.should.be.a('boolean');
      result.valid.should.be.false;
      expect(result.error).to.exist;
      result.error.message.should.equal(
        '`fingerprint` must be a multibase encoded string.');
    });
  });

  describe('static from', () => {
    it('should round-trip load exported keys', async () => {
      const keyPair = await RSAKeyPair.generate();
      keyPair.id = '#test-id';
      const exported = await keyPair.export({publicKey: true, privateKey: true});
      const imported = await RSAKeyPair.from(exported);

      expect(await imported.export({publicKey: true, privateKey: true}))
        .to.eql(exported);
    });
  });
});
