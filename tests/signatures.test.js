/**
 * EMILIA Protocol — Ed25519 Signature Verification Tests
 *
 * Tests the identified_signed provenance tier — any attempt to claim this tier
 * without a valid signature must be rejected and downgraded to self_attested.
 */

import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import { verifyReceiptSignature, resolveProvenanceTier } from '../lib/signatures.js';

// ---------------------------------------------------------------------------
// Helpers: generate real Ed25519 keypairs for positive-path testing
// ---------------------------------------------------------------------------

function generateKeypair() {
  return crypto.generateKeyPairSync('ed25519');
}

function signHash(privateKey, hexHash) {
  const data = Buffer.from(hexHash, 'hex');
  const sig = crypto.sign(null, data, privateKey);
  return sig.toString('base64');
}

function exportPublicKeyBase64(publicKey) {
  // Export raw 32-byte public key
  const der = publicKey.export({ type: 'spki', format: 'der' });
  // Last 32 bytes of a 44-byte Ed25519 SPKI DER are the raw key
  return der.slice(der.length - 32).toString('base64');
}

function makeFakeHash() {
  return crypto.randomBytes(32).toString('hex');
}

// ============================================================================
// verifyReceiptSignature — input validation
// ============================================================================

describe('verifyReceiptSignature — input validation', () => {
  it('rejects null receiptHash', () => {
    const r = verifyReceiptSignature(null, 'aGVsbG8=', 'aGVsbG8=');
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/receiptHash/);
  });

  it('rejects empty receiptHash', () => {
    const r = verifyReceiptSignature('', 'aGVsbG8=', 'aGVsbG8=');
    expect(r.valid).toBe(false);
  });

  it('rejects null signature', () => {
    const r = verifyReceiptSignature(makeFakeHash(), null, 'aGVsbG8=');
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/signature/);
  });

  it('rejects null publicKey', () => {
    const r = verifyReceiptSignature(makeFakeHash(), 'aGVsbG8=', null);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/publicKey/);
  });

  it('rejects signature of wrong length (1 byte)', () => {
    const sigShort = Buffer.from([0x00]).toString('base64');
    const pubkey = Buffer.alloc(32).toString('base64');
    const r = verifyReceiptSignature(makeFakeHash(), sigShort, pubkey);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/64 bytes/);
  });

  it('rejects public key of wrong length (16 bytes)', () => {
    const sig = Buffer.alloc(64).toString('base64');
    const keyShort = Buffer.alloc(16).toString('base64');
    const r = verifyReceiptSignature(makeFakeHash(), sig, keyShort);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/32 bytes/);
  });

  it('random 64-byte garbage signature against real pubkey is rejected', () => {
    const { publicKey } = generateKeypair();
    const pub = exportPublicKeyBase64(publicKey);
    const garbageSig = crypto.randomBytes(64).toString('base64');
    const r = verifyReceiptSignature(makeFakeHash(), garbageSig, pub);
    expect(r.valid).toBe(false);
  });
});

// ============================================================================
// verifyReceiptSignature — cryptographic correctness
// ============================================================================

describe('verifyReceiptSignature — cryptographic correctness', () => {
  it('accepts a valid ed25519 signature', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const sig = signHash(privateKey, hash);
    const pub = exportPublicKeyBase64(publicKey);

    const r = verifyReceiptSignature(hash, sig, pub);
    expect(r.valid).toBe(true);
    expect(r.reason).toBeUndefined();
  });

  it('rejects a signature over the wrong hash', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const wrongHash = makeFakeHash();
    const sig = signHash(privateKey, hash);
    const pub = exportPublicKeyBase64(publicKey);

    const r = verifyReceiptSignature(wrongHash, sig, pub);
    expect(r.valid).toBe(false);
  });

  it('rejects a signature from a different keypair', () => {
    const { privateKey } = generateKeypair();
    const { publicKey: wrongKey } = generateKeypair();
    const hash = makeFakeHash();
    const sig = signHash(privateKey, hash);
    const pub = exportPublicKeyBase64(wrongKey);

    const r = verifyReceiptSignature(hash, sig, pub);
    expect(r.valid).toBe(false);
  });

  it('rejects a signature with one flipped bit', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const sig = signHash(privateKey, hash);
    const pub = exportPublicKeyBase64(publicKey);

    // Flip the first bit of the signature
    const sigBuf = Buffer.from(sig, 'base64');
    sigBuf[0] ^= 0x01;
    const tamperedSig = sigBuf.toString('base64');

    const r = verifyReceiptSignature(hash, tamperedSig, pub);
    expect(r.valid).toBe(false);
  });

  it('verification is deterministic — same inputs always same result', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const sig = signHash(privateKey, hash);
    const pub = exportPublicKeyBase64(publicKey);

    const r1 = verifyReceiptSignature(hash, sig, pub);
    const r2 = verifyReceiptSignature(hash, sig, pub);
    const r3 = verifyReceiptSignature(hash, sig, pub);

    expect(r1.valid).toBe(true);
    expect(r2.valid).toBe(true);
    expect(r3.valid).toBe(true);
  });
});

// ============================================================================
// resolveProvenanceTier — provenance downgrade logic
// ============================================================================

describe('resolveProvenanceTier — pass-through for non-identified_signed tiers', () => {
  it('self_attested passes through unchanged', () => {
    const r = resolveProvenanceTier('self_attested', makeFakeHash(), {});
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toBeUndefined();
  });

  it('bilateral passes through unchanged', () => {
    const r = resolveProvenanceTier('bilateral', makeFakeHash(), {});
    expect(r.tier).toBe('bilateral');
  });

  it('oracle_verified passes through unchanged', () => {
    const r = resolveProvenanceTier('oracle_verified', makeFakeHash(), null);
    expect(r.tier).toBe('oracle_verified');
  });
});

describe('resolveProvenanceTier — identified_signed downgrade paths', () => {
  it('downgrades to self_attested when evidence has no signature', () => {
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { public_key: 'abc' });
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/signature/i);
    expect(r.warning).toMatch(/downgraded/i);
  });

  it('downgrades to self_attested when evidence has no public_key', () => {
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: 'abc' });
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/public_key/i);
  });

  it('downgrades to self_attested when evidence is null', () => {
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), null);
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/missing/i);
  });

  it('downgrades when signature has wrong byte length', () => {
    const shortSig = Buffer.alloc(10).toString('base64');
    const pub = Buffer.alloc(32).toString('base64');
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: shortSig, public_key: pub });
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/invalid length/i);
  });

  it('downgrades when public_key has wrong byte length', () => {
    const sig = Buffer.alloc(64).toString('base64');
    const shortPub = Buffer.alloc(16).toString('base64');
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: sig, public_key: shortPub });
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/invalid length/i);
  });

  it('downgrades when signature does not verify against hash', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const wrongHash = makeFakeHash();
    const sig = signHash(privateKey, hash); // signed wrong hash
    const pub = exportPublicKeyBase64(publicKey);

    const r = resolveProvenanceTier('identified_signed', wrongHash, { signature: sig, public_key: pub });
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/failed/i);
  });

  it('grants identified_signed tier when signature is valid', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const sig = signHash(privateKey, hash);
    const pub = exportPublicKeyBase64(publicKey);

    const r = resolveProvenanceTier('identified_signed', hash, { signature: sig, public_key: pub });
    expect(r.tier).toBe('identified_signed');
    expect(r.warning).toBeUndefined();
  });
});

// ============================================================================
// ADVERSARIAL: Signature injection attacks
// ============================================================================

describe('ADVERSARIAL: Signature attacks — cannot claim identified_signed without proof', () => {
  it('empty string signature is rejected', () => {
    const pub = Buffer.alloc(32).toString('base64');
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: '', public_key: pub });
    expect(r.tier).toBe('self_attested');
  });

  it('random garbage 64-byte signature does not verify against real key', () => {
    const { publicKey } = generateKeypair();
    const pub = exportPublicKeyBase64(publicKey);
    const garbageSig = crypto.randomBytes(64).toString('base64');
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: garbageSig, public_key: pub });
    expect(r.tier).toBe('self_attested');
  });

  it('random garbage signature is rejected', () => {
    const { publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const garbageSig = crypto.randomBytes(64).toString('base64');
    const pub = exportPublicKeyBase64(publicKey);

    const r = resolveProvenanceTier('identified_signed', hash, { signature: garbageSig, public_key: pub });
    expect(r.tier).toBe('self_attested');
  });

  it('attacker cannot elevate tier by claiming identified_signed with forged sig', () => {
    // Even if they guess the right hash, they cannot produce a valid sig without the private key
    const { publicKey } = generateKeypair();
    const hash = makeFakeHash();
    // Use a random 64-byte value as "forged" signature
    const forgedSig = crypto.randomBytes(64).toString('base64');
    const pub = exportPublicKeyBase64(publicKey);

    for (let i = 0; i < 5; i++) {
      const attempt = resolveProvenanceTier('identified_signed', hash, {
        signature: crypto.randomBytes(64).toString('base64'),
        public_key: pub,
      });
      expect(attempt.tier).toBe('self_attested');
    }
  });

  it('signed receipt for entity A cannot be replayed to elevate entity B', () => {
    const { privateKey: pkA, publicKey: pubA } = generateKeypair();
    const { publicKey: pubB } = generateKeypair();
    const hash = makeFakeHash();
    const sigA = signHash(pkA, hash);
    const pubAExported = exportPublicKeyBase64(pubA);
    const pubBExported = exportPublicKeyBase64(pubB);

    // Entity A's signature is valid for A's key
    expect(resolveProvenanceTier('identified_signed', hash, { signature: sigA, public_key: pubAExported }).tier)
      .toBe('identified_signed');

    // But entity A's signature against entity B's public key → invalid
    expect(resolveProvenanceTier('identified_signed', hash, { signature: sigA, public_key: pubBExported }).tier)
      .toBe('self_attested');
  });
});
