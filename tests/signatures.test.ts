/**
 * EMILIA Protocol — Ed25519 Signature Verification Tests
 *
 * Tests the identified_signed provenance tier — any attempt to claim this tier
 * without a valid signature must be rejected and downgraded to self_attested.
 */

import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  buildIdentifiedSubmissionDigest,
  verifyReceiptSignature,
  resolveProvenanceTier,
} from '../lib/signatures.js';

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

function exportPublicKeySpkiBase64url(publicKey) {
  return publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
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
    expect(r.reason).toMatch(/32-byte raw key/i);
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
    const { publicKey } = generateKeypair();
    const r = resolveProvenanceTier(
      'identified_signed', makeFakeHash(), {}, exportPublicKeySpkiBase64url(publicKey),
    );
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/signature/i);
    expect(r.warning).toMatch(/downgraded/i);
  });

  it('downgrades to self_attested when the authenticated submitter has no enrolled key', () => {
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: 'abc' });
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/enrolled submitter key/i);
  });

  it('downgrades to self_attested when evidence is null', () => {
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), null);
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/missing/i);
  });

  it('downgrades when signature has wrong byte length', () => {
    const shortSig = Buffer.alloc(10).toString('base64');
    const { publicKey } = generateKeypair();
    const trusted = exportPublicKeySpkiBase64url(publicKey);
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: shortSig }, trusted);
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/invalid signature length/i);
  });

  it('downgrades when the evidence public_key is malformed', () => {
    const sig = Buffer.alloc(64).toString('base64');
    const shortPub = Buffer.alloc(16).toString('base64');
    const { publicKey } = generateKeypair();
    const trusted = exportPublicKeySpkiBase64url(publicKey);
    const r = resolveProvenanceTier(
      'identified_signed', makeFakeHash(), { signature: sig, public_key: shortPub }, trusted,
    );
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/key verification error/i);
  });

  it('downgrades when signature does not verify against hash', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const wrongHash = makeFakeHash();
    const sig = signHash(privateKey, hash); // signed wrong hash
    const pub = exportPublicKeyBase64(publicKey);

    const r = resolveProvenanceTier('identified_signed', wrongHash, { signature: sig }, pub);
    expect(r.tier).toBe('self_attested');
    expect(r.warning).toMatch(/failed/i);
  });

  it('grants identified_signed tier when signature is valid', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const sig = signHash(privateKey, hash);
    const pub = exportPublicKeyBase64(publicKey);

    const r = resolveProvenanceTier('identified_signed', hash, { signature: sig }, pub);
    expect(r.tier).toBe('identified_signed');
    expect(r.warning).toBeUndefined();
  });

  it('accepts the entity registry SPKI encoding used by authenticateRequest', () => {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const signature = signHash(privateKey, hash);
    const trustedSpki = exportPublicKeySpkiBase64url(publicKey);

    expect(resolveProvenanceTier('identified_signed', hash, { signature }, trustedSpki).tier)
      .toBe('identified_signed');
  });
});

// ============================================================================
// ADVERSARIAL: Signature injection attacks
// ============================================================================

describe('ADVERSARIAL: Signature attacks — cannot claim identified_signed without proof', () => {
  it('empty string signature is rejected', () => {
    const { publicKey } = generateKeypair();
    const pub = exportPublicKeyBase64(publicKey);
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: '' }, pub);
    expect(r.tier).toBe('self_attested');
  });

  it('random garbage 64-byte signature does not verify against real key', () => {
    const { publicKey } = generateKeypair();
    const pub = exportPublicKeyBase64(publicKey);
    const garbageSig = crypto.randomBytes(64).toString('base64');
    const r = resolveProvenanceTier('identified_signed', makeFakeHash(), { signature: garbageSig }, pub);
    expect(r.tier).toBe('self_attested');
  });

  it('random garbage signature is rejected', () => {
    const { publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const garbageSig = crypto.randomBytes(64).toString('base64');
    const pub = exportPublicKeyBase64(publicKey);

    const r = resolveProvenanceTier('identified_signed', hash, { signature: garbageSig }, pub);
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
      }, pub);
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
    expect(resolveProvenanceTier('identified_signed', hash, { signature: sigA }, pubAExported).tier)
      .toBe('identified_signed');

    // But entity A's signature against entity B's public key → invalid
    expect(resolveProvenanceTier('identified_signed', hash, { signature: sigA }, pubBExported).tier)
      .toBe('self_attested');
  });

  it('does not let a submitter establish identity with an inline self-generated key', () => {
    const { publicKey: enrolledKey } = generateKeypair();
    const { privateKey: attackerPrivate, publicKey: attackerPublic } = generateKeypair();
    const hash = makeFakeHash();
    const signature = signHash(attackerPrivate, hash);

    const result = resolveProvenanceTier('identified_signed', hash, {
      signature,
      public_key: exportPublicKeyBase64(attackerPublic),
    }, exportPublicKeySpkiBase64url(enrolledKey));

    expect(result.tier).toBe('self_attested');
    expect(result.warning).toMatch(/does not match the authenticated submitter key/i);
  });
});

describe('buildIdentifiedSubmissionDigest — non-circular exact binding', () => {
  const base = {
    targetEntityRef: 'merchant.example',
    transactionRef: 'order-7',
    transactionType: 'purchase',
    signals: { price_integrity: 100 },
    claims: { price_honored: true },
    evidence: { invoice_hash: 'sha256:abc', signature: 'ignored', public_key: 'ignored' },
    context: { currency: 'USD' },
  };

  it('excludes authentication envelope fields from the signed payload', () => {
    const first = buildIdentifiedSubmissionDigest(base);
    const second = buildIdentifiedSubmissionDigest({
      ...base,
      evidence: { ...base.evidence, signature: 'different', public_key: 'different' },
    });
    expect(first.digest).toBe(second.digest);
    expect(first.payload.evidence).toEqual({ invoice_hash: 'sha256:abc' });
  });

  it('changes for the target, transaction, claims, context, or evidence', () => {
    const digest = buildIdentifiedSubmissionDigest(base).digest;
    for (const changed of [
      { ...base, targetEntityRef: 'attacker.example' },
      { ...base, transactionRef: 'order-8' },
      { ...base, claims: { price_honored: false } },
      { ...base, context: { currency: 'EUR' } },
      { ...base, evidence: { invoice_hash: 'sha256:def' } },
    ]) {
      expect(buildIdentifiedSubmissionDigest(changed).digest).not.toBe(digest);
    }
  });
});

// ===========================================================================
// Regression (encoding canonicality): decodeBase64Strict admitted a single
// character class of [A-Za-z0-9+/_-], so a MIXED-alphabet string (some standard
// '+/', some URL-safe '-_') passed the shape check and then normalized to the
// same bytes as its single-alphabet spellings. One signature therefore had
// several accepted encodings. A value must now be entirely standard base64 or
// entirely base64url, with correct padding and an exact round trip.
// ===========================================================================
describe('verifyReceiptSignature — one encoding per signature', () => {
  function signedFixture() {
    const { privateKey, publicKey } = generateKeypair();
    const hash = makeFakeHash();
    const sigStd = crypto.sign(null, Buffer.from(hash, 'hex'), privateKey).toString('base64');
    return { hash, sigStd, pub: exportPublicKeyBase64(publicKey) };
  }

  it('accepts each single-alphabet spelling but refuses a mixed one', () => {
    // Retry until the signature actually contains both '+/'-class characters,
    // so the mixed spelling below is a genuinely different string.
    let fixture = signedFixture();
    for (let i = 0; i < 200 && !/\+/.test(fixture.sigStd); i += 1) fixture = signedFixture();
    expect(/\+/.test(fixture.sigStd)).toBe(true);

    const { hash, sigStd, pub } = fixture;
    const sigUrl = sigStd.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(verifyReceiptSignature(hash, sigStd, pub).valid).toBe(true);
    expect(verifyReceiptSignature(hash, sigUrl, pub).valid).toBe(true);

    // Mixed alphabet: URL-safe body with a single standard '+' reintroduced.
    const mixed = sigUrl.replace('-', '+');
    expect(mixed).not.toBe(sigUrl);
    expect(mixed).not.toBe(sigStd);
    const r = verifyReceiptSignature(hash, mixed, pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/canonical base64/);
  });

  it('refuses a non-canonical final character (unused slack bits set)', () => {
    const { hash, sigStd, pub } = signedFixture();
    const url = sigStd.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(url[url.length - 1]);
    const slack = url.slice(0, -1) + alphabet[(last & 0b111100) | ((last + 1) & 0b11)];
    expect(slack).not.toBe(url);
    // Same bytes, different spelling.
    expect(Buffer.from(slack, 'base64url').equals(Buffer.from(url, 'base64url'))).toBe(true);
    const r = verifyReceiptSignature(hash, slack, pub);
    expect(r.valid).toBe(false);
    expect(r.reason).toMatch(/canonical base64/);
  });

  it('refuses padding that does not match the body length', () => {
    const { hash, sigStd, pub } = signedFixture();
    const body = sigStd.replace(/=+$/, '');
    // A 64-byte signature is 86 characters plus 2 pad characters.
    expect(verifyReceiptSignature(hash, `${body}=`, pub).valid).toBe(false);
    expect(verifyReceiptSignature(hash, `${body}==`, pub).valid).toBe(true);
  });
});
