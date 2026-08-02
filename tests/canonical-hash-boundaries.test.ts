// SPDX-License-Identifier: Apache-2.0

import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { hashClaim, signClaim } from '../lib/trust-desk/hash.js';
import { canonicalize as canonicalizeReleaseLock, sha256Digest } from '../app/release-lock/digests.js';
import { evaluateAdmissibility } from '../lib/evidence/admissibility.js';
import {
  artifactDigest, graphDigest, verifyRelianceResult,
} from '../lib/evidence/evidence-graph.js';
import {
  createAuthorityDoc, verifyAuthorityChain,
} from '../lib/authority/authority-doc.js';

describe('remaining signed and action-digest boundaries', () => {
  it('the public conformance verifier recursively binds nested receipt payloads', () => {
    const source = readFileSync(new URL('../conformance/ep-conformance-test.ts', import.meta.url), 'utf8');
    expect(source).toContain('canonicalizeStrictJson(testReceipt.payload)');
    expect(source).not.toContain('JSON.stringify(testReceipt.payload, Object.keys(testReceipt.payload).sort())');
  });

  it('Trust Desk hashes bind nested values and refuse ghost state', () => {
    expect(hashClaim({ answer: { accepted: true } }))
      .not.toBe(hashClaim({ answer: { accepted: false } }));
    expect(() => hashClaim({ answer: undefined })).toThrow(/CANONICALIZATION_ERROR/);
    expect(() => hashClaim({ answer: new Map([['accepted', true]]) })).toThrow(/CANONICALIZATION_ERROR/);
    expect(() => hashClaim({ answer: 'yes', [Symbol('authority')]: 'admin' })).toThrow(/CANONICALIZATION_ERROR/);
    expect(() => signClaim({ answer: undefined }, 'test-signing-key')).toThrow(/CANONICALIZATION_ERROR/);
  });

  it('Trust Desk does not invoke accessors while hashing', () => {
    let reads = 0;
    const claim = Object.defineProperty({}, 'answer', {
      enumerable: true,
      get() {
        reads += 1;
        return 'yes';
      },
    });
    expect(() => hashClaim(claim)).toThrow(/CANONICALIZATION_ERROR/);
    expect(reads).toBe(0);
  });

  it('release-lock digests refuse action fields that canonical JSON would erase', async () => {
    expect(() => canonicalizeReleaseLock({ action: undefined })).toThrow(/canonicalization profile/);
    expect(() => canonicalizeReleaseLock({ action: new Date('2026-08-01T00:00:00Z') })).toThrow(/canonicalization profile/);
    expect(() => canonicalizeReleaseLock({ action: 'release', [Symbol('authority')]: 'admin' })).toThrow(/canonicalization profile/);
    await expect(sha256Digest({ action: undefined })).rejects.toThrow(/canonicalization profile/);
  });

  it('admissibility returns a structured refusal for non-canonical policy state', () => {
    let reads = 0;
    const policy = Object.defineProperty({}, 'requirement', {
      enumerable: true,
      get() { reads += 1; return 'authorization_receipt'; },
    });
    const result = evaluateAdmissibility({ components: [] }, policy, {});
    expect(result.verdict).toBe('unverifiable');
    expect(result.reasons).toContain('input contains state outside the canonical JSON domain');
    expect(reads).toBe(0);
  });

  it('evidence graph digests and verifiers refuse ghost state', () => {
    expect(() => artifactDigest(new Map([['approved', true]]))).toThrow(/CANONICALIZATION_ERROR/);
    const graph = { '@version': 'EP-AEG-v1', nodes: [], edges: [] };
    Object.defineProperty(graph, 'shadow', { value: 'approved', enumerable: false });
    expect(() => graphDigest(graph)).toThrow(/CANONICALIZATION_ERROR/);

    let reads = 0;
    const doc = Object.defineProperty({}, 'payload', {
      enumerable: true,
      get() { reads += 1; return {}; },
    });
    expect(verifyRelianceResult(doc, []).verified).toBe(false);
    expect(reads).toBe(0);
  });

  it('authority documents refuse ghost state before signing or verification', () => {
    const root = crypto.generateKeyPairSync('ed25519');
    const issuer = crypto.generateKeyPairSync('ed25519');
    const issuerKey = issuer.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
    let reads = 0;
    const org = Object.defineProperty({}, 'domain', {
      enumerable: true,
      get() { reads += 1; return 'example.test'; },
    });
    expect(() => createAuthorityDoc({
      org,
      issuer_keys: [{ key: issuerKey, valid_from: '2026-01-01T00:00:00Z', valid_to: '2027-01-01T00:00:00Z' }],
      issued_at: '2026-01-01T00:00:00Z',
    }, root.privateKey)).toThrow(/canonicalization profile/);
    expect(reads).toBe(0);

    const malformed = { '@version': 'EP-AUTHORITY-DOC-v1' };
    Object.defineProperty(malformed, 'root_key', {
      enumerable: true,
      get() { reads += 1; return 'bad'; },
    });
    expect(verifyAuthorityChain([malformed]).verified).toBe(false);
    expect(reads).toBe(0);
  });
});
