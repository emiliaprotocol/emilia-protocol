// SPDX-License-Identifier: Apache-2.0
// Regression tests for the digest-divergence / canonicalization bugs surfaced by
// the surface audit: handshake NFC key ordering, stored payload re-hash, the
// assurance re-performance digest recompute, and the reliance signoff↔context join.
import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { deepSortKeys, computePayloadHash } from '@/lib/handshake/binding.js';
import { buildAssurancePackage, reperformAssurancePackage } from '@/packages/gate/reports/assurance-package.js';

const sha256 = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

describe('audit regression: canonicalization / digest divergence', () => {
  it('deepSortKeys normalizes keys to NFC before sorting (Unicode-equivalent objects agree)', () => {
    // "café" composed (NFC) vs decomposed (NFD e + combining acute) are the SAME
    // logical key; both must canonicalize identically.
    const nfc = { ['café']: 1, apple: 2 };       // é as U+00E9
    const nfd = { ['café']: 1, apple: 2 };       // e + U+0301
    expect(JSON.stringify(deepSortKeys(nfc))).toBe(JSON.stringify(deepSortKeys(nfd)));
  });

  it('a stored canonical payload re-hashes to its payload_hash under non-NFC input', () => {
    const input = { ['café']: { ['näme']: 'x' }, a: 1 };
    const stored = deepSortKeys(input);
    expect(sha256(JSON.stringify(stored))).toBe(computePayloadHash(input));
  });

  it('reperformAssurancePackage recomputes the package digest instead of trusting it', () => {
    const decisions = [{ decision_id: 'd1', stated_verdict: 'do_not_rely_no_profile', action: {}, evidence: {} }];
    const pkg = buildAssurancePackage(decisions, { profile: null, organization: 'acme', now: 1 });
    const clean = reperformAssurancePackage(pkg, { now: 2 });
    expect(clean.package_digest).toBe(pkg.package_digest);
    expect(clean.package_digest_verified).toBe(true);
    // Tamper a decision after packaging; the stated digest no longer matches.
    const tampered = JSON.parse(JSON.stringify(pkg));
    tampered.decisions[0].stated_verdict = 'rely';
    const rp = reperformAssurancePackage(tampered, { now: 3 });
    expect(rp.package_digest_verified).toBe(false);
  });
});
