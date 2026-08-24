// SPDX-License-Identifier: Apache-2.0
// Regression tests for the digest-divergence / canonicalization bugs surfaced by
// the surface audit: handshake NFC key ordering, stored payload re-hash, the
// assurance re-performance digest recompute, and the reliance signoff↔context join.
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { deepSortKeys, computePayloadHash } from '@/lib/handshake/binding.js';
import { hashCanonical } from '@/packages/gate/execution-binding.js';
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
    expect(clean.profile_hash_verified).toBe(true);
    expect(clean.integrity_verified).toBe(true);
    // Tamper a decision after packaging; the stated digest no longer matches.
    const tampered = JSON.parse(JSON.stringify(pkg));
    tampered.decisions[0].stated_verdict = 'rely';
    const rp = reperformAssurancePackage(tampered, { now: 3 });
    expect(rp.package_digest_verified).toBe(false);
    expect(rp.integrity_verified).toBe(false);
  });

  it('rejects an internally rehashed package that lies about its presented profile hash', () => {
    const decisions = [{ decision_id: 'd1', stated_verdict: 'do_not_rely_no_profile', action: {}, evidence: {} }];
    const pkg = buildAssurancePackage(decisions, {
      profile: { '@type': 'EP-RELIANCE-PROFILE-v1', required_evidence: [] },
      organization: 'acme',
      now: 1,
    });
    const lied = JSON.parse(JSON.stringify(pkg));
    lied.profile_hash = '0'.repeat(64);
    // Rehash the outer package exactly as a malicious producer could. The outer
    // digest is now self-consistent, but the inner profile commitment still lies.
    const { assembled_at: _at, package_digest: _digest, ...digestScope } = lied;
    lied.package_digest = hashCanonical(digestScope);

    const rp = reperformAssurancePackage(lied, { now: 2 });
    expect(rp.package_digest_verified).toBe(true);
    expect(rp.profile_hash_verified).toBe(false);
    expect(rp.integrity_verified).toBe(false);
  });

  it('checks auditor-supplied package and profile pins out of band', () => {
    const pkg = buildAssurancePackage([], {
      profile: { '@type': 'EP-RELIANCE-PROFILE-v1', required_evidence: [] },
      now: 1,
    });
    const ok = reperformAssurancePackage(pkg, {
      expectedPackageDigest: pkg.package_digest,
      expectedProfileHash: pkg.profile_hash,
      now: 2,
    });
    expect(ok.integrity_verified).toBe(true);
    expect(ok.expected_package_digest_matches).toBe(true);
    expect(ok.expected_profile_hash_matches).toBe(true);

    const mismatch = reperformAssurancePackage(pkg, {
      expectedProfileHash: 'f'.repeat(64),
      now: 2,
    });
    expect(mismatch.profile_hash_verified).toBe(true);
    expect(mismatch.expected_profile_hash_matches).toBe(false);
    expect(mismatch.integrity_verified).toBe(false);
  });

  it('ep-assure exits non-zero on a package digest mismatch even when verdicts do not drift', () => {
    const decisions = [{ decision_id: 'd1', stated_verdict: 'do_not_rely_no_profile', action: {}, evidence: {} }];
    const pkg = buildAssurancePackage(decisions, { profile: null, organization: 'acme', now: 1 });
    const tampered = JSON.parse(JSON.stringify(pkg));
    tampered.organization = 'changed-after-packaging';
    const temp = mkdtempSync(path.join(os.tmpdir(), 'ep-assure-integrity-'));
    const inputPath = path.join(temp, 'input.json');
    try {
      writeFileSync(inputPath, JSON.stringify({ package: tampered, keys: {}, now: 2 }));
      const result = spawnSync(
        process.execPath,
        ['packages/gate/ep-assure.mjs', inputPath, '--json'],
        { cwd: path.resolve(import.meta.dirname, '..'), encoding: 'utf8' },
      );
      expect(result.status).toBe(1);
      expect(JSON.parse(result.stdout).package_digest_verified).toBe(false);
      expect(result.stderr).toContain('package digest mismatch');
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });

  it('ep-assure exits non-zero on an internally rehashed profile-hash lie with no verdict drift', () => {
    const pkg = buildAssurancePackage(
      [{ decision_id: 'd1', stated_verdict: 'do_not_rely_unsigned', action: {}, evidence: {} }],
      { profile: { '@type': 'EP-RELIANCE-PROFILE-v1', required_evidence: [] }, now: 1 },
    );
    const lied = JSON.parse(JSON.stringify(pkg));
    lied.profile_hash = '0'.repeat(64);
    const { assembled_at: _at, package_digest: _digest, ...digestScope } = lied;
    lied.package_digest = hashCanonical(digestScope);
    const temp = mkdtempSync(path.join(os.tmpdir(), 'ep-assure-profile-integrity-'));
    const inputPath = path.join(temp, 'input.json');
    try {
      writeFileSync(inputPath, JSON.stringify({ package: lied, keys: {}, now: 2 }));
      const result = spawnSync(
        process.execPath,
        ['packages/gate/ep-assure.mjs', inputPath, '--json'],
        { cwd: path.resolve(import.meta.dirname, '..'), encoding: 'utf8' },
      );
      expect(result.status).toBe(1);
      const document = JSON.parse(result.stdout);
      expect(document.package_digest_verified).toBe(true);
      expect(document.profile_hash_verified).toBe(false);
      expect(document.integrity_verified).toBe(false);
      expect(result.stderr).toContain('profile hash mismatch');
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  });
});
