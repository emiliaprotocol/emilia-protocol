// SPDX-License-Identifier: Apache-2.0
//
// Conformance-style proof for lib/evidence/admissibility-profiles.js.
//
// The load-bearing property: the RELYING PARTY authors and pins the bar; the
// verdict + replay_digest are computed OFFLINE and deterministically against
// THAT pinned profile. Two relying parties with different bars over the SAME
// evidence must reach different, each-reproducible verdicts, and nobody may
// swap the bar under a pinned hash.

import { describe, it, expect } from 'vitest';
import {
  defineAdmissibilityProfile,
  computeProfileHash,
  verifyProfileHash,
  evaluateAdmissibilityProfile,
} from '../lib/evidence/admissibility-profiles.js';
import {
  POLICY_PACKS,
  computePolicyPackHash,
  verifyPolicyPackHash,
} from '../lib/evidence/policy-packs.js';

const NOW = '2026-07-05T12:00:00.000Z';
const nowMs = Date.parse(NOW);
const iso = (msAgo) => new Date(nowMs - msAgo).toISOString();

// ── A single evidence bundle. Two different relying-party profiles below judge
//    this SAME bundle and reach different verdicts. ──────────────────────────
function baseBundle() {
  return {
    items: [
      {
        evidence: 'authorization_receipt',
        digest: 'sha256:aaaa1111',
        signature_valid: true,
        assurance: 'high',
        issued_at: iso(60_000), // 60s old
        revoked: false,
        action_digest: 'sha256:action-x',
      },
      {
        evidence: 'policy_permit',
        digest: 'sha256:bbbb2222',
        signature_valid: true,
        assurance: 'verified',
        issued_at: iso(120_000), // 120s old
        revoked: false,
        action_digest: 'sha256:action-x',
      },
    ],
  };
}

// Relying party A: only needs an authorization_receipt (with revocation check).
const profileA = defineAdmissibilityProfile({
  id: 'ep:admissibility:auth-only:v1',
  authored_by: 'Bank-of-Example Risk (relying party)',
  version: 1,
  requires: [
    { evidence: 'authorization_receipt', min_assurance: 'high', max_staleness_sec: 300, checks: ['revocation_checked'] },
  ],
});

// Relying party B: needs BOTH an authorization_receipt AND a fresh
// execution_attestation. The bundle has no execution_attestation.
const profileB = defineAdmissibilityProfile({
  id: 'ep:admissibility:auth-plus-exec:v1',
  authored_by: 'Clearing-House Settlement (relying party)',
  version: 1,
  requires: [
    { evidence: 'authorization_receipt', min_assurance: 'high', max_staleness_sec: 300, checks: ['revocation_checked'] },
    { evidence: 'execution_attestation', max_staleness_sec: 300 },
  ],
});

describe('profile hashing', () => {
  it('computes a self-verifying profile_hash over JCS(profile) minus profile_hash', () => {
    expect(profileA.profile_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(computeProfileHash(profileA)).toBe(profileA.profile_hash);
    expect(verifyProfileHash(profileA)).toBe(true);
  });

  it('two different bars have different hashes', () => {
    expect(profileA.profile_hash).not.toBe(profileB.profile_hash);
  });

  it('a tampered profile no longer verifies', () => {
    const tampered = { ...profileA, requires: [{ evidence: 'nothing' }] };
    expect(verifyProfileHash(tampered)).toBe(false);
  });
});

describe('SAME bundle, TWO bars -> different verdicts, different digests', () => {
  it('profile A -> admissible; profile B -> missing_evidence; digests DIFFER', () => {
    const bundle = baseBundle();
    const a = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    const b = evaluateAdmissibilityProfile(profileB, bundle, { now: NOW });

    expect(a.verdict).toBe('admissible');
    expect(b.verdict).toBe('missing_evidence');

    // The whole point: different bar -> different replayable digest.
    expect(a.replay_digest).not.toBe(b.replay_digest);
    expect(a.replay_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(b.replay_digest).toMatch(/^sha256:[0-9a-f]{64}$/);

    // B's missing leg is named in the requirement results.
    const execRow = b.requirement_results.find((r) => r.evidence === 'execution_attestation');
    expect(execRow.satisfied).toBe(false);
    expect(execRow.reason).toMatch(/absent/);
  });

  it('each verdict + digest is reproducible across two evaluations (determinism)', () => {
    const a1 = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: NOW });
    const a2 = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: NOW });
    expect(a2.replay_digest).toBe(a1.replay_digest);
    expect(a2.verdict).toBe(a1.verdict);

    const b1 = evaluateAdmissibilityProfile(profileB, baseBundle(), { now: NOW });
    const b2 = evaluateAdmissibilityProfile(profileB, baseBundle(), { now: NOW });
    expect(b2.replay_digest).toBe(b1.replay_digest);
    expect(b2.verdict).toBe(b1.verdict);
  });

  it('evaluated_at is OUTSIDE the digest: different now, same inputs -> same digest when staleness unaffected', () => {
    // Move `now` forward 10s; both items still well within their staleness bounds,
    // so the verdict and consulted-item facts are unchanged -> digest unchanged.
    const a1 = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: NOW });
    const a2 = evaluateAdmissibilityProfile(profileA, baseBundle(), { now: nowMs + 10_000 });
    expect(a2.verdict).toBe(a1.verdict);
    expect(a2.replay_digest).toBe(a1.replay_digest);
    expect(a2.evaluated_at).not.toBe(a1.evaluated_at); // the timestamp itself DID move
  });
});

describe('fail-closed refusals', () => {
  it('profile_hash_mismatch -> REFUSE unverifiable', () => {
    const res = evaluateAdmissibilityProfile(profileA, baseBundle(), {
      now: NOW,
      expectedProfileHash: 'sha256:' + '0'.repeat(64),
    });
    expect(res.verdict).toBe('unverifiable');
    expect(res.refused).toBe(true);
    expect(res.reason).toBe('profile_hash_mismatch');
    expect(res.requirement_results[0].reason).toBe('profile_hash_mismatch');
  });

  it('matching pinned hash proceeds to a normal verdict', () => {
    const res = evaluateAdmissibilityProfile(profileA, baseBundle(), {
      now: NOW,
      expectedProfileHash: profileA.profile_hash,
    });
    expect(res.refused).toBeUndefined();
    expect(res.verdict).toBe('admissible');
  });

  it('a profile whose self-hash was swapped is refused (tamper)', () => {
    const swapped = { ...profileA, profile_hash: 'sha256:' + 'f'.repeat(64) };
    const res = evaluateAdmissibilityProfile(swapped, baseBundle(), { now: NOW });
    expect(res.verdict).toBe('unverifiable');
    expect(res.reason).toBe('profile_self_hash_mismatch');
  });
});

describe('staleness', () => {
  it('a receipt older than max_staleness_sec yields stale', () => {
    const bundle = baseBundle();
    // authorization_receipt now 10 minutes old; profile A allows 300s.
    bundle.items[0].issued_at = iso(600_000);
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).toBe('stale');
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.satisfied).toBe(false);
    expect(row.reason).toMatch(/staler than 300s/);
  });
});

describe('optional requirements', () => {
  const profileOpt = defineAdmissibilityProfile({
    id: 'ep:admissibility:auth-opt-transparency:v1',
    authored_by: 'Auditor (relying party)',
    requires: [
      { evidence: 'authorization_receipt', min_assurance: 'high', max_staleness_sec: 300, checks: ['revocation_checked'] },
      { evidence: 'transparency', optional: true },
    ],
  });

  it('optional-ABSENT stays admissible (no downgrade)', () => {
    const res = evaluateAdmissibilityProfile(profileOpt, baseBundle(), { now: NOW });
    expect(res.verdict).toBe('admissible');
    const t = res.requirement_results.find((r) => r.evidence === 'transparency');
    expect(t.satisfied).toBe(true);
    expect(t.reason).toMatch(/optional requirement absent/);
  });

  it('optional-PRESENT-but-invalid DOWNGRADES (contributes a conflict/unverifiable)', () => {
    const bundle = baseBundle();
    bundle.items.push({
      evidence: 'transparency',
      digest: 'sha256:cccc3333',
      signature_valid: false, // present but its own verification fails
      assurance: 'basic',
      issued_at: iso(30_000),
      revoked: false,
    });
    const res = evaluateAdmissibilityProfile(profileOpt, bundle, { now: NOW });
    // A present-but-invalid item is caught by admissibility.js precedence.
    expect(res.verdict).toBe('unverifiable');
    const t = res.requirement_results.find((r) => r.evidence === 'transparency');
    expect(t.satisfied).toBe(false);
  });
});

describe('revocation check fails closed', () => {
  it('unknown revocation state fails the revocation_checked gate', () => {
    const bundle = baseBundle();
    delete bundle.items[0].revoked; // revocation state never established
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).toBe('unverifiable');
    const row = res.requirement_results.find((r) => r.evidence === 'authorization_receipt');
    expect(row.reason).toMatch(/revocation state unknown/);
  });

  it('an actively revoked item is caught (conflicted via revoked outcome)', () => {
    const bundle = baseBundle();
    bundle.items[0].revoked = true;
    const res = evaluateAdmissibilityProfile(profileA, bundle, { now: NOW });
    expect(res.verdict).not.toBe('admissible');
  });
});

describe('policy packs are pinnable objects', () => {
  it('every shipped pack carries a self-verifying policy_hash == profile_hash', () => {
    for (const pack of Object.values(POLICY_PACKS)) {
      expect(pack.policy_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(pack.profile_hash).toBe(pack.policy_hash);
      expect(computePolicyPackHash(pack)).toBe(pack.policy_hash);
      expect(verifyPolicyPackHash(pack)).toBe(true);
    }
  });

  it('pack semantics are unchanged by the hash field (requirement/freshness intact)', () => {
    const wire = POLICY_PACKS['ep:pack:wire-transfer:v1'];
    expect(wire.requirement).toBe('authorization_receipt AND policy_permit AND workload_identity');
    expect(wire.freshness_sec.authorization_receipt).toBe(300);
    expect(wire.revocation_required).toEqual(['authorization_receipt']);
  });
});
